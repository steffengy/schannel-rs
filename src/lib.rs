//! Schannel is a pure-Rust wrapper to provide SSL functionality under windows by using schannel, which
//! removes the requirement of openssl.

#[macro_use]
extern crate log;
extern crate winapi;
extern crate crypt32;
extern crate secur32;
extern crate rustc_serialize;

#[cfg(feature = "hyper")]
extern crate hyper;

#[cfg(feature = "hyper")]
pub mod hyperimpl;

use std::error::Error;
use std::fmt::{self, Display};
use std::io::prelude::*;
use std::io::Error as IoError;
use std::ptr;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::slice;
use std::sync::Arc;
use winapi::*;
use secur32::*;
use crypt32::*;
use rustc_serialize::hex::{FromHex};

// TODO: Add constants to winapi-rs
pub const CERT_STORE_PROV_SYSTEM_W: DWORD = 10;
pub const CERT_STORE_PROV_SYSTEM: DWORD = CERT_STORE_PROV_SYSTEM_W;

pub const CERT_SYSTEM_STORE_LOCATION_SHIFT: DWORD = 16;

pub const CERT_SYSTEM_STORE_CURRENT_USER_ID: DWORD = 1;
pub const CERT_SYSTEM_STORE_LOCAL_MACHINE_ID: DWORD = 2;
pub const CERT_SYSTEM_STORE_USERS_ID: DWORD = 6;

pub const CERT_SYSTEM_STORE_CURRENT_USER: DWORD = CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
pub const CERT_SYSTEM_STORE_LOCAL_MACHINE: DWORD = CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
pub const CERT_SYSTEM_STORE_USERS: DWORD = CERT_SYSTEM_STORE_USERS_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

pub const CERT_STORE_READONLY_FLAG: DWORD = 0x00008000;

pub const CERT_COMPARE_SHA1_HASH: DWORD = 1;
pub const CERT_COMPARE_SHIFT: DWORD = 16;
pub const CERT_COMPARE_NAME_STR_W: DWORD = 8;

pub const CERT_FIND_SHA1_HASH: DWORD = CERT_COMPARE_SHA1_HASH << CERT_COMPARE_SHIFT;
pub const CERT_FIND_SUBJECT_STR: DWORD = CERT_COMPARE_NAME_STR_W << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG;

// TODO: General error handling and checks (if initialized for credential, stream_sizes, ...)
// TODO: renegotiation, disconnect?
// TODO: Manual certificate validation

#[derive(Debug)]
struct SchannelCertStore(*mut c_void);
#[derive(Debug)]
struct SchannelCertCtxt(*const winapi::wincrypt::CERT_CONTEXT);
#[derive(Debug)]
struct SchannelCredHandle(CredHandle);
#[derive(Debug)]
struct SchannelCtxtHandle(CtxtHandle);

#[derive(Debug)]
pub enum SslInfo {
    /// Configuration related to SSL clients
    Client(SslInfoClient),
    /// Configuration related to SSL servers
    Server(SslInfoServer)
}

/// SSL client wrapper configuration
#[derive(Debug)]
pub struct SslInfoClient
{
    /// Whether to validate the peer certificate
    pub disable_peer_verification: bool
}

/// SSL wrapper configuration, which only applies to SSL peers/servers
#[derive(Debug)]
pub struct SslInfoServer
{
    cert_store: Arc<SchannelCertStore>,
    cert_ctxt: Arc<SchannelCertCtxt>
}

unsafe impl Send for SslInfoServer {}
unsafe impl Sync for SslInfoServer {}

#[derive(Debug)]
pub enum SslCertStore
{
    /// HKEY_LOCAL_MACHINE
    LocalMachine,
    /// HKEY_CURRENT_USER
    CurrentUser,
    /// HKEY_USERS
    User
}

/// SSL certificate conditions
pub enum SslCertCondition
{
    /// Check if the sha1 thumbprint hash of a certificate matches a given string
    SHA1HashIdentical(String),
    /// Check if the subject name contains a given string
    SubjectContains(String)
}

/// internal, type of the value passed to the API to prevent the data from going out of scope
enum SslCertConditionValue
{
    None,
    U8Vector(Vec<u8>),
    U16Vector(Vec<u16>)
}

/// SSL wrapper for generic streams
#[derive(Debug, Clone)]
pub struct SslStream<S> 
{
    stream: S,
    info: Arc<SslInfo>,
    /// A pointer to a null-terminated string that uniquely identifies the target server (e.g. www.google.de)
    target_name: Option<String>,
    ctxt: Arc<SchannelCtxtHandle>,
    cred_handle: Arc<SchannelCredHandle>,
    stream_sizes: SecPkgContext_StreamSizes,
    read_buf: Vec<u8>,
    read_buf_raw: Vec<u8>
}

/// Possible errors which can occur when doing SSL operations (e.g. schannel failure)
#[derive(Debug)]
pub enum SslError
{
    CertCommonNameInvalid,
    CertAuthorityInvalid,
    CertExpired,
    CertRevoced,
    CertInvalid,
    ProtocolError,
    VersionCipherMismatch,
    HandshakeFailedNoStreamSizes,
    CertificationStoreOpenFailed,
    CertNotFound,
    IoError(std::io::Error),
    UnknownError(i32)
}

impl Display for SslError
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SslError::UnknownError(err_code) => write!(f, "An unknown error with code({}) occurred", err_code),
            _ => write!(f, "{:?}", self)
        }
    }
}

impl Error for SslError
{
    fn description(&self) -> &str {
        "TODO SSL Error occurred"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

macro_rules! map_security_error {
    ($x:expr) => (match $x {
            SEC_E_WRONG_PRINCIPAL|CERT_E_CN_NO_MATCH  => SslError::CertCommonNameInvalid,
            SEC_E_UNTRUSTED_ROOT|CERT_E_UNTRUSTEDROOT => SslError::CertAuthorityInvalid,
            SEC_E_CERT_EXPIRED|CERT_E_EXPIRED         => SslError::CertExpired,
            CRYPT_E_REVOKED                           => SslError::CertRevoced,
            SEC_E_CERT_UNKNOWN|CERT_E_ROLE            => SslError::CertInvalid,
            // SSL Errors which we map to a protocol error
            SEC_E_ILLEGAL_MESSAGE |
            SEC_E_DECRYPT_FAILURE |
            SEC_E_MESSAGE_ALTERED |
            SEC_E_INTERNAL_ERROR                      => SslError::ProtocolError,
            // Errors which are releated to an invalid version or unsupported cipher
            SEC_E_UNSUPPORTED_FUNCTION|
            SEC_E_ALGORITHM_MISMATCH                  => SslError::VersionCipherMismatch,
            _                                         => SslError::UnknownError($x)
        })
}

// Extract a value from an enum, ignoring default values and mapping to 0 pointer (since that case cannot occur when this is used)
macro_rules! match_ptr_ignore {
    ($st:expr, $($pat:pat => $result:expr),*) => (match $st {
        $($pat => $result),*,
        // This case cannot happen since when this macro is used, only cases in $matches are possible -> silence the compiler
        _ => 0 as *mut _
    })
}

impl SslInfoServer
{
    /// Create a new SslInfo containing the certificate loaded according to the params
    pub fn new(store: SslCertStore, cond: SslCertCondition) -> Result<SslInfoServer, SslError>
    {
        let store_location: DWORD = match store {
            SslCertStore::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            SslCertStore::User => CERT_SYSTEM_STORE_USERS,
            SslCertStore::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        } | CERT_STORE_READONLY_FLAG;
        let mut store_name = OsStr::new("My").encode_wide().chain(Some(0)).collect::<Vec<_>>();
        let handle = unsafe { 
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM as *mut i8,
                0,
                0,
                store_location,
                store_name.as_mut_ptr() as *mut c_void
            )
        };
        if handle == ptr::null_mut() {
            return Err(SslError::CertificationStoreOpenFailed)
        }

        let mut find_param;
        let mut find_param_data: SslCertConditionValue;
        let mut find_param_ptr = ptr::null_mut();
        
        let find_type = match cond {
            SslCertCondition::SHA1HashIdentical(hash) => {
                find_param_data = SslCertConditionValue::U8Vector(hash.from_hex().unwrap());
                let mut sha1_len: u32 = 0;
                let sha1_hash = match_ptr_ignore!(find_param_data,
                    SslCertConditionValue::U8Vector(ref mut hash) => {
                        sha1_len = hash.len() as u32;
                        hash.as_mut_ptr()
                    }
                );
                find_param = CRYPT_HASH_BLOB { cbData: sha1_len, pbData: sha1_hash };
                find_param_ptr = &mut find_param as *mut _ as *mut c_void;
                CERT_FIND_SHA1_HASH
            },
            SslCertCondition::SubjectContains(name) => {
                find_param_data = SslCertConditionValue::U16Vector(OsStr::new(&name).encode_wide().chain(Some(0)).collect::<Vec<_>>());
                let unicode_name = match_ptr_ignore!(find_param_data, 
                    SslCertConditionValue::U16Vector(ref mut name) => name.as_mut_ptr()
                );
                find_param_ptr = unicode_name as *mut c_void;
                CERT_FIND_SUBJECT_STR
            }
        };

        let ctxt = unsafe { 
            CertFindCertificateInStore(
                handle, 
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                find_type,
                find_param_ptr,
                ptr::null_mut()
            )
        };
        if ctxt == ptr::null_mut() {
            return Err(SslError::CertNotFound)
        }
        return Ok(SslInfoServer {
            cert_store: Arc::new(SchannelCertStore(handle)),
            cert_ctxt: Arc::new(SchannelCertCtxt(ctxt))
        })
    }
}

/// ARC mut macro (unsafe) to fetch stored handles
macro_rules! get_mut_handle(
    ($self_:ident, $field:ident) => { &(*$self_.$field).0 as *const SecHandle as *mut SecHandle };
);

impl<S: Read + Write> SslStream<S> 
{
    /// Instantiate a new SSL-stream
    pub fn new(stream: S, ssl_info: &Arc<SslInfo>) -> Result<SslStream<S>, SslError>
    {
        let ssl_stream = SslStream { 
            stream: stream, 
            info: ssl_info.clone(),
            target_name: None,
            stream_sizes: SecPkgContext_StreamSizes { cbHeader: 0, cbTrailer: 0, cbMaximumMessage: 0, cBuffers: 0, cbBlockSize: 0 },
            read_buf: Vec::new(),
            read_buf_raw: Vec::new(),
            ctxt: Arc::new(SchannelCtxtHandle(CtxtHandle { dwLower: 0, dwUpper: 0 })),
            cred_handle: Arc::new(SchannelCredHandle(CredHandle { dwLower: 0, dwUpper: 0 }))
        };
        return Ok(ssl_stream)
    }


    pub fn set_host(&mut self, host: &str)
    {
        self.target_name = Some(host.to_owned());
    }

    fn get_credentials_handle(&mut self) -> Option<SslError>
    {
        let ssl_info = &*self.info;
        let mut cert_amount: DWORD = 0;

        let mut flags = 0;

        let mut certs; 
        let cert_ctxts = match ssl_info {
            &SslInfo::Client(ref info) => {
                flags = SCH_CRED_NO_DEFAULT_CREDS;
                if info.disable_peer_verification {
                    flags |= SCH_CRED_MANUAL_CRED_VALIDATION;
                } else {
                    flags |= SCH_CRED_AUTO_CRED_VALIDATION;
                }
                ptr::null_mut()
            }
            &SslInfo::Server(ref info) => {
                cert_amount = 1;
                certs = [info.cert_ctxt.0];
                certs.as_mut_ptr() as *mut *const CERT_CONTEXT
            }
        };

        let mut creds = SCHANNEL_CRED { 
            dwVersion: SCHANNEL_CRED_VERSION,
            grbitEnabledProtocols: SP_PROT_ALL,
            dwFlags: flags,
            dwCredFormat: 0,
            aphMappers: ptr::null_mut(),
            paCred: cert_ctxts,
            cMappers: 0,
            palgSupportedAlgs: ptr::null_mut(),
            cSupportedAlgs: 0,
            dwSessionLifespan: 0,
            cCreds: cert_amount,
            dwMaximumCipherStrength: 0,
            hRootStore: ptr::null_mut(),
            dwMinimumCipherStrength: 0
        };

        let cred_use = match ssl_info {
            &SslInfo::Client(_) => SECPKG_CRED_OUTBOUND,
            &SslInfo::Server(_) => SECPKG_CRED_INBOUND
        };

        let cred_handle = get_mut_handle!(self, cred_handle);
        let mut sec_package = OsStr::new(UNISP_NAME).encode_wide().chain(Some(0)).collect::<Vec<_>>();
        let status = unsafe { secur32::AcquireCredentialsHandleW(
                ptr::null_mut(),
                sec_package.as_mut_ptr(),
                cred_use,
                ptr::null_mut(),
                &mut creds as *mut _ as *mut c_void,
                None,
                ptr::null_mut(),
                cred_handle as *mut CredHandle,
                ptr::null_mut()
            ) 
        };

        if status != SEC_E_OK {
            return Some(map_security_error!(status))
        }
        return None
    }

    fn get_ssl_flags(&self) -> u32 {
        return  ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_REPLAY_DETECT   |
                ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_ALLOCATE_MEMORY |
                //ISC_REQ_MANUAL_CRED_VALIDATION |
                ISC_REQ_STREAM;
    }

    fn do_handshake(&mut self) -> Option<SslError> 
    {
        let ssl_info = &*self.info;
        let mut read_buffer = Vec::new();
        let flags = self.get_ssl_flags();
        let mut status = SEC_I_CONTINUE_NEEDED;

        let mut initial: bool = true;
        let mut do_read: bool = match ssl_info {
            &SslInfo::Client(_) => false,
            &SslInfo::Server(_) => true
        };

        while status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE || status == SEC_I_INCOMPLETE_CREDENTIALS
        {
            if do_read && (status == SEC_E_INCOMPLETE_MESSAGE || read_buffer.len() == 0) {
                let mut buf = [0; 8192];
                let read_bytes = match self.stream.read(&mut buf) {
                    Ok(x) => x,
                    Err(_) => 0
                };
                // Nothing read, nothing about the state changes
                if read_bytes == 0 {
                    debug!("Read nothing");
                    break;
                }
                read_buffer.extend(buf[..read_bytes].iter().cloned());
                debug!("Reading {} bytes -> {}", read_bytes, read_buffer.len());
            }

            // Setup input buffers, buffer 0 is used for data received from the server, leftover data will be placed in buffer 1 (with buffer type SECBUFFER_EXTRA)
            let mut in_buffers = [
                SecBuffer { pvBuffer: &mut read_buffer[..] as *mut _ as *mut c_void, cbBuffer: read_buffer.len() as u32, BufferType: SECBUFFER_TOKEN },
                SecBuffer { pvBuffer: ptr::null_mut(), cbBuffer: 0, BufferType: SECBUFFER_EMPTY }
            ];
            let mut in_buffer_desc = SecBufferDesc { cBuffers: 2, pBuffers: &mut in_buffers[0] as *mut SecBuffer, ulVersion: SECBUFFER_VERSION };
            // Setup output buffers
            let mut out_buffers = [ SecBuffer { pvBuffer: ptr::null_mut(), BufferType: SECBUFFER_TOKEN, cbBuffer: 0} ];
            let mut out_buffer_desc = SecBufferDesc { cBuffers: 1, pBuffers: &mut out_buffers[0] as *mut SecBuffer, ulVersion: SECBUFFER_VERSION };

            let mut out_flags: DWORD = 0;

            let ctxt = get_mut_handle!(self, ctxt);
            let cred_handle = get_mut_handle!(self, cred_handle);

            let mut stored_ctx = match initial {
                true => ptr::null_mut(),
                false  => ctxt as *mut _
            };

            match ssl_info {
                &SslInfo::Client(_) => {
                    status = unsafe {
                        do_read = true;
                        let mut target_name = ptr::null_mut();
                        let mut in_buffer_desc_ptr = ptr::null_mut();
                        if initial && self.target_name != None {
                            target_name = OsStr::new(&self.target_name.as_mut().unwrap()).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>().as_mut_ptr();
                        } else {
                            in_buffer_desc_ptr = &mut in_buffer_desc;
                        }

                        secur32::InitializeSecurityContextW(
                            cred_handle as *mut CredHandle,
                            stored_ctx,
                            target_name,
                            flags,
                            0,
                            0,
                            in_buffer_desc_ptr,
                            0,
                            ctxt,
                            &mut out_buffer_desc,
                            &mut out_flags as *mut u32,
                            ptr::null_mut()
                        )
                    };
                },
                &SslInfo::Server(_) => {
                    status = unsafe {
                        secur32::AcceptSecurityContext(
                            cred_handle as *mut CredHandle,
                            stored_ctx,
                            &mut in_buffer_desc,
                            flags,
                            0,
                            ctxt,
                            &mut out_buffer_desc,
                            &mut out_flags as *mut u32,
                            ptr::null_mut()
                        )
                    }
                }
            }

            if (status != SEC_E_OK && status != SEC_E_INVALID_TOKEN && status != SEC_I_CONTINUE_NEEDED) || ((out_flags & ISC_RET_EXTENDED_ERROR) != 0) {
                if !initial {
                    continue;
                } else {
                    return Some(map_security_error!(status))
                }
            }
            else {
                initial = false;
                // We have some data to send to the server
                if out_buffers[0].cbBuffer != 0 && out_buffers[0].pvBuffer != ptr::null_mut() {
                    debug!("--WRITING {}", out_buffers[0].cbBuffer);
                    self.stream.write(unsafe { slice::from_raw_parts(out_buffers[0].pvBuffer as *mut u8, out_buffers[0].cbBuffer as usize) }).unwrap();
                    unsafe { FreeContextBuffer(out_buffers[0].pvBuffer); }
                }
            }
            
            if status == SEC_E_INCOMPLETE_MESSAGE {
                debug!("Incomplete; Continue");
                continue;
            }
            if status == SEC_E_OK {
                let status = unsafe { QueryContextAttributesW(ctxt, SECPKG_ATTR_STREAM_SIZES, &mut self.stream_sizes as *mut _ as *mut c_void) };
                if status != SEC_E_OK {
                    return Some(SslError::HandshakeFailedNoStreamSizes);
                }
                debug!("-[HANDSHAKE] done {}", in_buffers[1].BufferType == SECBUFFER_EXTRA);
                return None
            }
            // There is extra data to be handled TODO: Handle extra data on success and this might be bugged
            if in_buffers[1].BufferType == SECBUFFER_EXTRA {
                debug!("extra data todo this is bugged");
                let pos = read_buffer.len() - in_buffers[1].cbBuffer as usize;
                let end_pos = pos + in_buffers[1].cbBuffer as usize;
                read_buffer = read_buffer[pos..end_pos].to_vec();
            } else {
                read_buffer.clear();
            }
        }
        return Some(map_security_error!(status))
    }

    /// Initialize the connection for the usage of SSL, including performing a handshake
    pub fn init(&mut self) -> Option<SslError> {
        match self.get_credentials_handle() {
            Some(x) => return Some(x),
            None => {}
        };
        match self.do_handshake() {
            Some(x) => return Some(x),
            None => {}
        };
        return None
    }
}

impl<S: Read + Write> Read for SslStream<S>
{
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize>
    {
        let mut dst_vec: Vec<u8> = Vec::new();
        let mut data_left = dst.len();

        let mut buffers = [ 
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() }
        ];
        let mut message = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 4, pBuffers: &mut buffers[0] as *mut SecBuffer};

        // If we have some data in the buffer already, fetch as much as we might need
        if self.read_buf.len() > 0 {
            let iterator_len;
            let available_len;
            {
                available_len = self.read_buf.len();
                let iterator = self.read_buf.iter().take(dst.len());
                iterator_len = iterator.len();
                dst_vec.extend(iterator);
                data_left -= iterator_len;
            }
            // Make sure we do not read the same data multiple times
            if iterator_len < available_len {
                self.read_buf = self.read_buf[iterator_len..].to_vec();
            } else {
                self.read_buf.clear();
            }
        }

        //TODO: maybe handle that as separate reads/more efficiently?
        
        let mut status = SEC_E_INCOMPLETE_MESSAGE;

        let ctxt = get_mut_handle!(self, ctxt);

        let mut buf = vec![0 as u8; 0];
        loop 
        {
            if data_left == 0 {
                break;
            }

            // If we have some raw data stored to decrypt, fetch it
            if self.read_buf_raw.len() > 0
            {
                buf.extend(&self.read_buf_raw[..]); //is a .clone() necessary here?
                debug!("[EXTRA] read {}", self.read_buf_raw.len());
                self.read_buf_raw.clear();
            }

            let mut i_read_buf = vec![0 as u8; 8192];
            let bytes = self.stream.read(&mut i_read_buf).unwrap(); //Error Handling TODO
            if bytes > 0 {
                buf.extend(&i_read_buf[..bytes]);
            }

            if bytes + buf.len() == 0 {
                //TODO: store unused buf data on break (read_buf_raw)
                break;
            }
            
            buffers[0].pvBuffer = buf.as_mut_ptr() as *mut c_void; 
            buffers[0].cbBuffer = buf.len() as u32;
            buffers[0].BufferType = SECBUFFER_DATA;

            buffers[1].BufferType = SECBUFFER_EMPTY;
            buffers[2].BufferType = SECBUFFER_EMPTY;
            buffers[3].BufferType = SECBUFFER_EMPTY;
            unsafe {
                status = DecryptMessage(ctxt as *mut SecHandle, &mut message as *mut SecBufferDesc, 0, ptr::null_mut());
                debug!("decrypt status: {} -> {}", buf.len(), status);

                // Store extra data (not decrypted yet = raw), if available
                if status == SEC_E_INCOMPLETE_MESSAGE {
                    continue;
                }
                buf.clear();

                match buffers.iter().find(|&buf| buf.BufferType == SECBUFFER_EXTRA) {
                    Some(extra_buf) => {
                        let extra_buf = std::slice::from_raw_parts(extra_buf.pvBuffer as *mut u8, extra_buf.cbBuffer as usize);
                        debug!("[EXTRA] store {}", extra_buf.len());
                        self.read_buf_raw.extend(extra_buf);                        
                    },
                    None => ()
                }

                // Store decrypted data
                match buffers.iter().find(|&buf| buf.BufferType == SECBUFFER_DATA) {
                    Some(data_buffer) => {
                        debug!("data length: {}", data_buffer.cbBuffer);
                        
                        let data_buffer = std::slice::from_raw_parts(data_buffer.pvBuffer as *mut u8, data_buffer.cbBuffer as usize);
                        let iterator = data_buffer.iter().take(data_left);
                        let iterator_len = iterator.len();
                        dst_vec.extend(iterator);
                        data_left -= iterator_len;

                        // store additional decrypted data
                        if data_buffer.len() > iterator_len {
                            self.read_buf.extend(data_buffer.iter().skip(iterator_len));
                            debug!("read_buf: {} bytes", self.read_buf.len());
                        }
                        //println!("\n\nContent ({}) \n\n{}", iterator_len, std::str::from_utf8(&dst[..dst.len()-data_left]).unwrap());

                        buf.clear();
                    },
                    None => {
                        debug!("No data buffer, incomplete: {}", status == SEC_E_INCOMPLETE_MESSAGE)
                    }
                };
            }
        }

        if dst_vec.len() == 0 {
            return Ok(0)
        }
        debug!("conv_len: {}/{} ({})", dst_vec.len(), dst.len(), data_left);
        // Copy vector into output slice
        for (d, s) in dst.iter_mut().zip(dst_vec.iter()) {
            *d = *s;
        }
        //println!("req {}", std::str::from_utf8(dst).unwrap());
        Ok(dst_vec.len())
    }
}

impl<S: Read + Write> Write for SslStream<S>
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>
    {
        let mut buffers = [ 
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() }
        ];
        let mut message = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 4, pBuffers: &mut buffers[0] as *mut SecBuffer };

        if self.stream_sizes.cbHeader == 0 {
            return Err(IoError::new(std::io::ErrorKind::Other, "SSLStream doesn't seem initialized. Maybe you forgot to call .init?"));
        }

        let mut buffer = vec![0 as u8; self.stream_sizes.cbHeader as usize];
        buffer.extend(buf.iter().cloned());
        buffer.extend(vec![0 as u8; self.stream_sizes.cbTrailer as usize + self.stream_sizes.cbMaximumMessage as usize - buf.len()]);

        let mut ptr: *mut u8 = buffer.as_mut_ptr();
        buffers[0].pvBuffer     = ptr as *mut c_void;
        buffers[0].cbBuffer     = self.stream_sizes.cbHeader;
        buffers[0].BufferType   = SECBUFFER_STREAM_HEADER;

        ptr = (ptr as usize + self.stream_sizes.cbHeader as usize) as *mut u8;
        buffers[1].pvBuffer     = ptr as *mut c_void;
        buffers[1].cbBuffer     = buf.len() as u32;
        buffers[1].BufferType   = SECBUFFER_DATA;

        ptr = (ptr as usize + buf.len()) as *mut u8;
        buffers[2].pvBuffer     = ptr as *mut c_void;
        buffers[2].cbBuffer     = self.stream_sizes.cbTrailer;
        buffers[2].BufferType   = SECBUFFER_STREAM_TRAILER;

        buffers[3].BufferType   = SECBUFFER_EMPTY;

        let ctxt = get_mut_handle!(self, ctxt);

        //TODO: Respect stream_sizes.cbMaximumMessage (encryption length limit)
        unsafe {
            let status = EncryptMessage(ctxt as *mut SecHandle, 0, &mut message as *mut SecBufferDesc, 0);
            if status == SEC_E_OK {
                let len = buffers[0].cbBuffer as usize + buffers[1].cbBuffer as usize + buffers[2].cbBuffer as usize;
                debug!("Encrypted {}. Sending. {}", len, buffers[3].BufferType == SECBUFFER_EMPTY);
                self.stream.write(&buffer[..len]).unwrap();
            }
        }
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for SchannelCredHandle
{
    fn drop(&mut self) {
        unsafe {
            assert!(FreeCredentialsHandle(&mut self.0 as *mut CredHandle) == SEC_E_OK);
        }
    }
}

impl Drop for SchannelCtxtHandle
{
    fn drop(&mut self) {
        unsafe {
            assert!(DeleteSecurityContext(&mut self.0 as *mut CtxtHandle) == SEC_E_OK);
        }
    }
}

impl Drop for SchannelCertStore
{
    fn drop(&mut self) {
        unsafe {
            assert!(CertCloseStore(self.0, 0) == 1);
        }
    }
}

impl Drop for SchannelCertCtxt
{
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.0);
        }
    }
}
