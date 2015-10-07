//! Winssl is a pure-Rust wrapper to provide SSL functionality under windows by using schannel, which
//! removes the requirement of openssl.

extern crate winapi;
extern crate crypt32;
extern crate secur32;
extern crate rustc_serialize;

use std::io::prelude::*;
use std::ptr;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::slice;
use winapi::*;
use secur32::*;
use crypt32::*;
use rustc_serialize::hex::{FromHex, ToHex};

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

pub const CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG: DWORD = 0x00000004;
pub const CERT_STORE_READONLY_FLAG: DWORD = 0x00008000;

pub const CERT_COMPARE_SHA1_HASH: DWORD = 1;
pub const CERT_COMPARE_SHIFT: DWORD = 16;

pub const CERT_FIND_SHA1_HASH: DWORD = CERT_COMPARE_SHA1_HASH << CERT_COMPARE_SHIFT;

// TODO: General error handling
// TODO: renegotiation, disconnect, Fix behavior without inernet (Reading 0 bytes..)
// TODO: Manual certificate validation


pub enum SslInfo {
    Client(SslInfoClient),
    Server(SslInfoServer)
}

/// SSL client wrapper configuration
pub struct SslInfoClient
{
    /// A pointer to a null-terminated string that uniquely identifies the target server (e.g. www.google.de)
    pub target_name: String
}

/// SSL wrapper configuration, which only applies to SSL peers/servers
pub struct SslInfoServer
{
    cert_store: *mut c_void,
    cert_ctxt: *const winapi::wincrypt::CERT_CONTEXT
}

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

pub enum SslCertCondition
{
    SHA1HashIdentical { hash: String }
}

/// SSL wrapper for generic streams
pub struct SslStream<'a, S> 
{
    stream: S,
    info: &'a SslInfo,
    ctxt: CtxtHandle,
    cred_handle: CredHandle,
    stream_sizes: SecPkgContext_StreamSizes,
    read_buf: Option<Vec<u8>>,
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
    UnknownError { err_code: i32 }
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
            _                                         => SslError::UnknownError { err_code: $x }
        })
}

impl SslInfoServer
{
    /// Create a new SslInfo containing the certificate loaded according to the params
    pub fn new(store: SslCertStore, cond: SslCertCondition) -> Result<SslInfoServer, SslError>
    {
        let store_location = match store {
            SslCertStore::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            SslCertStore::User => CERT_SYSTEM_STORE_USERS,
            SslCertStore::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        } | CERT_STORE_READONLY_FLAG; //| CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG;
        let store_name = OsStr::new("MY").encode_wide().chain(Some(0)).collect::<Vec<_>>().as_mut_ptr();
        let handle = unsafe { 
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM as *mut i8,
                0,
                0,
                store_location,
                store_name as *mut c_void
            )
        };
        if handle == ptr::null_mut() {
            return Err(SslError::CertificationStoreOpenFailed)
        }

        let mut find_param;
        let mut find_param_ptr = ptr::null_mut();
        
        let find_type = match cond {
            SslCertCondition::SHA1HashIdentical { hash } => {
                let mut sha1_hash = hash.from_hex().unwrap();
                find_param = CRYPT_HASH_BLOB { cbData: sha1_hash.len() as u32, pbData: sha1_hash.as_mut_ptr() };
                find_param_ptr = &mut find_param as *mut _ as *mut c_void;
                CERT_FIND_SHA1_HASH
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
            cert_store: handle,
            cert_ctxt: ctxt
        })
    }
}

impl Drop for SslInfoServer
{
    fn drop(&mut self) {
        unsafe {
            CertFreeCertificateContext(self.cert_ctxt);
            CertCloseStore(self.cert_store, 0);
        }
    }
}


impl<'a, S: Read+Write> SslStream<'a, S> 
{
    /// Instantiate a new SSL-stream, initializing the stream including a handshake
    pub fn new(stream: S, ssl_info: &SslInfo) -> Result<SslStream<S>, SslError>
    {
        let mut ssl_stream = SslStream { 
            stream: stream, 
            info: ssl_info, 
            ctxt: CtxtHandle { dwLower: 0, dwUpper: 0 },
            stream_sizes: SecPkgContext_StreamSizes { cbHeader: 0, cbTrailer: 0, cbMaximumMessage: 0, cBuffers: 0, cbBlockSize: 0 },
            read_buf: None,
            cred_handle: CredHandle { dwLower: 0, dwUpper: 0 }
        };
        match ssl_stream.init() {
            Some(x) => return Err(x),
            None => {}
        };
        return Ok(ssl_stream)
    }

    pub fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize>
    {
        let mut buffers = [ 
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() }
        ];
        let mut message = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 4, pBuffers: &mut buffers[0] as *mut SecBuffer};

        //TODO handle dst.len() > 8192 (buf.len)
        let mut buf = [0; 8192];

        // If we have some data in the buffer already, fetch as much as we might need
        let mut dst_pos = 0;
        if self.read_buf != None {
            // Already write the amount we need into our dst buffer
            for (d, s) in dst.iter_mut().zip(self.read_buf.as_mut().unwrap().iter()) {
                *d = *s;
                dst_pos += 1;
            }
            // Make sure we do not read the same data multiple times
            if dst_pos < self.read_buf.as_mut().unwrap().len() {
                let vec: Vec<_> = self.read_buf.as_mut().unwrap()[dst_pos..].to_vec();
                self.read_buf = Some(vec);
            } else {
                self.read_buf = None;
            }
        }

        let bytes = self.stream.read(&mut buf).unwrap(); //Error Handling TODO
        println!("decrypt read: {}", bytes);

        buffers[0].pvBuffer = &mut buf as *mut _ as *mut c_void; 
        buffers[0].cbBuffer = buf.len() as u32;
        buffers[0].BufferType = SECBUFFER_DATA;

        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        unsafe {
            let status = DecryptMessage(&mut self.ctxt as *mut SecHandle, &mut message as *mut SecBufferDesc, 0, ptr::null_mut());
            println!("decrypt status: {}", status);
            match buffers.iter().find(|&buf| buf.BufferType == SECBUFFER_DATA) {
                Some(data_buffer) => {
                    println!("data length: {}", data_buffer.cbBuffer);
                    
                    let data_buffer = std::slice::from_raw_parts(data_buffer.pvBuffer as *mut u8, data_buffer.cbBuffer as usize);
                    let mut len = 0;
                    for (d, s) in dst.iter_mut().skip(dst_pos).zip(data_buffer.iter()) {
                        *d = *s;
                        len += 1;
                    }

                    // store additional decrypted data
                    if data_buffer.len() > len {
                        if self.read_buf == None {
                            let vec: Vec<u8> = Vec::new();
                            self.read_buf = Some(vec);
                        }
                        self.read_buf.as_mut().unwrap().extend(data_buffer.iter().skip(len));
                        println!("read_buf: {} bytes", self.read_buf.as_mut().unwrap().len());
                    }
                    println!("\n\nContent ({}) \n\n{}", len, std::str::from_utf8(&dst[..len]).unwrap());
                    return Ok(dst.len())
                },
                None => println!("No data buffer, incomplete: {}", status == SEC_E_INCOMPLETE_MESSAGE)
            };
            //TODO handle incomplete messages (SEC_E_INCOMPLETE_MESSAGE)
        }
        // TODO
        Ok(0)
    }

    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>
    {
        let mut buffers = [ 
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() },
            SecBuffer { BufferType: SECBUFFER_EMPTY, cbBuffer: 0, pvBuffer: ptr::null_mut() }
        ];
        let mut message = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 4, pBuffers: &mut buffers[0] as *mut SecBuffer };

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

        unsafe {
            let status = EncryptMessage(&mut self.ctxt as *mut SecHandle, 0, &mut message as *mut SecBufferDesc, 0);
            if status == SEC_E_OK {
                let len = buffers[0].cbBuffer as usize + buffers[1].cbBuffer as usize + buffers[2].cbBuffer as usize;
                println!("Encrypted {}. Sending.", len);
                self.stream.write(&buffer[..len]);
            }
        }
        // TODO
        Ok(0)
    }

    fn get_credentials_handle(&mut self) -> Option<SslError>
    {
        let mut cert_amount: DWORD = 0;
        let mut cert_ctxts = match self.info {
            &SslInfo::Client(_) => ptr::null_mut(),
            &SslInfo::Server(ref info) => {
                cert_amount = 1;
                [info.cert_ctxt].as_ptr() as *mut *const CERT_CONTEXT
            }
        };

        let mut creds = SCHANNEL_CRED { 
            dwVersion: SCHANNEL_CRED_VERSION,
            grbitEnabledProtocols: SP_PROT_ALL,
            dwFlags: SCH_CRED_AUTO_CRED_VALIDATION | /*SCH_CRED_MANUAL_CRED_VALIDATION | */SCH_CRED_NO_DEFAULT_CREDS,
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

        let cred_use = match self.info {
            &SslInfo::Client(_) => SECPKG_CRED_OUTBOUND,
            &SslInfo::Server(_) => SECPKG_CRED_INBOUND
        };

        let status = unsafe { secur32::AcquireCredentialsHandleW(
                ptr::null_mut(),
                OsStr::new(UNISP_NAME).encode_wide().chain(Some(0)).collect::<Vec<_>>().as_mut_ptr(),
                cred_use,
                ptr::null_mut(),
                &mut creds as *mut _ as *mut c_void,
                None,
                ptr::null_mut(),
                &mut self.cred_handle as *mut CredHandle,
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

    fn initialize_ssl_context(&mut self) -> Option<SslError>
    {
        // Initialize some req buffers (output)
        let mut sec_buffer = SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: ptr::null_mut() };
        let mut sec_buffer_desc = SecBufferDesc { cBuffers: 1, pBuffers: &mut sec_buffer, ulVersion: SECBUFFER_VERSION };
        let mut out_flags: DWORD = 0;

        let flags = self.get_ssl_flags();

        let mut status;
        match self.info {
            &SslInfo::Client(ref client_info) => {
                status = unsafe { 
                    secur32::InitializeSecurityContextW(
                        &mut self.cred_handle as *mut CredHandle,
                        ptr::null_mut(), // (null on first call)
                        OsStr::new(&client_info.target_name).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>().as_mut_ptr(),
                        flags,
                        0,
                        0,
                        ptr::null_mut(),
                        0,
                        &mut self.ctxt as *mut CtxtHandle,
                        &mut sec_buffer_desc as *mut SecBufferDesc,
                        &mut out_flags as *mut u32,
                        ptr::null_mut()
                    )
                };
            }
            &SslInfo::Server(_) => {
                // Prepare additional input buffers
                return None;
                /*status = unsafe {
                    secur32::AcceptSecurityContext(
                        &mut self.cred_handle as *mut CredHandle,
                        ptr::null_mut(),
                        ptr::null_mut(), //pInput probably needed
                        flags,
                        0,
                        &mut self.ctxt as *mut CtxtHandle,
                        &mut sec_buffer_desc as *mut SecBufferDesc,
                        &mut out_flags as *mut u32,
                        ptr::null_mut()
                    )
                };*/
            }
        };

        if status != SEC_I_CONTINUE_NEEDED {
            return Some(map_security_error!(status))
        }
        unsafe {
            let handshake = slice::from_raw_parts(sec_buffer.pvBuffer as *mut u8, sec_buffer.cbBuffer as usize);
            self.stream.write(handshake).unwrap(); //TODO: Error Handling
            FreeContextBuffer(sec_buffer.pvBuffer);
        }

        println!("Sent {} bytes of handshake data", sec_buffer.cbBuffer);
        return None;
    }

    fn do_handshake(&mut self) -> Option<SslError> 
    {
        let mut read_buffer = Vec::new();
        let flags = self.get_ssl_flags();
        let mut status = SEC_I_CONTINUE_NEEDED;

        while status == SEC_I_CONTINUE_NEEDED || status == SEC_E_INCOMPLETE_MESSAGE || status == SEC_I_INCOMPLETE_CREDENTIALS
        {
            if status == SEC_E_INCOMPLETE_MESSAGE || read_buffer.len() == 0 {
                let mut buf = [0; 4096];
                let read_bytes = match self.stream.read(&mut buf) {
                    Ok(x) => x,
                    Err(_) => 0
                };
                // Nothing read, nothing about the state changes
                if read_bytes == 0 {
                    continue;
                }
                read_buffer.extend(buf[..read_bytes].iter().cloned());
                println!("Reading {} bytes -> {}", read_bytes, read_buffer.len());
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
            match self.info {
                &SslInfo::Client(ref client_info) => {
                    status = unsafe { 
                        secur32::InitializeSecurityContextW(
                            &mut self.cred_handle as *mut CredHandle,
                            &mut self.ctxt,
                            ptr::null_mut(),
                            flags,
                            0,
                            0,
                            &mut in_buffer_desc,
                            0,
                            ptr::null_mut(),
                            &mut out_buffer_desc,
                            &mut out_flags as *mut u32,
                            ptr::null_mut()
                        )
                    };
                },
                &SslInfo::Server(_) => {
                    status = unsafe {
                        let stored_ctx = if self.ctxt.dwLower == 0 && self.ctxt.dwUpper == 0 { 
                            ptr::null_mut() 
                        } else {
                            &mut self.ctxt as *mut _
                        };
                        secur32::AcceptSecurityContext(
                            &mut self.cred_handle as *mut CredHandle,
                            stored_ctx,
                            &mut in_buffer_desc,
                            flags,
                            0,
                            &mut self.ctxt,
                            &mut out_buffer_desc as *mut SecBufferDesc,
                            &mut out_flags as *mut u32,
                            ptr::null_mut()
                        )
                    }
                }
            }
            println!("run accept {}", status);
            if (status != SEC_E_OK && status != SEC_E_INVALID_TOKEN && status != SEC_I_CONTINUE_NEEDED) || ((out_flags & ISC_RET_EXTENDED_ERROR) != 0) {
                continue;
            }
            else {
                // We have some data to send to the server
                if out_buffers[0].cbBuffer != 0 && out_buffers[0].pvBuffer != ptr::null_mut() {
                    println!("--WRITING");
                    self.stream.write(unsafe { slice::from_raw_parts(out_buffers[0].pvBuffer as *mut u8, out_buffers[0].cbBuffer as usize) });
                    unsafe { FreeContextBuffer(out_buffers[0].pvBuffer); }
                }
            }
            if status == SEC_E_INCOMPLETE_MESSAGE {
                println!("Incomplete; Continue");
                continue;
            }
            if status == SEC_E_OK {
                let status = unsafe { QueryContextAttributesW(&mut self.ctxt, SECPKG_ATTR_STREAM_SIZES, &mut self.stream_sizes as *mut _ as *mut c_void) };
                if status != SEC_E_OK {
                    return Some(SslError::HandshakeFailedNoStreamSizes);
                }
                println!("Handshake done");
                return None
            }

            // There is extra data to be handled TODO: Handle extra data on success
            if in_buffers[1].BufferType == SECBUFFER_EXTRA {
                let pos = read_buffer.len() - in_buffers[1].cbBuffer as usize;
                let end_pos = pos + in_buffers[1].cbBuffer as usize;
                read_buffer = read_buffer[pos..end_pos].to_vec();
            } else {
                read_buffer.clear();
            }
        }
        return Some(map_security_error!(status))
    }

    /// Prepare for the usage of SSL, including performing a handshake
    fn init(&mut self) -> Option<SslError> {
        match self.get_credentials_handle() {
            Some(x) => return Some(x),
            None => {}
        };
        match self.initialize_ssl_context() {
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

impl<'a, S> Drop for SslStream<'a, S>
{
    fn drop(&mut self) {
        unsafe {
            assert!(DeleteSecurityContext(&mut self.ctxt as *mut CtxtHandle) == SEC_E_OK);
            assert!(FreeCredentialsHandle(&mut self.cred_handle as *mut CredHandle) == SEC_E_OK);
        }
    }
}
