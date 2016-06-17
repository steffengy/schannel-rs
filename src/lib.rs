extern crate crypt32;
extern crate kernel32;
extern crate libc;
extern crate secur32;
extern crate winapi;

use libc::c_ulong;
use std::cmp;
use std::io::{self, BufRead, Read, Write, Cursor};
use std::mem;
use std::ops::Deref;
use std::ptr;
use std::slice;

use cert_store::CertStore;

pub mod cert_context;
pub mod cert_store;
pub mod ctl_context;

#[cfg(test)]
mod test;

const INIT_REQUESTS: c_ulong =
    winapi::ISC_REQ_CONFIDENTIALITY | winapi::ISC_REQ_INTEGRITY | winapi::ISC_REQ_REPLAY_DETECT |
    winapi::ISC_REQ_SEQUENCE_DETECT | winapi::ISC_REQ_MANUAL_CRED_VALIDATION |
    winapi::ISC_REQ_ALLOCATE_MEMORY | winapi::ISC_REQ_STREAM;

struct CertContext(*mut winapi::CERT_CONTEXT);

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe {
            crypt32::CertFreeCertificateContext(self.0);
        }
    }
}

struct CertChainContext(*const winapi::CERT_CHAIN_CONTEXT);

impl Drop for CertChainContext {
    fn drop(&mut self) {
        unsafe {
            crypt32::CertFreeCertificateChain(self.0);
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375549(v=vs.85).aspx
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Algorithm {
    /// Advanced Encryption Standard (AES).
    Aes = winapi::CALG_AES,
    /// 128 bit AES.
    Aes128 = winapi::CALG_AES_128,
    /// 192 bit AES.
    Aes192 = winapi::CALG_AES_192,
    /// 256 bit AES.
    Aes256 = winapi::CALG_AES_256,
    /// Temporary algorithm identifier for handles of Diffie-Hellman–agreed keys.
    AgreedkeyAny = winapi::CALG_AGREEDKEY_ANY,
    /// An algorithm to create a 40-bit DES key that has parity bits and zeroed key bits to make
    /// its key length 64 bits.
    CylinkMek = winapi::CALG_CYLINK_MEK,
    /// DES encryption algorithm.
    Des = winapi::CALG_DES,
    /// DESX encryption algorithm.
    Desx = winapi::CALG_DESX,
    /// Diffie-Hellman ephemeral key exchange algorithm.
    DhEphem = winapi::CALG_DH_EPHEM,
    /// Diffie-Hellman store and forward key exchange algorithm.
    DhSf = winapi::CALG_DH_SF,
    /// DSA public key signature algorithm.
    DssSign = winapi::CALG_DSS_SIGN,
    /// Elliptic curve Diffie-Hellman key exchange algorithm.
    Ecdh = winapi::CALG_ECDH,
    // https://github.com/retep998/winapi-rs/issues/287
    // /// Ephemeral elliptic curve Diffie-Hellman key exchange algorithm.
    // EcdhEphem = winapi::CALG_ECDH_EPHEM,
    /// Elliptic curve digital signature algorithm.
    Ecdsa = winapi::CALG_ECDSA,
    /// One way function hashing algorithm.
    HashReplaceOwf = winapi::CALG_HASH_REPLACE_OWF,
    /// Hughes MD5 hashing algorithm.
    HughesMd5 = winapi::CALG_HUGHES_MD5,
    /// HMAC keyed hash algorithm.
    Hmac = winapi::CALG_HMAC,
    /// MAC keyed hash algorithm.
    Mac = winapi::CALG_MAC,
    /// MD2 hashing algorithm.
    Md2 = winapi::CALG_MD2,
    /// MD4 hashing algorithm.
    Md4 = winapi::CALG_MD4,
    /// MD5 hashing algorithm.
    Md5 = winapi::CALG_MD5,
    /// No signature algorithm..
    NoSign = winapi::CALG_NO_SIGN,
    /// RC2 block encryption algorithm.
    Rc2 = winapi::CALG_RC2,
    /// RC4 stream encryption algorithm.
    Rc4 = winapi::CALG_RC4,
    /// RC5 block encryption algorithm.
    Rc5 = winapi::CALG_RC5,
    /// RSA public key exchange algorithm.
    RsaKeyx = winapi::CALG_RSA_KEYX,
    /// RSA public key signature algorithm.
    RsaSign = winapi::CALG_RSA_SIGN,
    /// SHA hashing algorithm.
    Sha1 = winapi::CALG_SHA1,
    /// 256 bit SHA hashing algorithm.
    Sha256 = winapi::CALG_SHA_256,
    /// 384 bit SHA hashing algorithm.
    Sha384 = winapi::CALG_SHA_384,
    /// 512 bit SHA hashing algorithm.
    Sha512 = winapi::CALG_SHA_512,
    /// Triple DES encryption algorithm.
    TripleDes = winapi::CALG_3DES,
    /// Two-key triple DES encryption with effective key length equal to 112 bits.
    TripleDes112 = winapi::CALG_3DES_112,
}

#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    /// Secure Sockets Layer 3.0
    Ssl3,
    /// Transport Layer Security 1.0
    Tls10,
    /// Transport Layer Security 1.1
    Tls11,
    /// Transport Layer Security 1.2
    Tls12,
}

impl Protocol {
    fn dword(self, direction: Direction) -> winapi::DWORD {
        if direction == Direction::Inbound {
            match self {
                Protocol::Ssl3 => winapi::SP_PROT_SSL3_SERVER,
                Protocol::Tls10 => winapi::SP_PROT_TLS1_0_SERVER,
                Protocol::Tls11 => winapi::SP_PROT_TLS1_1_SERVER,
                Protocol::Tls12 => winapi::SP_PROT_TLS1_2_SERVER,
            }
        } else {
            match self {
                Protocol::Ssl3 => winapi::SP_PROT_SSL3_CLIENT,
                Protocol::Tls10 => winapi::SP_PROT_TLS1_0_CLIENT,
                Protocol::Tls11 => winapi::SP_PROT_TLS1_1_CLIENT,
                Protocol::Tls12 => winapi::SP_PROT_TLS1_2_CLIENT,
            }
        }
    }
}

pub struct SchannelCredBuilder {
    supported_algorithms: Option<Vec<Algorithm>>,
    enabled_protocols: Option<Vec<Protocol>>,
}

impl SchannelCredBuilder {
    /// Sets the algorithms supported for sessions created from this builder.
    pub fn supported_algorithms(mut self,
                                supported_algorithms: &[Algorithm])
                                -> SchannelCredBuilder {
        self.supported_algorithms = Some(supported_algorithms.to_owned());
        self
    }

    /// Sets the protocols enabled for sessions created from this builder.
    pub fn enabled_protocols(mut self, enabled_protocols: &[Protocol]) -> SchannelCredBuilder {
        self.enabled_protocols = Some(enabled_protocols.to_owned());
        self
    }

    pub fn acquire(&self, direction: Direction) -> io::Result<SchannelCred> {
        unsafe {
            let mut handle = mem::uninitialized();
            let mut cred_data: winapi::SCHANNEL_CRED = mem::zeroed();
            cred_data.dwVersion = winapi::SCHANNEL_CRED_VERSION;
            cred_data.dwFlags = winapi::SCH_USE_STRONG_CRYPTO;
            if let Some(ref supported_algorithms) = self.supported_algorithms {
                cred_data.cSupportedAlgs = supported_algorithms.len() as winapi::DWORD;
                cred_data.palgSupportedAlgs = supported_algorithms.as_ptr() as *mut _;
            }
            if let Some(ref enabled_protocols) = self.enabled_protocols {
                cred_data.grbitEnabledProtocols = enabled_protocols.iter()
                                                                   .map(|p| p.dword(direction))
                                                                   .fold(0, |acc, p| acc | p);
            }

            let direction = match direction {
                Direction::Inbound => winapi::SECPKG_CRED_INBOUND,
                Direction::Outbound => winapi::SECPKG_CRED_OUTBOUND,
            };

            let mut unisp_name = winapi::UNISP_NAME.bytes().chain(Some(0u8)).collect::<Vec<u8>>();
            match secur32::AcquireCredentialsHandleA(ptr::null_mut(),
                                                     unisp_name.as_mut_slice() as *mut _ as *mut _,
                                                     direction,
                                                     ptr::null_mut(),
                                                     &mut cred_data as *mut _ as *mut _,
                                                     None,
                                                     ptr::null_mut(),
                                                     &mut handle,
                                                     ptr::null_mut()) {
                winapi::SEC_E_OK => Ok(SchannelCred(handle)),
                err => Err(io::Error::from_raw_os_error(err as i32)),
            }
        }
    }
}

pub struct SchannelCred(winapi::CredHandle);

impl Drop for SchannelCred {
    fn drop(&mut self) {
        unsafe {
            secur32::FreeCredentialsHandle(&mut self.0);
        }
    }
}

impl SchannelCred {
    pub fn builder() -> SchannelCredBuilder {
        SchannelCredBuilder {
            supported_algorithms: None,
            enabled_protocols: None,
        }
    }
}

#[derive(Default)]
pub struct TlsStreamBuilder {
    domain: Option<Vec<u16>>,
    cert_store: Option<CertStore>,
}

impl TlsStreamBuilder {
    pub fn new() -> TlsStreamBuilder {
        TlsStreamBuilder::default()
    }

    pub fn domain(&mut self, domain: &str) -> &mut TlsStreamBuilder {
        self.domain = Some(domain.encode_utf16().chain(Some(0)).collect());
        self
    }

    pub fn cert_store(&mut self, cert_store: CertStore) -> &mut TlsStreamBuilder {
        self.cert_store = Some(cert_store);
        self
    }

    pub fn initialize<S>(&self, cred: SchannelCred, stream: S) -> io::Result<TlsStream<S>>
        where S: Read + Write
    {
        let (ctxt, buf) = try!(SecurityContext::initialize(&cred,
                                                           self.domain.as_ref().map(|s| &s[..])));

        let mut stream = TlsStream {
            cred: cred,
            context: ctxt,
            cert_store: self.cert_store.clone(),
            domain: self.domain.clone(),
            stream: stream,
            state: State::Initializing {
                needs_flush: false,
                more_calls: true,
                shutting_down: false,
            },
            needs_read: true,
            dec_in: Cursor::new(Vec::new()),
            enc_in: Cursor::new(Vec::new()),
            out_buf: Cursor::new(buf.to_owned()),
        };

        match stream.initialize() {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        Ok(stream)
    }
}

struct SecurityContext(winapi::CtxtHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        unsafe {
            secur32::DeleteSecurityContext(&mut self.0);
        }
    }
}

impl SecurityContext {
    fn initialize(cred: &SchannelCred,
                  domain: Option<&[u16]>)
                  -> io::Result<(SecurityContext, ContextBuffer)> {
        unsafe {
            let domain = domain.map(|b| b.as_ptr() as *mut u16).unwrap_or(ptr::null_mut());

            let mut ctxt = mem::uninitialized();

            let mut outbuf = winapi::SecBuffer {
                cbBuffer: 0,
                BufferType: winapi::SECBUFFER_EMPTY,
                pvBuffer: ptr::null_mut(),
            };
            let mut outbuf_desc = winapi::SecBufferDesc {
                ulVersion: winapi::SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut outbuf,
            };

            let mut attributes = 0;

            match secur32::InitializeSecurityContextW(&cred.0 as *const _ as *mut _,
                                                      ptr::null_mut(),
                                                      domain,
                                                      INIT_REQUESTS,
                                                      0,
                                                      0,
                                                      ptr::null_mut(),
                                                      0,
                                                      &mut ctxt,
                                                      &mut outbuf_desc,
                                                      &mut attributes,
                                                      ptr::null_mut()) {
                winapi::SEC_I_CONTINUE_NEEDED => Ok((SecurityContext(ctxt), ContextBuffer(outbuf))),
                err => Err(io::Error::from_raw_os_error(err as i32)),
            }
        }
    }

    fn stream_sizes(&mut self) -> io::Result<winapi::SecPkgContext_StreamSizes> {
        unsafe {
            let mut stream_sizes = mem::uninitialized();
            let status = secur32::QueryContextAttributesW(&mut self.0,
                                                          winapi::SECPKG_ATTR_STREAM_SIZES,
                                                          &mut stream_sizes as *mut _ as *mut _);
            if status == winapi::SEC_E_OK {
                Ok(stream_sizes)
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            }
        }
    }

    fn remote_cert(&mut self) -> io::Result<CertContext> {
        unsafe {
            let mut cert_context = mem::uninitialized();
            let status = secur32::QueryContextAttributesW(&mut self.0,
                                                          winapi::SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                                          &mut cert_context as *mut _ as *mut _);
            if status == winapi::SEC_E_OK {
                Ok(CertContext(cert_context))
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            }
        }
    }
}

struct ContextBuffer(winapi::SecBuffer);

impl Drop for ContextBuffer {
    fn drop(&mut self) {
        unsafe {
            secur32::FreeContextBuffer(self.0.pvBuffer);
        }
    }
}

impl Deref for ContextBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.pvBuffer as *const _, self.0.cbBuffer as usize) }
    }
}

enum State {
    Initializing {
        needs_flush: bool,
        more_calls: bool,
        shutting_down: bool,
    },
    Streaming {
        sizes: winapi::SecPkgContext_StreamSizes,
    },
    Shutdown,
}

pub struct TlsStream<S> {
    cred: SchannelCred,
    context: SecurityContext,
    cert_store: Option<CertStore>,
    domain: Option<Vec<u16>>,
    stream: S,
    state: State,
    needs_read: bool,
    // valid from position() to len()
    dec_in: Cursor<Vec<u8>>,
    // valid from 0 to position()
    enc_in: Cursor<Vec<u8>>,
    // valid from position() to len()
    out_buf: Cursor<Vec<u8>>,
}

impl<S> TlsStream<S>
    where S: Read + Write
{
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.state {
            State::Shutdown => return Ok(()),
            State::Initializing { shutting_down: true, .. } => {}
            _ => {
                unsafe {
                    let mut token = winapi::SCHANNEL_SHUTDOWN;
                    let mut buf = winapi::SecBuffer {
                        cbBuffer: mem::size_of_val(&token) as c_ulong,
                        BufferType: winapi::SECBUFFER_TOKEN,
                        pvBuffer: &mut token as *mut _ as *mut _,
                    };
                    let mut desc = winapi::SecBufferDesc {
                        ulVersion: winapi::SECBUFFER_VERSION,
                        cBuffers: 1,
                        pBuffers: &mut buf,
                    };
                    match secur32::ApplyControlToken(&mut self.context.0, &mut desc) {
                        winapi::SEC_E_OK => {}
                        err => return Err(io::Error::from_raw_os_error(err as i32)),
                    }
                }

                self.state = State::Initializing {
                    needs_flush: false,
                    more_calls: true,
                    shutting_down: true,
                };
                self.needs_read = false;
            }
        }

        self.initialize().map(|_| ())
    }

    fn step_initialize(&mut self) -> io::Result<()> {
        unsafe {
            let domain = self.domain
                .as_ref()
                .map(|b| b.as_ptr() as *mut u16)
                .unwrap_or(ptr::null_mut());

            let inbufs = &mut [winapi::SecBuffer {
                                   cbBuffer: self.enc_in.position() as c_ulong,
                                   BufferType: winapi::SECBUFFER_TOKEN,
                                   pvBuffer: self.enc_in.get_mut().as_mut_ptr() as *mut _,
                               },
                               winapi::SecBuffer {
                                   cbBuffer: 0,
                                   BufferType: winapi::SECBUFFER_EMPTY,
                                   pvBuffer: ptr::null_mut(),
                               }];
            let mut inbuf_desc = winapi::SecBufferDesc {
                ulVersion: winapi::SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: inbufs.as_mut_ptr(),
            };

            let outbufs = &mut [winapi::SecBuffer {
                                    cbBuffer: 0,
                                    BufferType: winapi::SECBUFFER_TOKEN,
                                    pvBuffer: ptr::null_mut(),
                                },
                                winapi::SecBuffer {
                                    cbBuffer: 0,
                                    BufferType: winapi::SECBUFFER_ALERT,
                                    pvBuffer: ptr::null_mut(),
                                }];
            let mut outbuf_desc = winapi::SecBufferDesc {
                ulVersion: winapi::SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: outbufs.as_mut_ptr(),
            };

            let mut attributes = 0;

            let status = secur32::InitializeSecurityContextW(&mut self.cred.0,
                                                             &mut self.context.0,
                                                             domain,
                                                             INIT_REQUESTS,
                                                             0,
                                                             0,
                                                             &mut inbuf_desc,
                                                             0,
                                                             ptr::null_mut(),
                                                             &mut outbuf_desc,
                                                             &mut attributes,
                                                             ptr::null_mut());

            if !outbufs[1].pvBuffer.is_null() {
                secur32::FreeContextBuffer(outbufs[1].pvBuffer);
            }

            match status {
                winapi::SEC_I_CONTINUE_NEEDED => {
                    let nread = if inbufs[1].BufferType == winapi::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - inbufs[1].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    let to_write = ContextBuffer(outbufs[0]);

                    self.consume_enc_in(nread);
                    self.needs_read = self.enc_in.position() == 0;
                    self.out_buf.get_mut().extend_from_slice(&to_write);
                }
                winapi::SEC_E_INCOMPLETE_MESSAGE => self.needs_read = true,
                winapi::SEC_E_OK => {
                    let nread = if inbufs[1].BufferType == winapi::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - inbufs[1].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    let to_write = if outbufs[0].pvBuffer.is_null() {
                        None
                    } else {
                        Some(ContextBuffer(outbufs[0]))
                    };

                    self.consume_enc_in(nread);
                    self.needs_read = self.enc_in.position() == 0;
                    if let Some(to_write) = to_write {
                        self.out_buf.get_mut().extend_from_slice(&to_write);
                    }
                    if self.enc_in.position() != 0 {
                        try!(self.decrypt());
                    }
                    if let State::Initializing { ref mut more_calls, .. } = self.state {
                        *more_calls = false;
                    }
                }
                _ => return Err(io::Error::from_raw_os_error(status as i32)),
            }
            Ok(())
        }
    }

    fn initialize(&mut self) -> io::Result<Option<winapi::SecPkgContext_StreamSizes>> {
        loop {
            match self.state {
                State::Initializing { mut needs_flush, more_calls, shutting_down } => {
                    if try!(self.write_out()) > 0 {
                        needs_flush = true;
                        if let State::Initializing { needs_flush: ref mut n, .. } = self.state {
                            *n = needs_flush;
                        }
                    }

                    if needs_flush {
                        try!(self.stream.flush());
                        if let State::Initializing { ref mut needs_flush, .. } = self.state {
                            *needs_flush = false;
                        }
                    }

                    if !more_calls {
                        self.state = if shutting_down {
                            State::Shutdown
                        } else {
                            State::Streaming {
                                sizes: try!(self.context.stream_sizes()),
                            }
                        };

                        continue;
                    }

                    if self.needs_read {
                        if try!(self.read_in()) == 0 {
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                                                      "unexpected EOF during handshake"));
                        }
                    }

                    try!(self.step_initialize());
                }
                State::Streaming { sizes } => {
                    try!(self.validate());
                    return Ok(Some(sizes));
                }
                State::Shutdown => return Ok(None),
            }
        }
    }

    fn validate(&mut self) -> io::Result<()> {
        let cert_context = try!(self.context.remote_cert());

        let cert_chain = unsafe {
            let cert_store = self.cert_store
                                 .as_ref()
                                 .map(|s| s.as_inner())
                                 .unwrap_or(ptr::null_mut());

            let flags = winapi::CERT_CHAIN_CACHE_END_CERT |
                        winapi::CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
                        winapi::CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

            let mut para: winapi::CERT_CHAIN_PARA = mem::zeroed();
            para.cbSize = mem::size_of_val(&para) as winapi::DWORD;
            para.RequestedUsage.dwType = winapi::USAGE_MATCH_TYPE_OR;

            let mut pkix_kp_server_auth = winapi::szOID_PKIX_KP_SERVER_AUTH.as_bytes().to_owned();
            pkix_kp_server_auth.push(0);
            let mut server_gated_crypto = winapi::szOID_SERVER_GATED_CRYPTO.as_bytes().to_owned();
            server_gated_crypto.push(0);
            let mut sgc_netscape = winapi::szOID_SGC_NETSCAPE.as_bytes().to_owned();
            sgc_netscape.push(0);
            let mut identifiers = [pkix_kp_server_auth.as_ptr() as winapi::LPSTR,
                                   server_gated_crypto.as_ptr() as winapi::LPSTR,
                                   sgc_netscape.as_ptr() as winapi::LPSTR];
            para.RequestedUsage.Usage.cUsageIdentifier = identifiers.len() as winapi::DWORD;
            para.RequestedUsage.Usage.rgpszUsageIdentifier = identifiers.as_mut_ptr();

            let mut cert_chain = mem::uninitialized();

            let res = crypt32::CertGetCertificateChain(ptr::null_mut(),
                                                       cert_context.0,
                                                       ptr::null_mut(),
                                                       cert_store,
                                                       &mut para,
                                                       flags,
                                                       ptr::null_mut(),
                                                       &mut cert_chain);

            if res == winapi::TRUE {
                CertChainContext(cert_chain)
            } else {
                return Err(io::Error::last_os_error());
            }
        };

        unsafe {
            let mut extra_para: winapi::SSL_EXTRA_CERT_CHAIN_POLICY_PARA = mem::zeroed();
            extra_para.cbSize = mem::size_of_val(&extra_para) as winapi::DWORD;
            extra_para.dwAuthType = winapi::AUTHTYPE_SERVER;
            if let Some(ref mut name) = self.domain {
                extra_para.pwszServerName = name.as_mut_ptr();
            }

            let mut para: winapi::CERT_CHAIN_POLICY_PARA = mem::zeroed();
            para.cbSize = mem::size_of_val(&para) as winapi::DWORD;
            para.dwFlags = winapi::CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
            para.pvExtraPolicyPara = &mut extra_para as *mut _ as *mut _;

            let mut status: winapi::CERT_CHAIN_POLICY_STATUS = mem::zeroed();
            status.cbSize = mem::size_of_val(&status) as winapi::DWORD;

            let res = crypt32::CertVerifyCertificateChainPolicy(winapi::CERT_CHAIN_POLICY_SSL as winapi::LPCSTR,
                                                                cert_chain.0,
                                                                &mut para,
                                                                &mut status);
            if res == winapi::FALSE {
                return Err(io::Error::last_os_error());
            }

            if status.dwError != winapi::ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status.dwError as i32));
            }
        }

        Ok(())
    }

    fn write_out(&mut self) -> io::Result<usize> {
        let mut out = 0;
        while self.out_buf.position() as usize != self.out_buf.get_ref().len() {
            let position = self.out_buf.position() as usize;
            let nwritten = try!(self.stream.write(&self.out_buf.get_ref()[position..]));
            out += nwritten;
            self.out_buf.set_position((position + nwritten) as u64);
        }

        Ok(out)
    }

    fn read_in(&mut self) -> io::Result<usize> {
        let existing_len = self.enc_in.position() as usize;
        let min_len = cmp::max(1024, 2 * existing_len);
        if self.enc_in.get_ref().len() < min_len {
            self.enc_in.get_mut().resize(min_len, 0);
        }
        let nread = {
            let buf = &mut self.enc_in.get_mut()[existing_len..];
            try!(self.stream.read(buf))
        };
        self.enc_in.set_position((existing_len + nread) as u64);
        Ok(nread)
    }

    fn consume_enc_in(&mut self, nread: usize) {
        unsafe {
            let src = &self.enc_in.get_ref()[nread] as *const _;
            let dst = self.enc_in.get_mut().as_mut_ptr();

            let size = self.enc_in.position() as usize;
            assert!(size >= nread);
            let count = size - nread;

            ptr::copy(src, dst, count);

            self.enc_in.set_position(count as u64);
        }
    }

    fn decrypt(&mut self) -> io::Result<()> {
        unsafe {
            let bufs = &mut [winapi::SecBuffer {
                                 cbBuffer: self.enc_in.position() as c_ulong,
                                 BufferType: winapi::SECBUFFER_DATA,
                                 pvBuffer: self.enc_in.get_mut().as_mut_ptr() as *mut _,
                             },
                             winapi::SecBuffer {
                                 cbBuffer: 0,
                                 BufferType: winapi::SECBUFFER_EMPTY,
                                 pvBuffer: ptr::null_mut(),
                             },
                             winapi::SecBuffer {
                                 cbBuffer: 0,
                                 BufferType: winapi::SECBUFFER_EMPTY,
                                 pvBuffer: ptr::null_mut(),
                             },
                             winapi::SecBuffer {
                                 cbBuffer: 0,
                                 BufferType: winapi::SECBUFFER_EMPTY,
                                 pvBuffer: ptr::null_mut(),
                             }];
            let mut bufdesc = winapi::SecBufferDesc {
                ulVersion: winapi::SECBUFFER_VERSION,
                cBuffers: 4,
                pBuffers: bufs.as_mut_ptr(),
            };

            match secur32::DecryptMessage(&mut self.context.0, &mut bufdesc, 0, ptr::null_mut()) {
                winapi::SEC_E_OK => {
                    let start = bufs[1].pvBuffer as usize - self.enc_in.get_ref().as_ptr() as usize;
                    let end = start + bufs[1].cbBuffer as usize;
                    self.dec_in.get_mut().clear();
                    self.dec_in
                        .get_mut()
                        .extend_from_slice(&self.enc_in.get_ref()[start..end]);
                    self.dec_in.set_position(0);

                    let nread = if bufs[3].BufferType == winapi::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - bufs[3].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    self.consume_enc_in(nread);
                    self.needs_read = self.enc_in.position() == 0;
                    Ok(())
                }
                winapi::SEC_E_INCOMPLETE_MESSAGE => {
                    self.needs_read = true;
                    Ok(())
                }
                state @ winapi::SEC_I_CONTEXT_EXPIRED |
                state @ winapi::SEC_I_RENEGOTIATE => {
                    self.state = State::Initializing {
                        needs_flush: false,
                        more_calls: true,
                        shutting_down: state == winapi::SEC_I_CONTEXT_EXPIRED,
                    };

                    let nread = if bufs[3].BufferType == winapi::SECBUFFER_EXTRA {
                        self.enc_in.position() as usize - bufs[3].cbBuffer as usize
                    } else {
                        self.enc_in.position() as usize
                    };
                    self.consume_enc_in(nread);
                    self.needs_read = self.enc_in.position() == 0;
                    Ok(())
                }
                e => Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
    }

    fn encrypt(&mut self, buf: &[u8], sizes: &winapi::SecPkgContext_StreamSizes) -> io::Result<()> {
        assert!(buf.len() <= sizes.cbMaximumMessage as usize);

        unsafe {
            let len = sizes.cbHeader as usize + buf.len() + sizes.cbTrailer as usize;

            if self.out_buf.get_ref().len() < len {
                self.out_buf.get_mut().resize(len, 0);
            }

            let message_start = sizes.cbHeader as usize;
            self.out_buf
                    .get_mut()[message_start..message_start + buf.len()]
                .clone_from_slice(buf);

            let buf_start = self.out_buf.get_mut().as_mut_ptr();
            let bufs =
                &mut [winapi::SecBuffer {
                          cbBuffer: sizes.cbHeader,
                          BufferType: winapi::SECBUFFER_STREAM_HEADER,
                          pvBuffer: buf_start as *mut _,
                      },
                      winapi::SecBuffer {
                          cbBuffer: buf.len() as c_ulong,
                          BufferType: winapi::SECBUFFER_DATA,
                          pvBuffer: buf_start.offset(sizes.cbHeader as isize) as *mut _,
                      },
                      winapi::SecBuffer {
                          cbBuffer: sizes.cbTrailer,
                          BufferType: winapi::SECBUFFER_STREAM_TRAILER,
                          pvBuffer:
                              buf_start.offset(sizes.cbHeader as isize +
                                      buf.len() as isize) as *mut _,
                      },
                      winapi::SecBuffer {
                          cbBuffer: 0,
                          BufferType: winapi::SECBUFFER_EMPTY,
                          pvBuffer: ptr::null_mut(),
                      }];
            let mut bufdesc = winapi::SecBufferDesc {
                ulVersion: winapi::SECBUFFER_VERSION,
                cBuffers: 4,
                pBuffers: bufs.as_mut_ptr(),
            };

            match secur32::EncryptMessage(&mut self.context.0, 0, &mut bufdesc, 0) {
                winapi::SEC_E_OK => {
                    let len = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
                    self.out_buf.get_mut().truncate(len as usize);
                    self.out_buf.set_position(0);
                    Ok(())
                }
                err => Err(io::Error::from_raw_os_error(err as i32)),
            }
        }
    }

    fn get_buf(&self) -> &[u8] {
        &self.dec_in.get_ref()[self.dec_in.position() as usize..]
    }
}

impl<S> Write for TlsStream<S>
    where S: Read + Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let sizes = match try!(self.initialize()) {
            Some(sizes) => sizes,
            None => return Err(io::Error::from_raw_os_error(winapi::SEC_E_CONTEXT_EXPIRED as i32)),
        };

        let len = cmp::min(buf.len(), sizes.cbMaximumMessage as usize);

        // if we have pending output data, it must have been because a previous
        // attempt to send this data ran into an error. Specifically in the
        // case of WouldBlock errors, we expect another call to write with the
        // same data.
        if self.out_buf.position() == self.out_buf.get_ref().len() as u64 {
            try!(self.encrypt(&buf[..len], &sizes));
        }
        try!(self.write_out());

        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S> Read for TlsStream<S>
    where S: Read + Write
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nread = {
            let read_buf = try!(self.fill_buf());
            let nread = cmp::min(buf.len(), read_buf.len());
            buf[..nread].clone_from_slice(&read_buf[..nread]);
            nread
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<S> BufRead for TlsStream<S>
    where S: Read + Write
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.get_buf().is_empty() {
            if let State::Shutdown = self.state {
                break;
            }

            if self.needs_read {
                if try!(self.read_in()) == 0 {
                    break;
                }
                self.needs_read = false;
            }

            try!(self.decrypt());
        }

        Ok(self.get_buf())
    }

    fn consume(&mut self, amt: usize) {
        let pos = self.dec_in.position() + amt as u64;
        assert!(pos <= self.dec_in.get_ref().len() as u64);
        self.dec_in.set_position(pos);
    }
}

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;
}
