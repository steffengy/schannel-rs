//! Schannel TLS streams.
use crypt32;
use secur32;
use libc;
use std::cmp;
use std::io::{self, Read, BufRead, Write, Cursor};
use std::ptr;
use std::mem;
use std::fmt;
use winapi;

use {INIT_REQUESTS, Inner};
use cert_store::CertStore;
use security_context::SecurityContext;
use context_buffer::ContextBuffer;
use schannel_cred::SchannelCred;

lazy_static! {
    static ref szOID_PKIX_KP_SERVER_AUTH: Vec<u8> =
        winapi::szOID_PKIX_KP_SERVER_AUTH.bytes().chain(Some(0)).collect();
    static ref szOID_SERVER_GATED_CRYPTO: Vec<u8> =
        winapi::szOID_SERVER_GATED_CRYPTO.bytes().chain(Some(0)).collect();
    static ref szOID_SGC_NETSCAPE: Vec<u8> =
        winapi::szOID_SGC_NETSCAPE.bytes().chain(Some(0)).collect();
}

struct CertChainContext(winapi::PCERT_CHAIN_CONTEXT);

impl Drop for CertChainContext {
    fn drop(&mut self) {
        unsafe {
            crypt32::CertFreeCertificateChain(self.0);
        }
    }
}

/// A builder type for `TlsStream`s.
#[derive(Default, Debug)]
pub struct Builder {
    domain: Option<Vec<u16>>,
    cert_store: Option<CertStore>,
}

impl Builder {
    /// Returns a new `Builder`.
    pub fn new() -> Builder {
        Builder::default()
    }

    /// Sets the domain associated with connections created with this `Builder`.
    ///
    /// The domain will be used for Server Name Indication as well as
    /// certificate validation.
    pub fn domain(&mut self, domain: &str) -> &mut Builder {
        self.domain = Some(domain.encode_utf16().chain(Some(0)).collect());
        self
    }

    #[allow(dead_code)]
    /* pub */ fn cert_store(&mut self, cert_store: CertStore) -> &mut Builder {
        self.cert_store = Some(cert_store);
        self
    }

    /// Initializes a new TLS session.
    pub fn initialize<S>(&self,
                         mut cred: SchannelCred,
                         stream: S)
                         -> Result<TlsStream<S>, HandshakeError<S>>
        where S: Read + Write
    {
        let domain = self.domain.as_ref().map(|s| &s[..]);
        let (ctxt, buf) = match SecurityContext::initialize(&mut cred, domain) {
            Ok(pair) => pair,
            Err(e) => return Err(HandshakeError::Failure(e)),
        };

        let stream = TlsStream {
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

        MidHandshakeTlsStream {
            inner: stream,
        }.handshake()
    }
}

enum State {
    Initializing {
        needs_flush: bool,
        more_calls: bool,
        shutting_down: bool,
    },
    Streaming { sizes: winapi::SecPkgContext_StreamSizes, },
    Shutdown,
}

/// An Schannel TLS stream.
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

/// A failure which can happen during the `Builder::initialize` phase, either an
/// I/O error or an intermediate stream which has not completed its handshake.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal I/O error occurred
    Failure(io::Error),
    /// The stream connection is in progress, but the handshake is not completed
    /// yet.
    Interrupted(MidHandshakeTlsStream<S>),
}

/// A stream which has not yet completed its handshake.
#[derive(Debug)]
pub struct MidHandshakeTlsStream<S> {
    inner: TlsStream<S>,
}

impl<S> fmt::Debug for TlsStream<S>
    where S: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S> TlsStream<S>
    where S: Read + Write
{
    /// Returns a reference to the wrapped stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Returns a reference to the buffer of pending data.
    ///
    /// Like `BufRead::fill_buf` except that it will return an empty slice
    /// rather than reading from the wrapped stream if there is no buffered
    /// data.
    pub fn get_buf(&self) -> &[u8] {
        &self.dec_in.get_ref()[self.dec_in.position() as usize..]
    }

    /// Shuts the TLS session down.
    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.state {
            State::Shutdown => return Ok(()),
            State::Initializing { shutting_down: true, .. } => {}
            _ => {
                unsafe {
                    let mut token = winapi::SCHANNEL_SHUTDOWN;
                    let mut buf = winapi::SecBuffer {
                        cbBuffer: mem::size_of_val(&token) as libc::c_ulong,
                        BufferType: winapi::SECBUFFER_TOKEN,
                        pvBuffer: &mut token as *mut _ as *mut _,
                    };
                    let mut desc = winapi::SecBufferDesc {
                        ulVersion: winapi::SECBUFFER_VERSION,
                        cBuffers: 1,
                        pBuffers: &mut buf,
                    };
                    match secur32::ApplyControlToken(self.context.get_mut(), &mut desc) {
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
                                   cbBuffer: self.enc_in.position() as libc::c_ulong,
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
                                },
                                winapi::SecBuffer {
                                    cbBuffer: 0,
                                    BufferType: winapi::SECBUFFER_EMPTY,
                                    pvBuffer: ptr::null_mut(),
                                }];
            let mut outbuf_desc = winapi::SecBufferDesc {
                ulVersion: winapi::SECBUFFER_VERSION,
                cBuffers: 3,
                pBuffers: outbufs.as_mut_ptr(),
            };

            let mut attributes = 0;

            let status = secur32::InitializeSecurityContextW(self.cred.get_mut(),
                                                             self.context.get_mut(),
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

            for buf in &outbufs[1..] {
                if !buf.pvBuffer.is_null() {
                    secur32::FreeContextBuffer(buf.pvBuffer);
                }
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
                        if let State::Initializing { ref mut needs_flush, .. } = self.state {
                            *needs_flush = true;
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
                            try!(self.validate());
                            State::Streaming { sizes: try!(self.context.stream_sizes()) }
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
                State::Streaming { sizes } => return Ok(Some(sizes)),
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

            let mut identifiers = [szOID_PKIX_KP_SERVER_AUTH.as_ptr() as winapi::LPSTR,
                                   szOID_SERVER_GATED_CRYPTO.as_ptr() as winapi::LPSTR,
                                   szOID_SGC_NETSCAPE.as_ptr() as winapi::LPSTR];
            para.RequestedUsage.Usage.cUsageIdentifier = identifiers.len() as winapi::DWORD;
            para.RequestedUsage.Usage.rgpszUsageIdentifier = identifiers.as_mut_ptr();

            let mut cert_chain = mem::uninitialized();

            let res = crypt32::CertGetCertificateChain(ptr::null_mut(),
                                                       cert_context.as_inner(),
                                                       ptr::null_mut(),
                                                       cert_store,
                                                       &mut para,
                                                       flags,
                                                       ptr::null_mut(),
                                                       &mut cert_chain);

            if res == winapi::TRUE {
                CertChainContext(cert_chain as *mut _)
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
        let size = self.enc_in.position() as usize;
        assert!(size >= nread);
        let count = size - nread;

        if count > 0 {
            unsafe {
                let src = &self.enc_in.get_ref()[nread] as *const _;
                let dst = self.enc_in.get_mut().as_mut_ptr();
    
                ptr::copy(src, dst, count);
            }
        }

        self.enc_in.set_position(count as u64);
    }

    fn decrypt(&mut self) -> io::Result<()> {
        unsafe {
            let bufs = &mut [winapi::SecBuffer {
                                 cbBuffer: self.enc_in.position() as libc::c_ulong,
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

            match secur32::DecryptMessage(self.context.get_mut(),
                                          &mut bufdesc,
                                          0,
                                          ptr::null_mut()) {
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
                          cbBuffer: buf.len() as libc::c_ulong,
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

            match secur32::EncryptMessage(self.context.get_mut(), 0, &mut bufdesc, 0) {
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
}

impl<S> MidHandshakeTlsStream<S>
    where S: Read + Write,
{
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut()
    }

    /// Restarts the handshake process.
    pub fn handshake(mut self) -> Result<TlsStream<S>, HandshakeError<S>> {
        match self.inner.initialize() {
            Ok(_) => Ok(self.inner),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(HandshakeError::Interrupted(self))
            }
            Err(e) => Err(HandshakeError::Failure(e)),
        }
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
            buf[..nread].copy_from_slice(&read_buf[..nread]);
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
            if let None = try!(self.initialize()) {
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
