extern crate libc;
extern crate secur32;
extern crate winapi;

use libc::c_ulong;
use secur32::{AcquireCredentialsHandleA, FreeCredentialsHandle, InitializeSecurityContextW,
              DeleteSecurityContext, FreeContextBuffer, QueryContextAttributesW, DecryptMessage};
use std::cmp;
use std::error;
use std::fmt;
use std::io::{self, Read, Write, Cursor};
use std::mem;
use std::ops::{Deref, Range};
use std::ptr;
use std::result;
use std::slice;
use winapi::{CredHandle, SECURITY_STATUS, SCHANNEL_CRED, SCHANNEL_CRED_VERSION, UNISP_NAME,
             SECPKG_CRED_OUTBOUND, SECPKG_CRED_INBOUND, SEC_E_OK, CtxtHandle,
             ISC_REQ_CONFIDENTIALITY, ISC_REQ_INTEGRITY, ISC_REQ_REPLAY_DETECT,
             ISC_REQ_SEQUENCE_DETECT, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_STREAM, SecBuffer,
             SECBUFFER_EMPTY, SECBUFFER_TOKEN, SecBufferDesc, SECBUFFER_VERSION,
             SEC_I_CONTINUE_NEEDED, SecPkgContext_StreamSizes, SECPKG_ATTR_STREAM_SIZES,
             SECBUFFER_ALERT, SECBUFFER_EXTRA, SEC_E_INCOMPLETE_MESSAGE, SECBUFFER_DATA};

const INIT_REQUESTS: c_ulong = ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_INTEGRITY | 
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_STREAM;

pub type Result<T> = result::Result<T, Error>;

pub struct Error(SECURITY_STATUS);

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_tuple("Error")
           .field(&format_args!("{:#x}", self.0))
           .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            n => write!(fmt, "unknown error {:#x}", n)
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "an SChannel error"
    }
}

pub enum Direction {
    Inbound,
    Outbound,
}

pub struct SchannelCredBuilder(());

impl SchannelCredBuilder {
    pub fn new() -> SchannelCredBuilder {
        SchannelCredBuilder(())
    }

    pub fn acquire(&self, direction: Direction) -> Result<SchannelCred> {
        unsafe {
            let mut handle = mem::uninitialized();
            let mut cred_data: SCHANNEL_CRED = mem::zeroed();
            cred_data.dwVersion = SCHANNEL_CRED_VERSION;

            let direction = match direction {
                Direction::Inbound => SECPKG_CRED_INBOUND,
                Direction::Outbound => SECPKG_CRED_OUTBOUND,
            };

            let status = AcquireCredentialsHandleA(ptr::null_mut(),
                                                   UNISP_NAME.as_ptr() as *mut _,
                                                   direction,
                                                   ptr::null_mut(),
                                                   &mut cred_data as *mut _ as *mut _,
                                                   None,
                                                   ptr::null_mut(),
                                                   &mut handle,
                                                   ptr::null_mut());

            if status == SEC_E_OK {
                Ok(SchannelCred(handle))
            } else {
                Err(Error(status))
            }
        }
    }
}

pub struct SchannelCred(CredHandle);

impl Drop for SchannelCred {
    fn drop(&mut self) {
        unsafe { FreeCredentialsHandle(&mut self.0); }
    }
}

#[derive(Default)]
pub struct TlsStreamBuilder {
    domain: Option<Vec<u16>>,
}

impl TlsStreamBuilder {
    pub fn new() -> TlsStreamBuilder {
        TlsStreamBuilder::default()
    }

    pub fn domain(&mut self, domain: &str) -> &mut TlsStreamBuilder {
        self.domain = Some(domain.encode_utf16().chain(Some(0)).collect());
        self
    }

    pub fn initialize<S>(&self, cred: SchannelCred, stream: S) -> io::Result<TlsStream<S>>
        where S: Read + Write
    {
        let (ctxt, buf) = try!(SecurityContext::initialize(&cred,
                                                           self.domain.as_ref().map(|s| &s[..]))
                                   .map_err(|e| io::Error::new(io::ErrorKind::Other, e)));

        let mut stream = TlsStream {
            cred: cred,
            context: ctxt,
            domain: self.domain.clone(),
            stream: stream,
            state: State::Initializing,
            plaintext_in_buf: Cursor::new(Vec::new()),
            encrypted_in_buf: Cursor::new(Vec::new()),
            out_buf: Cursor::new(buf.to_owned()),
        };
        try!(stream.initialize());

        Ok(stream)
    }
}

enum InitializeResponse {
    ContinueNeeded(usize, ContextBuffer),
    IncompleteMessage,
    Ok(usize, Option<ContextBuffer>),
}

enum DecryptResponse {
    Ok {
        nread: usize,
        decrypted: Range<usize>,
    },
    IncompleteMessage,
    // Renegotiate,
}

struct SecurityContext(CtxtHandle);

impl SecurityContext {
    fn initialize(cred: &SchannelCred,
                  domain: Option<&[u16]>)
                  -> Result<(SecurityContext, ContextBuffer)> {
        unsafe {
            let domain = domain.map(|b| b.as_ptr() as *mut u16).unwrap_or(ptr::null_mut());

            let mut ctxt = mem::uninitialized();

            let mut outbuf = SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_EMPTY,
                pvBuffer: ptr::null_mut(),
            };
            let mut outbuf_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 1,
                pBuffers: &mut outbuf,
            };

            let mut attributes = 0;

            let status = InitializeSecurityContextW(&cred.0 as *const _ as *mut _,
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
                                                    ptr::null_mut());
            if status != SEC_I_CONTINUE_NEEDED {
                return Err(Error(status));
            }

            Ok((SecurityContext(ctxt), ContextBuffer(outbuf)))
        }
    }

    fn continue_initialize(&mut self,
                            cred: &SchannelCred,
                            domain: Option<&[u16]>,
                            buf: &mut [u8])
                            -> Result<InitializeResponse> {
        unsafe {
            let domain = domain.map(|b| b.as_ptr() as *mut u16).unwrap_or(ptr::null_mut());

            let inbufs = &mut [SecBuffer {
                                   cbBuffer: buf.len() as c_ulong,
                                   BufferType: SECBUFFER_TOKEN,
                                   pvBuffer: buf.as_mut_ptr() as *mut _,
                               },
                               SecBuffer {
                                   cbBuffer: 0,
                                   BufferType: SECBUFFER_EMPTY,
                                   pvBuffer: ptr::null_mut(),
                               }];
            let mut inbuf_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: inbufs.as_mut_ptr(),
            };

            let outbufs = &mut [SecBuffer {
                                    cbBuffer: 0,
                                    BufferType: SECBUFFER_TOKEN,
                                    pvBuffer: ptr::null_mut(),
                                },
                                SecBuffer {
                                    cbBuffer: 0,
                                    BufferType: SECBUFFER_ALERT,
                                    pvBuffer: ptr::null_mut(),
                                }];
            let mut outbuf_desc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 2,
                pBuffers: outbufs.as_mut_ptr(),
            };

            let mut attributes = 0;

            let status = InitializeSecurityContextW(&cred.0 as *const _ as *mut _,
                                                    &mut self.0,
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
                FreeContextBuffer(outbufs[1].pvBuffer);
            }

            match status {
                SEC_I_CONTINUE_NEEDED => {
                    let nread = if inbufs[1].BufferType == SECBUFFER_EXTRA  {
                        buf.len() - inbufs[1].cbBuffer as usize
                    } else {
                        buf.len()
                    };
                    let to_write = ContextBuffer(outbufs[0]);
                    Ok(InitializeResponse::ContinueNeeded(nread, to_write))
                }
                SEC_E_INCOMPLETE_MESSAGE => Ok(InitializeResponse::IncompleteMessage),
                SEC_E_OK => {
                    let nread = if inbufs[1].BufferType == SECBUFFER_EXTRA  {
                        buf.len() - inbufs[1].cbBuffer as usize
                    } else {
                        buf.len()
                    };
                    let to_write = if outbufs[0].pvBuffer.is_null() {
                        None
                    } else {
                        Some(ContextBuffer(outbufs[0]))
                    };
                    Ok(InitializeResponse::Ok(nread, to_write))
                }
                _ => Err(Error(status))
            }
        }
    }

    fn stream_sizes(&mut self) -> Result<SecPkgContext_StreamSizes> {
        unsafe {
            let mut stream_sizes = mem::uninitialized();
            let status = QueryContextAttributesW(&mut self.0,
                                                 SECPKG_ATTR_STREAM_SIZES,
                                                 &mut stream_sizes as *mut _ as *mut _);
            if status == SEC_E_OK {
                Ok(stream_sizes)
            } else {
                Err(Error(status))
            }
        }
    }

    fn decrypt(&mut self, buf: &mut [u8]) -> Result<DecryptResponse> {
        unsafe {
            let bufs = &mut [SecBuffer {
                                 cbBuffer: buf.len() as c_ulong,
                                 BufferType: SECBUFFER_DATA,
                                 pvBuffer: buf.as_mut_ptr() as *mut _,
                             },
                             SecBuffer {
                                cbBuffer: 0,
                                BufferType: SECBUFFER_EMPTY,
                                pvBuffer: ptr::null_mut(),
                             },
                             SecBuffer {
                                cbBuffer: 0,
                                BufferType: SECBUFFER_EMPTY,
                                pvBuffer: ptr::null_mut(),
                             },
                             SecBuffer {
                                cbBuffer: 0,
                                BufferType: SECBUFFER_EMPTY,
                                pvBuffer: ptr::null_mut(),
                             },
                             SecBuffer {
                                cbBuffer: 0,
                                BufferType: SECBUFFER_EMPTY,
                                pvBuffer: ptr::null_mut(),
                             }];
            let mut bufdesc = SecBufferDesc {
                ulVersion: SECBUFFER_VERSION,
                cBuffers: 5,
                pBuffers: bufs.as_mut_ptr(),
            };

            match DecryptMessage(&mut self.0, &mut bufdesc, 0, ptr::null_mut()) {
                SEC_E_OK => {
                    let nread = if bufs[3].BufferType == SECBUFFER_EXTRA {
                        buf.len() - bufs[3].cbBuffer as usize
                    } else {
                        buf.len()
                    };
                    let start = bufs[1].pvBuffer as usize - buf.as_ptr() as usize;
                    let end = start + bufs[1].cbBuffer as usize;
                    Ok(DecryptResponse::Ok {
                        nread: nread,
                        decrypted: start..end,
                    })
                }
                SEC_E_INCOMPLETE_MESSAGE => Ok(DecryptResponse::IncompleteMessage),
                e => Err(Error(e)),
            }
        }
    }
}

impl Drop for SecurityContext {
    fn drop(&mut self) {
        unsafe { DeleteSecurityContext(&mut self.0); }
    }
}

struct ContextBuffer(SecBuffer);

impl Drop for ContextBuffer {
    fn drop(&mut self) {
        unsafe { FreeContextBuffer(self.0.pvBuffer); }
    }
}

impl Deref for ContextBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.0.pvBuffer as *const _, self.0.cbBuffer as usize) }
    }
}

enum State {
    Initializing,
    Streaming,
}

pub struct TlsStream<S> {
    cred: SchannelCred,
    context: SecurityContext,
    domain: Option<Vec<u16>>,
    stream: S,
    state: State,
    plaintext_in_buf: Cursor<Vec<u8>>,
    encrypted_in_buf: Cursor<Vec<u8>>,
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

    fn initialize(&mut self) -> io::Result<()> {
        let mut needs_read = true;

        while let State::Initializing = self.state {
            if try!(self.write_out()) > 0 {
                try!(self.stream.flush());
            }

            if needs_read {
                if try!(self.read_in()) == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                                              "unexpected EOF during handshake"));
                }
            }

            let end = self.encrypted_in_buf.position() as usize;
            match self.context.continue_initialize(&self.cred,
                                                   self.domain.as_ref().map(|d| &d[..]),
                                                   &mut self.encrypted_in_buf.get_mut()[..end]) {
                Ok(InitializeResponse::ContinueNeeded(nread, buf)) => {
                    self.consume_encrypted_in(nread);
                    self.out_buf.get_mut().extend_from_slice(&buf);
                    needs_read = self.encrypted_in_buf.get_ref().len() == 0;
                }
                Ok(InitializeResponse::Ok(nread, buf)) => {
                    self.consume_encrypted_in(nread);
                    if let Some(buf) = buf {
                        self.out_buf.get_mut().extend_from_slice(&buf);
                    }
                    if self.encrypted_in_buf.position() != 0 {
                        try!(self.decrypt().map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
                    }
                    self.state = State::Streaming;
                }
                Ok(InitializeResponse::IncompleteMessage) => needs_read = true,
                Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
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

        self.out_buf.set_position(0);
        self.out_buf.get_mut().clear();

        Ok(out)
    }

    fn read_in(&mut self) -> io::Result<usize> {
        let existing_len = self.encrypted_in_buf.position() as usize;
        let min_len = cmp::max(1024, 2 * existing_len);
        if self.encrypted_in_buf.get_ref().len() < min_len {
            self.encrypted_in_buf.get_mut().resize(min_len, 0);
        }
        let nread = {
            let buf = &mut self.encrypted_in_buf.get_mut()[existing_len..];
            try!(self.stream.read(buf))
        };
        self.encrypted_in_buf.set_position((existing_len + nread) as u64);
        Ok(nread)
    }

    fn consume_encrypted_in(&mut self, nread: usize) {
        unsafe {
            let src = &self.encrypted_in_buf.get_ref()[nread] as *const _;
            let dst = self.encrypted_in_buf.get_mut().as_mut_ptr();

            let size = self.encrypted_in_buf.position() as usize;
            assert!(size >= nread);
            let count = size - nread;

            ptr::copy(src, dst, count);

            self.encrypted_in_buf.set_position(count as u64);
        }
    }

    fn decrypt(&mut self) -> Result<()> {
        match try!(self.context.decrypt(self.encrypted_in_buf.get_mut())) {
            DecryptResponse::Ok { nread, decrypted } => {
                self.plaintext_in_buf.get_mut().extend_from_slice(&self.encrypted_in_buf.get_ref()[decrypted]);
                self.consume_encrypted_in(nread);
            }
            DecryptResponse::IncompleteMessage => {}
        }

        Ok(())
    }
}

impl<S> Write for TlsStream<S>
    where S: Read + Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.initialize());
        unimplemented!();
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S> Read for TlsStream<S>
    where S: Read + Write
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.plaintext_in_buf.position() as usize != self.plaintext_in_buf.get_ref().len() {
            return self.plaintext_in_buf.read(buf);
        }

        try!(self.initialize());

        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use std::net::TcpStream;

    use super::*;

    #[test]
    fn basic() {
        let creds = SchannelCredBuilder::new().acquire(Direction::Outbound).unwrap();
        let stream = TcpStream::connect("google.com:443").unwrap();
        let stream = TlsStreamBuilder::new()
                         .domain("google.com")
                         .initialize(creds, stream)
                         .unwrap();
    }
}