extern crate libc;
extern crate secur32;
extern crate winapi;

use libc::c_ulong;
use secur32::{AcquireCredentialsHandleA, FreeCredentialsHandle, InitializeSecurityContextW,
              DeleteSecurityContext, FreeContextBuffer};
use std::error;
use std::fmt;
use std::io;
use std::mem;
use std::ptr;
use std::result;
use std::slice;
use winapi::{CredHandle, SECURITY_STATUS, SCHANNEL_CRED, SCHANNEL_CRED_VERSION, UNISP_NAME,
             SECPKG_CRED_OUTBOUND, SECPKG_CRED_INBOUND, SEC_E_OK, CtxtHandle,
             ISC_REQ_CONFIDENTIALITY, ISC_REQ_INTEGRITY, ISC_REQ_REPLAY_DETECT,
             ISC_REQ_SEQUENCE_DETECT, ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_STREAM, SecBuffer,
             SECBUFFER_EMPTY, SECBUFFER_TOKEN, SecBufferDesc, SECBUFFER_VERSION,
             SEC_I_CONTINUE_NEEDED};

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

    pub fn initialize<S>(&self, cred: &SchannelCred, mut stream: S) -> io::Result<TlsStream<S>>
        where S: io::Read + io::Write
    {
        let domain = self.domain.as_ref().map(|d| &d[..]);
        let (ctxt, buf) = try!(SecurityContext::initialize_new(cred, domain)
                                   .map_err(|e| io::Error::new(io::ErrorKind::Other, e)));

        unsafe {
            let buf = slice::from_raw_parts(buf.0.pvBuffer as *const _, buf.0.cbBuffer as usize);
            try!(stream.write_all(buf));
        }
        try!(stream.flush());

        panic!();
    }
}

struct SecurityContext(CtxtHandle);

impl SecurityContext {
    fn initialize_new(cred: &SchannelCred,
                      domain: Option<&[u16]>)
                      -> Result<(SecurityContext, ContextBuffer)> {
        unsafe {
            let domain = domain.map(|b| b.as_ptr() as *mut u16).unwrap_or(ptr::null_mut());

            let requests = ISC_REQ_CONFIDENTIALITY |
                ISC_REQ_INTEGRITY | 
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_ALLOCATE_MEMORY |
                ISC_REQ_STREAM;

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
                                                    requests,
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

pub struct TlsStream<S> {
    stream: S,
    context: SecurityContext,
}

impl<S> TlsStream<S>
    where S: io::Read + io::Write
{
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
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
                         .initialize(&creds, stream)
                         .unwrap();
    }
}