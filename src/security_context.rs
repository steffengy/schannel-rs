use winapi;
use secur32;
use std::mem;
use std::ptr;
use std::io;

use {INIT_REQUESTS, Inner};
use cert_context::CertContext;
use context_buffer::ContextBuffer;

use schannel_cred::SchannelCred;

pub struct SecurityContext(winapi::CtxtHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        unsafe {
            secur32::DeleteSecurityContext(&mut self.0);
        }
    }
}

impl Inner<winapi::CtxtHandle> for SecurityContext {
	unsafe fn from_inner(inner: winapi::CtxtHandle) -> SecurityContext {
		SecurityContext(inner)
	}

	fn as_inner(&self) -> winapi::CtxtHandle {
		self.0
	}

	fn get_mut(&mut self) -> &mut winapi::CtxtHandle {
		&mut self.0
	}
}

impl SecurityContext {
    pub fn initialize(cred: &mut SchannelCred,
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

            match secur32::InitializeSecurityContextW(cred.get_mut(),
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

    pub fn stream_sizes(&mut self) -> io::Result<winapi::SecPkgContext_StreamSizes> {
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

    pub fn remote_cert(&mut self) -> io::Result<CertContext> {
        unsafe {
            let mut cert_context = mem::uninitialized();
            let status = secur32::QueryContextAttributesW(&mut self.0,
                                                          winapi::SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                                          &mut cert_context as *mut _ as *mut _);
            if status == winapi::SEC_E_OK {
                Ok(CertContext::from_inner(cert_context))
            } else {
                Err(io::Error::from_raw_os_error(status as i32))
            }
        }
    }
}
