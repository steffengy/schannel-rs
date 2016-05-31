use crypt32;
use winapi;

use Inner;

pub struct CtlContext(winapi::PCCTL_CONTEXT);

impl Drop for CtlContext {
	fn drop(&mut self) {
		unsafe {
			crypt32::CertFreeCTLContext(self.0);
		}
	}
}

impl Inner<winapi::PCCTL_CONTEXT> for CtlContext {
	unsafe fn from_inner(t: winapi::PCCTL_CONTEXT) -> CtlContext {
		CtlContext(t)
	}

	fn as_inner(&self) -> winapi::PCCTL_CONTEXT {
		self.0
	}
}