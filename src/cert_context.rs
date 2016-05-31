use crypt32;
use winapi;

use Inner;

pub struct CertContext(winapi::PCCERT_CONTEXT);

impl Drop for CertContext {
	fn drop(&mut self) {
		unsafe {
			crypt32::CertFreeCertificateContext(self.0);
		}
	}
}

impl Inner<winapi::PCCERT_CONTEXT> for CertContext {
	unsafe fn from_inner(t: winapi::PCCERT_CONTEXT) -> CertContext {
		CertContext(t)
	}

	fn as_inner(&self) -> winapi::PCCERT_CONTEXT {
		self.0
	}
}