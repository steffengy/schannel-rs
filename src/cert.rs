use crypt32;
use std::io;
use std::ptr;
use winapi;

pub struct CertStore(winapi::HCERTSTORE);

impl Drop for CertStore {
	fn drop(&mut self) {
		unsafe {
			crypt32::CertCloseStore(self.0, 0);
		}
	}
}

impl CertStore {
	pub fn memory() -> io::Result<Memory> {
		unsafe {
			let store = crypt32::CertOpenStore(winapi::CERT_STORE_PROV_MEMORY as winapi::LPCSTR,
											   0,
											   0,
											   0,
											   ptr::null_mut());
			if store.is_null() {
				Err(io::Error::last_os_error())
			} else {
				Ok(Memory(CertStore(store)))
			}
		}
	}
}

pub struct Memory(CertStore);

impl Memory {
	pub fn add_certificate(&mut self, cert: &[u8]) -> io::Result<CertContext> {
		unsafe {
			let mut cert_context = ptr::null();

			let res = crypt32::CertAddEncodedCertificateToStore(
				(self.0).0,
				winapi::X509_ASN_ENCODING | winapi::PKCS_7_ASN_ENCODING,
				cert.as_ptr() as *const _,
				cert.len() as winapi::DWORD,
				winapi::CERT_STORE_ADD_ALWAYS,
				&mut cert_context);
			if res == winapi::TRUE {
				Ok(CertContext(cert_context))
			} else {
				Err(io::Error::last_os_error())
			}
		}
	}
}

pub struct CertContext(winapi::PCCERT_CONTEXT);

impl Drop for CertContext {
	fn drop(&mut self) {
		unsafe {
			crypt32::CertFreeCertificateContext(self.0);
		}
	}
}

#[cfg(test)]
mod test {
	use std::fs::File;
	use std::io::Read;

	use super::*;

	#[test]
	fn load() {
		let mut file = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/test/cert.der"))
				           .unwrap();
		let mut cert = vec![];
		file.read_to_end(&mut cert).unwrap();

		let mut store = CertStore::memory().unwrap();
		store.add_certificate(&cert).unwrap();
	}
}