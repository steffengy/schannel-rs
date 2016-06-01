use crypt32;
use std::io;
use std::mem;
use std::ptr;
use winapi;

use cert_context::CertContext;
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

impl CtlContext {
	pub fn builder() -> Builder {
		Builder {
			certificates: vec![],
			usages: vec![],
		}
	}
}

pub struct Builder {
	certificates: Vec<CertContext>,
	usages: Vec<Vec<u8>>,
}

impl Builder {
	pub fn certificate(&mut self, cert: CertContext) -> &mut Builder {
		self.certificates.push(cert);
		self
	}

	pub fn usage(&mut self, usage: &str) -> &mut Builder {
		let mut usage = usage.as_bytes().to_owned();
		usage.push(0);
		self.usages.push(usage);
		self
	}

	pub fn build(&self) -> io::Result<Vec<u8>> {
		unsafe {
			let encoding = winapi::X509_ASN_ENCODING | winapi::PKCS_7_ASN_ENCODING;

			let mut usages = self.usages.iter().map(|u| u.as_ptr()).collect::<Vec<_>>();
			let mut entry_data = vec![];
			let mut entries = vec![];
			for certificate in &self.certificates {
				let data = try!(cert_entry(certificate));
				entries.push(*(data.as_ptr() as *const winapi::CTL_ENTRY));
				entry_data.push(data);
			}

			let mut ctl_info: winapi::CTL_INFO = mem::zeroed();
			ctl_info.dwVersion = winapi::CTL_V1;
			ctl_info.SubjectUsage.cUsageIdentifier = usages.len() as winapi::DWORD;
			ctl_info.SubjectUsage.rgpszUsageIdentifier = usages.as_mut_ptr() as *mut winapi::LPSTR;
			let mut algorithm = winapi::szOID_OIWSEC_sha1.as_bytes().to_owned();
			algorithm.push(0);
			ctl_info.SubjectAlgorithm.pszObjId = algorithm.as_ptr() as winapi::LPSTR;
			ctl_info.cCTLEntry = entries.len() as winapi::DWORD;
			ctl_info.rgCTLEntry = entries.as_mut_ptr();

			let mut sign_info: winapi::CMSG_SIGNED_ENCODE_INFO = mem::zeroed();
			sign_info.cbSize = mem::size_of_val(&sign_info) as winapi::DWORD;
			let mut encoded_certs = self.certificates
										.iter()
										.map(|c| {
											winapi::CERT_BLOB {
												cbData: (*c.as_inner()).cbCertEncoded,
												pbData: (*c.as_inner()).pbCertEncoded,
											}
										})
										.collect::<Vec<_>>();
			sign_info.rgCertEncoded = encoded_certs.as_mut_ptr();
			sign_info.cCertEncoded = encoded_certs.len() as winapi::DWORD;

			let flags = winapi::CMSG_ENCODE_SORTED_CTL_FLAG |
				winapi::CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG;

			let mut size = 0;

			let res = crypt32::CryptMsgEncodeAndSignCTL(
				encoding,
				&mut ctl_info,
				&mut sign_info,
				flags,
				ptr::null_mut(),
				&mut size);
			if res == winapi::FALSE {
				return Err(io::Error::last_os_error());
			}

			let mut encoded = vec![0; size as usize];

			let res = crypt32::CryptMsgEncodeAndSignCTL(
				encoding,
				&mut ctl_info,
				&mut sign_info,
				flags,
				encoded.as_mut_ptr() as *mut winapi::BYTE,
				&mut size);
			if res == winapi::FALSE {
				return Err(io::Error::last_os_error());
			}

			Ok(encoded)
		}
	}
}

fn cert_entry(cert: &CertContext) -> io::Result<Vec<u8>> {
	unsafe {
		let mut size = 0;

		let res = crypt32::CertCreateCTLEntryFromCertificateContextProperties(
			cert.as_inner(),
			0,
			ptr::null_mut(),
			winapi::CTL_ENTRY_FROM_PROP_CHAIN_FLAG,
			ptr::null_mut(),
			ptr::null_mut(),
			&mut size);
		if res == winapi::FALSE {
			return Err(io::Error::last_os_error());
		}

		let mut entry = vec![0; size as usize];
		let res = crypt32::CertCreateCTLEntryFromCertificateContextProperties(
			cert.as_inner(),
			0,
			ptr::null_mut(),
			winapi::CTL_ENTRY_FROM_PROP_CHAIN_FLAG,
			ptr::null_mut(),
			entry.as_mut_ptr() as winapi::PCTL_ENTRY,
			&mut size);
		if res == winapi::FALSE {
			Err(io::Error::last_os_error())
		} else {
			Ok(entry)
		}
	}
}

#[cfg(test)]
mod test {
	use std::io::Read;
	use std::fs::File;
	use cert_store::CertStore;
	use ctl_context::CtlContext;

	#[test]
	fn create_ctl() {
        let mut file = File::open(concat!(env!("CARGO_MANIFEST_DIR"),
                                          "/test/self-signed.badssl.com.cer"))
                           .unwrap();
        let mut cert = vec![];
        file.read_to_end(&mut cert).unwrap();

        let mut store = CertStore::memory().unwrap();
        let cert = store.add_der_certificate(&cert).unwrap();

        CtlContext::builder()
        	.certificate(cert)
            .usage("1.3.6.1.4.1.311.2.2.2")
            .build()
            .unwrap();
	}
}