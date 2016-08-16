//! Bindings to winapi's `PCCERT_CONTEXT` APIs.

use std::ffi::OsString;
use std::io;
use std::mem;
use std::os::windows::prelude::*;
use std::ptr;

use crypt32;
use winapi;

use Inner;

/// Wrapper of a winapi certificate, or a `PCCERT_CONTEXT`.
#[derive(Debug)]
pub struct CertContext(winapi::PCCERT_CONTEXT);

unsafe impl Sync for CertContext {}
unsafe impl Send for CertContext {}

impl CertContext {
    /// Creates a new certificate from the encoded form.
    ///
    /// For example a DER-encoded certificate can be passed in to create a
    /// `CertContext`.
    pub fn new(data: &[u8]) -> io::Result<CertContext> {
        let ret = unsafe {
            crypt32::CertCreateCertificateContext(
                winapi::X509_ASN_ENCODING |
                winapi::PKCS_7_ASN_ENCODING,
                data.as_ptr(),
                data.len() as winapi::DWORD)
        };
        if ret.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(CertContext(ret))
        }
    }

    /// Returns the sha1 hash of this certificate
    ///
    /// The sha1 is returned as a 20-byte array representing the bits of the
    /// sha1 hash.
    pub fn sha1(&self) -> io::Result<[u8; 20]> {
        unsafe {
            let mut buf = [0; 20];
            let mut len = buf.len() as winapi::DWORD;
            let ret = crypt32::CertGetCertificateContextProperty(
                        self.0,
                        winapi::CERT_SHA1_HASH_PROP_ID,
                        buf.as_mut_ptr() as *mut winapi::c_void,
                        &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error())
            }
            Ok(buf)
        }
    }

    /// Returns the `<SIGNATURE>/<HASH>` string representing the certificate
    /// signature.
    ///
    /// The `<SIGNATURE>` value identifies the CNG public key
    /// algorithm. The `<HASH>` value identifies the CNG hash algorithm.
    ///
    /// Common examples are:
    ///
    /// * `RSA/SHA1`
    /// * `RSA/SHA256`
    /// * `ECDSA/SHA256`
    pub fn sign_hash_algorithms(&self) -> io::Result<String> {
        self.get_string(winapi::CERT_SIGN_HASH_CNG_ALG_PROP_ID)
    }

    /// Returns the signature hash.
    pub fn signature_hash(&self) -> io::Result<Vec<u8>> {
        self.get_bytes(winapi::CERT_SIGNATURE_HASH_PROP_ID)
    }

    /// Returns the property displayed by the certificate UI. This property
    /// allows the user to describe the certificate's use.
    pub fn description(&self) -> io::Result<Vec<u8>> {
        self.get_bytes(winapi::CERT_DESCRIPTION_PROP_ID)
    }

    /// Returns a string that contains the display name for the certificate.
    pub fn friendly_name(&self) -> io::Result<String> {
        self.get_string(winapi::CERT_FRIENDLY_NAME_PROP_ID)
    }

    /// Configures the string that contains the display name for this
    /// certificate.
    pub fn set_friendly_name(&self, name: &str) -> io::Result<()> {
        self.set_string(winapi::CERT_FRIENDLY_NAME_PROP_ID, name)
    }

    /// Verifies the time validity of this certificate relative to the system's
    /// current time.
    pub fn is_time_valid(&self) -> io::Result<bool> {
        let ret = unsafe {
            crypt32::CertVerifyTimeValidity(ptr::null_mut(), (*self.0).pCertInfo)
        };
        Ok(ret == 0)
    }

    /// Deletes this certificate from its certificate store.
    pub fn delete(self) -> io::Result<()> {
        unsafe {
            let ret = crypt32::CertDeleteCertificateFromStore(self.0);
            mem::forget(self);
            if ret == winapi::TRUE {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    fn get_bytes(&self, prop: winapi::DWORD) -> io::Result<Vec<u8>> {
        unsafe {
            let mut len = 0;
            let ret = crypt32::CertGetCertificateContextProperty(
                        self.0,
                        prop,
                        ptr::null_mut(),
                        &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error())
            }

            let mut buf = vec![0u8; len as usize];
            let ret = crypt32::CertGetCertificateContextProperty(
                        self.0,
                        prop,
                        buf.as_mut_ptr() as *mut winapi::c_void,
                        &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error())
            }
            Ok(buf)
        }
    }

    fn get_string(&self, prop: winapi::DWORD) -> io::Result<String> {
        unsafe {
            let mut len = 0;
            let ret = crypt32::CertGetCertificateContextProperty(
                        self.0,
                        prop,
                        ptr::null_mut(),
                        &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error())
            }

            // Divide by 2 b/c `len` is the byte length, but we're allocating
            // u16 pairs which are 2 bytes each.
            let amt = (len / 2) as usize;
            let mut buf = vec![0u16; amt];
            let ret = crypt32::CertGetCertificateContextProperty(
                        self.0,
                        prop,
                        buf.as_mut_ptr() as *mut winapi::c_void,
                        &mut len);
            if ret != winapi::TRUE {
                return Err(io::Error::last_os_error())
            }

            // Chop off the trailing nul byte
            Ok(OsString::from_wide(&buf[..amt - 1]).into_string().unwrap())
        }
    }

    fn set_string(&self, prop: winapi::DWORD, s: &str) -> io::Result<()> {
        unsafe {
            let data = s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let data = winapi::CRYPT_DATA_BLOB {
                cbData: (data.len() * 2) as winapi::DWORD,
                pbData: data.as_ptr() as *mut _,
            };
            let ret = crypt32::CertSetCertificateContextProperty(
                        self.0,
                        prop,
                        0,
                        &data as *const _ as *const _);
            if ret != winapi::TRUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

impl Clone for CertContext {
    fn clone(&self) -> CertContext {
        unsafe {
            CertContext(crypt32::CertDuplicateCertificateContext(self.0))
        }
    }
}

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

    fn get_mut(&mut self) -> &mut winapi::PCCERT_CONTEXT {
        &mut self.0
    }
}
