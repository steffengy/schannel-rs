//! Bindings to winapi's certificate-store related APIs.

use crypt32;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::mem;
use std::os::windows::prelude::*;
use std::ptr;
use winapi;

use cert_context::CertContext;
use ctl_context::CtlContext;

use Inner;

/// Representation of certificate store on Windows, wrapping a `HCERTSTORE`.
pub struct CertStore(winapi::HCERTSTORE);

unsafe impl Sync for CertStore {}
unsafe impl Send for CertStore {}

impl fmt::Debug for CertStore {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		fmt.debug_struct("CertStore").finish()
	}
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe {
            crypt32::CertCloseStore(self.0, 0);
        }
    }
}

impl Clone for CertStore {
    fn clone(&self) -> CertStore {
        unsafe { CertStore(crypt32::CertDuplicateStore(self.0)) }
    }
}

impl Inner<winapi::HCERTSTORE> for CertStore {
    unsafe fn from_inner(t: winapi::HCERTSTORE) -> CertStore {
        CertStore(t)
    }

    fn as_inner(&self) -> winapi::HCERTSTORE {
        self.0
    }

    fn get_mut(&mut self) -> &mut winapi::HCERTSTORE {
        &mut self.0
    }
}

/// Argument to the `add_cert` function indicating how a certificate should be
/// added to a `CertStore`.
pub enum CertAdd {
    /// The function makes no check for an existing matching certificate or link
    /// to a matching certificate. A new certificate is always added to the
    /// store. This can lead to duplicates in a store.
    Always = winapi::CERT_STORE_ADD_ALWAYS as isize,

    /// If a matching certificate or a link to a matching certificate exists,
    /// the operation fails.
    New = winapi::CERT_STORE_ADD_NEW as isize,

    /// If a matching certificate or a link to a matching certificate exists and
    /// the NotBefore time of the existing context is equal to or greater than
    /// the NotBefore time of the new context being added, the operation fails.
    ///
    /// If the NotBefore time of the existing context is less than the NotBefore
    /// time of the new context being added, the existing certificate or link is
    /// deleted and a new certificate is created and added to the store. If a
    /// matching certificate or a link to a matching certificate does not exist,
    /// a new link is added.
    Newer = winapi::CERT_STORE_ADD_NEWER as isize,

    /// If a matching certificate or a link to a matching certificate exists and
    /// the NotBefore time of the existing context is equal to or greater than
    /// the NotBefore time of the new context being added, the operation fails.
    ///
    /// If the NotBefore time of the existing context is less than the NotBefore
    /// time of the new context being added, the existing context is deleted
    /// before creating and adding the new context. The new added context
    /// inherits properties from the existing certificate.
    NewerInheritProperties = winapi::CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES as isize,

    /// If a link to a matching certificate exists, that existing certificate or
    /// link is deleted and a new certificate is created and added to the store.
    /// If a matching certificate or a link to a matching certificate does not
    /// exist, a new link is added.
    ReplaceExisting = winapi::CERT_STORE_ADD_REPLACE_EXISTING as isize,

    /// If a matching certificate exists in the store, the existing context is
    /// not replaced. The existing context inherits properties from the new
    /// certificate.
    ReplaceExistingInheritProperties =
        winapi::CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES as isize,

    /// If a matching certificate or a link to a matching certificate exists,
    /// that existing certificate or link is used and properties from the
    /// new certificate are added. The function does not fail, but it does
    /// not add a new context. The existing context is duplicated and returned.
    ///
    /// If a matching certificate or a link to a matching certificate does
    /// not exist, a new certificate is added.
    UseExisting = winapi::CERT_STORE_ADD_USE_EXISTING as isize,
}

impl CertStore {
    /// Creates a new in-memory certificate store which certificates and CTLs
    /// can be added to.
    #[allow(dead_code)]
    /* pub */ fn memory() -> io::Result<Memory> {
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

    /// Opens up the specified key store within the context of the current user.
    ///
    /// Known valid values for `which` are "Root" and "My".
    pub fn open_current_user(which: &str) -> io::Result<CertStore> {
        unsafe {
            let data = OsStr::new(which)
                             .encode_wide()
                             .chain(Some(0))
                             .collect::<Vec<_>>();
            let store = crypt32::CertOpenStore(winapi::CERT_STORE_PROV_SYSTEM_W as winapi::LPCSTR,
                                               0,
                                               0,
                                               winapi::CERT_SYSTEM_STORE_CURRENT_USER,
                                               data.as_ptr() as *mut _);
            if store.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(CertStore(store))
            }
        }
    }

    /// Opens up the specified key store within the context of the local
    /// machine.
    ///
    /// Known valid values for `which` are "Root" and "My".
    pub fn open_local_machine(which: &str) -> io::Result<CertStore> {
        unsafe {
            let data = OsStr::new(which)
                             .encode_wide()
                             .chain(Some(0))
                             .collect::<Vec<_>>();
            let store = crypt32::CertOpenStore(winapi::CERT_STORE_PROV_SYSTEM_W as winapi::LPCSTR,
                                               0,
                                               0,
                                               winapi::CERT_SYSTEM_STORE_LOCAL_MACHINE,
                                               data.as_ptr() as *mut _);
            if store.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(CertStore(store))
            }
        }
    }

    /// Imports a PKCS#12-encoded key/certificate pair, returned as a
    /// `CertStore` instance.
    ///
    /// The password must also be provided to decrypt the encoded data.
    pub fn import_pkcs12(data: &[u8],
                         password: Option<&str>)
                         -> io::Result<CertStore> {
        unsafe {
            let mut blob = winapi::CRYPT_INTEGER_BLOB {
                cbData: data.len() as winapi::DWORD,
                pbData: data.as_ptr() as *mut u8,
            };
            let password = password.map(|s| {
                OsStr::new(s).encode_wide()
                             .chain(Some(0))
                             .collect::<Vec<_>>()
            });
            let password = password.as_ref().map(|s| s.as_ptr());
            let password = password.unwrap_or(ptr::null());
            let res = crypt32::PFXImportCertStore(&mut blob,
                                                  password,
                                                  0);
            if res.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(CertStore(res))
            }
        }
    }

    /// Returns an iterator over the certificates in this certificate store.
    pub fn certs(&mut self) -> Certs {
        Certs { store: self, cur: None }
    }

    /// Adds a certificate context to this store.
    ///
    /// This function will add the certificate specified in `cx` to this store.
    /// A copy of the added certificate is returned.
    pub fn add_cert(&mut self,
                    cx: &CertContext,
                    how: CertAdd) -> io::Result<CertContext> {
        unsafe {
            let how = how as winapi::DWORD;
            let mut ret = ptr::null();
            let res = crypt32::CertAddCertificateContextToStore(self.0,
                                                                cx.as_inner(),
                                                                how,
                                                                &mut ret);
            if res != winapi::TRUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(CertContext::from_inner(ret))
            }
        }
    }
}

/// An iterator over the certificates contained in a `CertStore`, returned by
/// `CertStore::iter`
pub struct Certs<'a> {
    store: &'a mut CertStore,
    cur: Option<CertContext>,
}

impl<'a> Iterator for Certs<'a> {
    type Item = CertContext;

    fn next(&mut self) -> Option<CertContext> {
        unsafe {
            let cur = self.cur.take().map(|p| {
                let ptr = p.as_inner();
                mem::forget(p);
                ptr
            });
            let cur = cur.unwrap_or(ptr::null_mut());
            let next = crypt32::CertEnumCertificatesInStore(self.store.0, cur);

            if next.is_null() {
                self.cur = None;
                None
            } else {
                let next = CertContext::from_inner(next);
                self.cur = Some(next.clone());
                Some(next)
            }
        }
    }
}

/// An in-memory store of certificates and CTLs, created by `CertStore::memory`
/// and can be converted into a `CertStore`.
#[derive(Clone)]
/* pub */ struct Memory(CertStore);

#[allow(dead_code)]
impl Memory {
    /// Adds a new certificate to this memory store.
    ///
    /// For example the bytes could be a DER-encoded certificate.
    pub fn add_encoded_certificate(&mut self, cert: &[u8]) -> io::Result<CertContext> {
        unsafe {
            let mut cert_context = ptr::null();

            let res = crypt32::CertAddEncodedCertificateToStore((self.0).0,
                                                                winapi::X509_ASN_ENCODING |
                                                                winapi::PKCS_7_ASN_ENCODING,
                                                                cert.as_ptr() as *const _,
                                                                cert.len() as winapi::DWORD,
                                                                winapi::CERT_STORE_ADD_ALWAYS,
                                                                &mut cert_context);
            if res == winapi::TRUE {
                Ok(CertContext::from_inner(cert_context))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Adds a new CTL to this memory store, in its encoded form.
    ///
    /// This can be created through the `ctl_context::Builder` type.
    pub fn add_encoded_ctl(&mut self, ctl: &[u8]) -> io::Result<CtlContext> {
        unsafe {
            let mut ctl_context = ptr::null();

            let res = crypt32::CertAddEncodedCTLToStore((self.0).0,
                                                        winapi::X509_ASN_ENCODING |
                                                        winapi::PKCS_7_ASN_ENCODING,
                                                        ctl.as_ptr() as *const _,
                                                        ctl.len() as winapi::DWORD,
                                                        winapi::CERT_STORE_ADD_ALWAYS,
                                                        &mut ctl_context);
            if res == winapi::TRUE {
                Ok(CtlContext::from_inner(ctl_context))
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    /// Consumes this memory store, returning the underlying `CertStore`.
    pub fn into_store(self) -> CertStore {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ctl_context::CtlContext;

    #[test]
    fn load() {
        let cert = include_bytes!("../test/cert.der");
        let mut store = CertStore::memory().unwrap();
        store.add_encoded_certificate(cert).unwrap();
    }

    #[test]
    fn create_ctl() {
        let cert = include_bytes!("../test/self-signed.badssl.com.cer");
        let mut store = CertStore::memory().unwrap();
        let cert = store.add_encoded_certificate(cert).unwrap();

        CtlContext::builder()
            .certificate(cert)
            .usage("1.3.6.1.4.1.311.2.2.2")
            .encode_and_sign()
            .unwrap();
    }
}
