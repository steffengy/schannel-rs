//! Private keys.

use advapi32;
use winapi;

use KeyHandlePriv;

/// A handle to a private key.
pub struct KeyHandle {
    handle: winapi::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    spec: winapi::DWORD,
}

// FIXME https://github.com/retep998/winapi-rs/pull/319
extern "system" {
    fn NCryptFreeObject(handle: winapi::NCRYPT_HANDLE) -> winapi::SECURITY_STATUS;
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        unsafe {
            if self.spec == winapi::CERT_NCRYPT_KEY_SPEC {
                NCryptFreeObject(self.handle);
            } else {
                advapi32::CryptReleaseContext(self.handle, 0);
            }
        }
    }
}

impl KeyHandlePriv for KeyHandle {
    fn new(handle: winapi::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, spec: winapi::DWORD) -> KeyHandle {
        KeyHandle {
            handle: handle,
            spec: spec,
        }
    }
}
