//! CNG private keys.
use winapi;

// FIXME https://github.com/retep998/winapi-rs/pull/319
extern "system" {
    fn NCryptFreeObject(handle: winapi::NCRYPT_HANDLE) -> winapi::SECURITY_STATUS;
}

/// A CNG handle to a key.
pub struct NcryptKey(winapi::NCRYPT_KEY_HANDLE);

impl Drop for NcryptKey {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0);
        }
    }
}

inner!(NcryptKey, winapi::NCRYPT_KEY_HANDLE);
