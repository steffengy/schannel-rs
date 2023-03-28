//! CNG private keys.

use crate::bindings::cryptography as Cryptography;

/// A CNG handle to a key.
pub struct NcryptKey(Cryptography::NCRYPT_KEY_HANDLE);

impl Drop for NcryptKey {
    fn drop(&mut self) {
        //#[link(name = "ncrypt")]
        extern "system" {
            pub fn NCryptFreeObject(hObject: usize) -> i32;
        }

        unsafe {
            NCryptFreeObject(self.0);
        }
    }
}

inner!(NcryptKey, Cryptography::NCRYPT_KEY_HANDLE);
