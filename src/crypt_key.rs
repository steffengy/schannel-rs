//! CryptoAPI private keys.

/// A handle to a key.
pub struct CryptKey(usize);

impl Drop for CryptKey {
    fn drop(&mut self) {
        unsafe {
            crate::bindings::cryptography::CryptDestroyKey(self.0);
        }
    }
}

inner!(CryptKey, usize);
