//! CryptoAPI private keys.
use advapi32;
use winapi;

/// A handle to a key.
pub struct CryptKey(winapi::HCRYPTKEY);

impl Drop for CryptKey {
    fn drop(&mut self) {
        unsafe {
            advapi32::CryptDestroyKey(self.0);
        }
    }
}

inner!(CryptKey, winapi::HCRYPTKEY);
