extern crate crypt32;
extern crate secur32;
extern crate winapi;

use secur32::{AcquireCredentialsHandleA, FreeCredentialsHandle};
use std::mem;
use std::ptr;
use std::result;
use winapi::{CredHandle, SECURITY_STATUS, SCHANNEL_CRED, SCHANNEL_CRED_VERSION, UNISP_NAME,
             SECPKG_CRED_OUTBOUND, SEC_E_OK};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(SECURITY_STATUS);

pub struct SchannelCredBuilder(());

impl SchannelCredBuilder {
    pub fn new() -> SchannelCredBuilder {
        SchannelCredBuilder(())
    }

    pub fn acquire(&self) -> Result<SchannelCred> {
        unsafe {
            let mut handle = mem::uninitialized();
            let mut cred_data: SCHANNEL_CRED = mem::zeroed();
            cred_data.dwVersion = SCHANNEL_CRED_VERSION;

            let status = AcquireCredentialsHandleA(ptr::null_mut(),
                                                   UNISP_NAME.as_ptr() as *mut _,
                                                   SECPKG_CRED_OUTBOUND,
                                                   ptr::null_mut(),
                                                   &mut cred_data as *mut _ as *mut _,
                                                   None,
                                                   ptr::null_mut(),
                                                   &mut handle,
                                                   ptr::null_mut());

            if status == SEC_E_OK {
                Ok(SchannelCred(handle))
            } else {
                Err(Error(status))
            }
        }
    }
}

pub struct SchannelCred(CredHandle);

impl Drop for SchannelCred {
    fn drop(&mut self) {
        unsafe { FreeCredentialsHandle(&mut self.0); }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let _creds = SchannelCredBuilder::new().acquire().unwrap();
    }
}