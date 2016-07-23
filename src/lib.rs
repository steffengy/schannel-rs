#![allow(non_upper_case_globals)]

extern crate crypt32;
extern crate kernel32;
extern crate libc;
extern crate secur32;
extern crate winapi;

#[macro_use]
extern crate lazy_static;

pub mod cert_context;
pub mod cert_store;
pub mod ctl_context;
pub mod schannel_cred;
pub mod tls_stream;

mod security_context;

#[cfg(test)]
mod test;

mod fuck_visibility {
    use winapi;
    use secur32;
    use std::ops::Deref;
    use std::slice;

    pub struct ContextBuffer(pub winapi::SecBuffer);

    impl Drop for ContextBuffer {
        fn drop(&mut self) {
            unsafe {
                secur32::FreeContextBuffer(self.0.pvBuffer);
            }
        }
    }

    impl Deref for ContextBuffer {
        type Target = [u8];

        fn deref(&self) -> &[u8] {
            unsafe { slice::from_raw_parts(self.0.pvBuffer as *const _, self.0.cbBuffer as usize) }
        }
    }
}

const INIT_REQUESTS: libc::c_ulong =
    winapi::ISC_REQ_CONFIDENTIALITY | winapi::ISC_REQ_INTEGRITY | winapi::ISC_REQ_REPLAY_DETECT |
    winapi::ISC_REQ_SEQUENCE_DETECT | winapi::ISC_REQ_MANUAL_CRED_VALIDATION |
    winapi::ISC_REQ_ALLOCATE_MEMORY | winapi::ISC_REQ_STREAM;

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    fn get_mut(&mut self) -> &mut T;
}
