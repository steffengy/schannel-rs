//! Bindings to the Windows SChannel APIs.
#![warn(missing_docs)]
#![allow(non_upper_case_globals)]

extern crate crypt32;
extern crate kernel32;
extern crate secur32;
extern crate winapi;

#[macro_use]
extern crate lazy_static;

#[allow(dead_code)]
/* pub */ mod cert_store;
#[allow(dead_code)]
/* pub */ mod ctl_context;
pub mod schannel_cred;
pub mod tls_stream;

mod cert_context;
mod context_buffer;
mod security_context;

#[cfg(test)]
mod test;

const INIT_REQUESTS: winapi::c_ulong =
    winapi::ISC_REQ_CONFIDENTIALITY | winapi::ISC_REQ_INTEGRITY | winapi::ISC_REQ_REPLAY_DETECT |
    winapi::ISC_REQ_SEQUENCE_DETECT | winapi::ISC_REQ_MANUAL_CRED_VALIDATION |
    winapi::ISC_REQ_ALLOCATE_MEMORY | winapi::ISC_REQ_STREAM;

trait Inner<T> {
    unsafe fn from_inner(t: T) -> Self;

    fn as_inner(&self) -> T;

    fn get_mut(&mut self) -> &mut T;
}
