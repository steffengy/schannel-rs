#![allow(non_camel_case_types, non_snake_case)]

pub type BOOL = i32;
pub type Hresult = i32;

pub const S_OK: Hresult = 0;
pub const CRYPT_E_NOT_FOUND: Hresult = -2146885628;

pub const SEC_E_OK: i32 = 0;
pub const SEC_I_CONTINUE_NEEDED: i32 = 590610;
pub const SEC_E_CONTEXT_EXPIRED: i32 = -2146893033;
pub const SEC_I_RENEGOTIATE: i32 = 590625;
pub const SEC_I_CONTEXT_EXPIRED: i32 = 590615;
pub const SEC_E_INCOMPLETE_MESSAGE: i32 = -2146893032;

pub const ERROR_SUCCESS: u32 = 0;

pub(crate) mod credentials {
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct SecHandle {
        pub dwLower: usize,
        pub dwUpper: usize,
    }
}

pub(crate) mod cryptography;
pub(crate) mod identity;
