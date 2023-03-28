use super::{credentials::SecHandle, Hresult};

pub type SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT = i32;
pub const SecApplicationProtocolNegotiationExt_ALPN: SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT = 2;

pub type SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS = i32;
pub const SecApplicationProtocolNegotiationStatus_Success:
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS = 1;

#[repr(C)]
pub struct SEC_APPLICATION_PROTOCOL_LIST {
    pub ProtoNegoExt: SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT,
    pub ProtocolListSize: u16,
    pub ProtocolList: [u8; 1],
}

#[repr(C)]
pub struct SEC_APPLICATION_PROTOCOLS {
    pub ProtocolListsSize: u32,
    pub ProtocolLists: [SEC_APPLICATION_PROTOCOL_LIST; 1],
}

pub const SCHANNEL_SHUTDOWN: u32 = 1;
pub const SCHANNEL_CRED_VERSION: u32 = 4;

pub const SSL_SESSION_RECONNECT: u32 = 1;

pub const SECBUFFER_EMPTY: u32 = 0;
pub const SECBUFFER_VERSION: u32 = 0;
pub const SECBUFFER_DATA: u32 = 1;
pub const SECBUFFER_TOKEN: u32 = 2;
pub const SECBUFFER_MISSING: u32 = 4;
pub const SECBUFFER_EXTRA: u32 = 5;
pub const SECBUFFER_STREAM_TRAILER: u32 = 6;
pub const SECBUFFER_STREAM_HEADER: u32 = 7;
pub const SECBUFFER_ALERT: u32 = 17;
pub const SECBUFFER_APPLICATION_PROTOCOLS: u32 = 18;

pub const SP_PROT_SSL3_CLIENT: u32 = 32;
pub const SP_PROT_TLS1_0_CLIENT: u32 = 128;
pub const SP_PROT_TLS1_1_CLIENT: u32 = 512;
pub const SP_PROT_TLS1_2_CLIENT: u32 = 2048;
pub const SP_PROT_TLS1_3_CLIENT: u32 = 8192;

pub const SP_PROT_SSL3_SERVER: u32 = 16;
pub const SP_PROT_TLS1_0_SERVER: u32 = 64;
pub const SP_PROT_TLS1_1_SERVER: u32 = 256;
pub const SP_PROT_TLS1_2_SERVER: u32 = 1024;
pub const SP_PROT_TLS1_3_SERVER: u32 = 4096;

pub type SECPKG_ATTR = u32;
pub const SECPKG_ATTR_LOCAL_CERT_CONTEXT: SECPKG_ATTR = 84;
pub const SECPKG_ATTR_REMOTE_CERT_CONTEXT: SECPKG_ATTR = 83;
pub const SECPKG_ATTR_SESSION_INFO: SECPKG_ATTR = 93;
pub const SECPKG_ATTR_STREAM_SIZES: SECPKG_ATTR = 4;
pub const SECPKG_ATTR_APPLICATION_PROTOCOL: SECPKG_ATTR = 35;

pub type ISC_REQ_FLAGS = u32;
pub const ISC_REQ_REPLAY_DETECT: ISC_REQ_FLAGS = 4;
pub const ISC_REQ_SEQUENCE_DETECT: ISC_REQ_FLAGS = 8;
pub const ISC_REQ_CONFIDENTIALITY: ISC_REQ_FLAGS = 16;
pub const ISC_REQ_USE_SUPPLIED_CREDS: ISC_REQ_FLAGS = 128;
pub const ISC_REQ_ALLOCATE_MEMORY: ISC_REQ_FLAGS = 256;
pub const ISC_REQ_STREAM: ISC_REQ_FLAGS = 32768;
pub const ISC_REQ_INTEGRITY: ISC_REQ_FLAGS = 65536;
pub const ISC_REQ_MANUAL_CRED_VALIDATION: ISC_REQ_FLAGS = 524288;

pub type ASC_REQ_FLAGS = u32;
pub const ASC_REQ_REPLAY_DETECT: ASC_REQ_FLAGS = 4;
pub const ASC_REQ_SEQUENCE_DETECT: ASC_REQ_FLAGS = 8;
pub const ASC_REQ_CONFIDENTIALITY: ASC_REQ_FLAGS = 16;
pub const ASC_REQ_ALLOCATE_MEMORY: ASC_REQ_FLAGS = 256;
pub const ASC_REQ_STREAM: ASC_REQ_FLAGS = 65536;

#[repr(C)]
pub struct _HMAPPER {
    pub _unused: [u8; 0],
}
pub type SCHANNEL_CRED_FLAGS = u32;
pub const SCH_CRED_NO_DEFAULT_CREDS: SCHANNEL_CRED_FLAGS = 16;
pub const SCH_USE_STRONG_CRYPTO: SCHANNEL_CRED_FLAGS = 4194304;

#[repr(C)]
pub struct SCHANNEL_CRED {
    pub dwVersion: u32,
    pub cCreds: u32,
    pub paCred: *mut *mut super::cryptography::CERT_CONTEXT,
    pub hRootStore: super::cryptography::HCERTSTORE,
    pub cMappers: u32,
    pub aphMappers: *mut *mut _HMAPPER,
    pub cSupportedAlgs: u32,
    pub palgSupportedAlgs: *mut u32,
    pub grbitEnabledProtocols: u32,
    pub dwMinimumCipherStrength: u32,
    pub dwMaximumCipherStrength: u32,
    pub dwSessionLifespan: u32,
    pub dwFlags: SCHANNEL_CRED_FLAGS,
    pub dwCredFormat: u32,
}

#[repr(C)]
pub struct SecPkgContext_SessionInfo {
    pub dwFlags: u32,
    pub cbSessionId: u32,
    pub rgbSessionId: [u8; 32],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SecPkgContext_StreamSizes {
    pub cbHeader: u32,
    pub cbTrailer: u32,
    pub cbMaximumMessage: u32,
    pub cBuffers: u32,
    pub cbBlockSize: u32,
}
#[repr(C)]
pub struct SecPkgContext_ApplicationProtocol {
    pub ProtoNegoStatus: SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS,
    pub ProtoNegoExt: SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT,
    pub ProtocolIdSize: u8,
    pub ProtocolId: [u8; 255],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SecBuffer {
    pub cbBuffer: u32,
    pub BufferType: u32,
    pub pvBuffer: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct SecBufferDesc {
    pub ulVersion: u32,
    pub cBuffers: u32,
    pub pBuffers: *mut SecBuffer,
}

pub type SECPKG_CRED = u32;
pub const SECPKG_CRED_INBOUND: SECPKG_CRED = 1;
pub const SECPKG_CRED_OUTBOUND: SECPKG_CRED = 2;

pub type SEC_GET_KEY_FN = Option<
    unsafe extern "system" fn(
        Arg: *mut std::ffi::c_void,
        Principal: *mut std::ffi::c_void,
        KeyVer: u32,
        Key: *mut *mut std::ffi::c_void,
        Status: *mut Hresult,
    ),
>;

//#[link(name = "secur32")]
extern "system" {
    pub fn AcquireCredentialsHandleA(
        pszPrincipal: *const u8,
        pszPackage: *const u8,
        fCredentialUse: SECPKG_CRED,
        pvLogonId: *const std::ffi::c_void,
        pAuthData: *const std::ffi::c_void,
        pGetKeyFn: SEC_GET_KEY_FN,
        pvGetKeyArgument: *const std::ffi::c_void,
        phCredential: *mut SecHandle,
        ptsExpiry: *mut i64,
    ) -> Hresult;
    pub fn FreeCredentialsHandle(phCredential: *const SecHandle) -> Hresult;
    pub fn ApplyControlToken(phContext: *const SecHandle, pInput: *const SecBufferDesc) -> Hresult;
    pub fn AcceptSecurityContext(
        phCredential: *const SecHandle,
        phContext: *const SecHandle,
        pInput: *const SecBufferDesc,
        fContextReq: ASC_REQ_FLAGS,
        TargetDataRep: u32,
        phNewContext: *mut SecHandle,
        pOutput: *mut SecBufferDesc,
        pfContextAttr: *mut u32,
        ptsExpiry: *mut i64,
    ) -> Hresult;
    pub fn QueryContextAttributesW(
        phContext: *const SecHandle,
        ulAttribute: SECPKG_ATTR,
        pBuffer: *mut std::ffi::c_void,
    ) -> Hresult;
    pub fn DeleteSecurityContext(phContext: *const SecHandle) -> Hresult;
    pub fn InitializeSecurityContextW(
        phCredential: *const SecHandle,
        phContext: *const SecHandle,
        pszTargetName: *const u16,
        fContextReq: ISC_REQ_FLAGS,
        Reserved1: u32,
        TargetDataRep: u32,
        pInput: *const SecBufferDesc,
        Reserved2: u32,
        phNewContext: *mut SecHandle,
        pOutput: *mut SecBufferDesc,
        pfContextAttr: *mut u32,
        ptsExpiry: *mut i64,
    ) -> Hresult;
    pub fn EncryptMessage(
        phContext: *const SecHandle,
        fQOP: u32,
        pMessage: *const SecBufferDesc,
        MessageSeqNo: u32,
    ) -> Hresult;
    pub fn DecryptMessage(
        phContext: *const SecHandle,
        pMessage: *const SecBufferDesc,
        MessageSeqNo: u32,
        pfQOP: *mut u32,
    ) -> Hresult;
    pub fn FreeContextBuffer(pvContextBuffer: *mut std::ffi::c_void) -> Hresult;
}
