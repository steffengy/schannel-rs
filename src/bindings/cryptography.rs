use super::BOOL;

pub const ALG_TYPE_ANY: u32 = 0;
pub const ALG_TYPE_DSS: u32 = 512;
pub const ALG_TYPE_RSA: u32 = 1024;
pub const ALG_TYPE_BLOCK: u32 = 1536;
pub const ALG_TYPE_STREAM: u32 = 2048;
pub const ALG_TYPE_DH: u32 = 2560;
pub const ALG_TYPE_ECDH: u32 = 3584;

pub const ALG_CLASS_SIGNATURE: u32 = 8192;
pub const ALG_CLASS_DATA_ENCRYPT: u32 = 24576;
pub const ALG_CLASS_HASH: u32 = 32768;
pub const ALG_CLASS_KEY_EXCHANGE: u32 = 40960;

pub const ALG_SID_ANY: u32 = 0;
pub const ALG_SID_DSS_ANY: u32 = 0;
pub const ALG_SID_RSA_ANY: u32 = 0;
pub const ALG_SID_DH_SANDF: u32 = 1;
pub const ALG_SID_RC4: u32 = 1;
pub const ALG_SID_MD2: u32 = 1;
pub const ALG_SID_DES: u32 = 1;
pub const ALG_SID_RC2: u32 = 2;
pub const ALG_SID_DH_EPHEM: u32 = 2;
pub const ALG_SID_MD4: u32 = 2;
pub const ALG_SID_AGREED_KEY_ANY: u32 = 3;
pub const ALG_SID_MD5: u32 = 3;
pub const ALG_SID_ECDSA: u32 = 3;
pub const ALG_SID_3DES: u32 = 3;
pub const ALG_SID_SHA1: u32 = 4;
pub const ALG_SID_DESX: u32 = 4;
pub const ALG_SID_ECDH: u32 = 5;
pub const ALG_SID_MAC: u32 = 5;
pub const ALG_SID_ECDH_EPHEM: u32 = 6;
pub const ALG_SID_3DES_112: u32 = 9;
pub const ALG_SID_HMAC: u32 = 9;
pub const ALG_SID_HASH_REPLACE_OWF: u32 = 11;
pub const ALG_SID_SHA_256: u32 = 12;
pub const ALG_SID_CYLINK_MEK: u32 = 12;
pub const ALG_SID_SHA_384: u32 = 13;
pub const ALG_SID_RC5: u32 = 13;
pub const ALG_SID_SHA_512: u32 = 14;
pub const ALG_SID_AES_128: u32 = 14;
pub const ALG_SID_AES_192: u32 = 15;
pub const ALG_SID_AES_256: u32 = 16;
pub const ALG_SID_AES: u32 = 17;

pub const CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG: u32 = 8;

pub const CERT_SYSTEM_STORE_LOCATION_SHIFT: u32 = 16;

pub const CERT_CHAIN_POLICY_SSL: *const u8 = 4 as _;
pub const CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: u32 = 1073741824;
pub const CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY: u32 = 2147483648;
pub const CERT_CHAIN_CACHE_END_CERT: u32 = 1;

pub const CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG: u32 = 2;
pub const CMSG_ENCODE_SORTED_CTL_FLAG: u32 = 1;

pub const CTL_V1: u32 = 0;
pub const CTL_ENTRY_FROM_PROP_CHAIN_FLAG: u32 = 1;

#[repr(C)]
pub struct CERT_TRUST_STATUS {
    pub dwErrorStatus: u32,
    pub dwInfoStatus: u32,
}

pub type PFN_CRYPT_ALLOC =
    Option<unsafe extern "system" fn(cbSize: usize) -> *mut std::ffi::c_void>;
pub type PFN_CRYPT_FREE = Option<unsafe extern "system" fn(pv: *const std::ffi::c_void)>;
#[repr(C)]
pub struct CRYPT_ENCODE_PARA {
    pub cbSize: u32,
    pub pfnAlloc: PFN_CRYPT_ALLOC,
    pub pfnFree: PFN_CRYPT_FREE,
}
#[repr(C)]
pub struct CRYPT_DECODE_PARA {
    pub cbSize: u32,
    pub pfnAlloc: PFN_CRYPT_ALLOC,
    pub pfnFree: PFN_CRYPT_FREE,
}

pub type HCERTCHAINENGINE = isize;

pub const USAGE_MATCH_TYPE_OR: u32 = 1;

pub const CERT_SYSTEM_STORE_CURRENT_USER_ID: u32 = 1;
pub const CERT_SYSTEM_STORE_LOCAL_MACHINE_ID: u32 = 2;
pub const CERT_FRIENDLY_NAME_PROP_ID: u32 = 11;
pub const CERT_DESCRIPTION_PROP_ID: u32 = 13;
pub const CERT_SIGNATURE_HASH_PROP_ID: u32 = 15;
pub const CERT_SIGN_HASH_CNG_ALG_PROP_ID: u32 = 89;

pub const CERT_KEY_PROV_INFO_PROP_ID: u32 = 2;

pub const CERT_STORE_ADD_REPLACE_EXISTING: u32 = 3;

pub type CERT_QUERY_ENCODING_TYPE = u32;
pub const X509_ASN_ENCODING: CERT_QUERY_ENCODING_TYPE = 1;
pub const PKCS_7_ASN_ENCODING: CERT_QUERY_ENCODING_TYPE = 65536;

pub type HCRYPTPROV_LEGACY = usize;

pub type HTTPSPOLICY_CALLBACK_DATA_AUTH_TYPE = u32;
pub const AUTHTYPE_SERVER: HTTPSPOLICY_CALLBACK_DATA_AUTH_TYPE = 2;

pub type CERT_OPEN_STORE_FLAGS = u32;

pub const CERT_STORE_PROV_SYSTEM_W: *const u8 = 10 as _;
pub const CERT_STORE_ADD_USE_EXISTING: u32 = 2;
pub const CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES: u32 = 5;
pub const CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES: u32 = 7;
pub const CERT_STORE_ADD_NEWER: u32 = 6;
pub const CERT_STORE_ADD_NEW: u32 = 1;

pub type CRYPT_KEY_FLAGS = u32;
#[cfg(test)]
pub const CRYPT_EXPORTABLE: CRYPT_KEY_FLAGS = 1;
pub const CRYPT_MACHINE_KEYSET: CRYPT_KEY_FLAGS = 32;
pub const PKCS12_NO_PERSIST_KEY: CRYPT_KEY_FLAGS = 32768;
pub const PKCS12_INCLUDE_EXTENDED_PROPERTIES: CRYPT_KEY_FLAGS = 16;
pub const CERT_SET_KEY_PROV_HANDLE_PROP_ID: CRYPT_KEY_FLAGS = 1;

pub type CRYPT_STRING = u32;
pub const CRYPT_STRING_BASE64HEADER: CRYPT_STRING = 0;
pub const CRYPT_STRING_BASE64_ANY: CRYPT_STRING = 6;

pub type CRYPT_ACQUIRE_FLAGS = u32;
pub const CRYPT_ACQUIRE_COMPARE_KEY_FLAG: CRYPT_ACQUIRE_FLAGS = 4;
pub const CRYPT_ACQUIRE_SILENT_FLAG: CRYPT_ACQUIRE_FLAGS = 64;

pub type CERT_KEY_SPEC = u32;
pub const AT_KEYEXCHANGE: CERT_KEY_SPEC = 1;
pub const AT_SIGNATURE: CERT_KEY_SPEC = 2;
pub const CERT_NCRYPT_KEY_SPEC: CERT_KEY_SPEC = 4294967295;

pub type CRYPT_ENCODE_OBJECT_FLAGS = u32;

pub type CERT_CHAIN_POLICY_FLAGS = u32;
pub const CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG: CERT_CHAIN_POLICY_FLAGS = 16;
pub const CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS: CERT_CHAIN_POLICY_FLAGS = 3840;

pub const CRYPT_DECODE_ALLOC_FLAG: u32 = 32768;
pub const PKCS_PRIVATE_KEY_INFO: *const u8 = 44 as _;
pub const PKCS_RSA_PRIVATE_KEY: *const u8 = 43 as _;
pub const PROV_SSL: u32 = 6;
pub const PROV_MS_EXCHANGE: u32 = 5;
pub const PROV_FORTEZZA: u32 = 4;
pub const PROV_DH_SCHANNEL: u32 = 18;
pub const PROV_DSS_DH: u32 = 13;
pub const PROV_DSS: u32 = 3;
pub const PROV_RSA_SCHANNEL: u32 = 12;
pub const PROV_RSA_SIG: u32 = 2;
pub const PROV_RSA_AES: u32 = 24;
pub const PROV_RSA_FULL: u32 = 1;
pub const CRYPT_SILENT: u32 = 64;
pub const CRYPT_NEWKEYSET: u32 = 8;
pub const CRYPT_VERIFYCONTEXT: u32 = 4026531840;
pub const CERT_STORE_ADD_ALWAYS: u32 = 4;
pub const CERT_STORE_PROV_MEMORY: *const u8 = 2 as _;
pub const EXPORT_PRIVATE_KEYS: u32 = 4;

pub const CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG: u32 = 65536;

#[repr(C)]
pub union HTTPSPolicyCallbackData_0 {
    pub cbStruct: u32,
    pub cbSize: u32,
}
#[repr(C)]
pub struct HTTPSPolicyCallbackData {
    pub Anonymous: HTTPSPolicyCallbackData_0,
    pub dwAuthType: HTTPSPOLICY_CALLBACK_DATA_AUTH_TYPE,
    pub fdwChecks: u32,
    pub pwszServerName: *mut u16,
}

#[repr(C)]
pub struct CERT_CHAIN_POLICY_PARA {
    pub cbSize: u32,
    pub dwFlags: CERT_CHAIN_POLICY_FLAGS,
    pub pvExtraPolicyPara: *mut std::ffi::c_void,
}

#[repr(C)]
pub struct CRYPT_KEY_PROV_PARAM {
    pub dwParam: u32,
    pub pbData: *mut u8,
    pub cbData: u32,
    pub dwFlags: u32,
}
#[repr(C)]
pub struct CRYPT_KEY_PROV_INFO {
    pub pwszContainerName: *mut u16,
    pub pwszProvName: *mut u16,
    pub dwProvType: u32,
    pub dwFlags: CRYPT_KEY_FLAGS,
    pub cProvParam: u32,
    pub rgProvParam: *mut CRYPT_KEY_PROV_PARAM,
    pub dwKeySpec: u32,
}

pub type HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = usize;
pub type NCRYPT_KEY_HANDLE = usize;

#[repr(C)]
pub union CMSG_SIGNER_ENCODE_INFO_0 {
    pub hCryptProv: usize,
    pub hNCryptKey: NCRYPT_KEY_HANDLE,
}
#[repr(C)]
pub struct CMSG_SIGNER_ENCODE_INFO {
    pub cbSize: u32,
    pub pCertInfo: *mut CERT_INFO,
    pub Anonymous: CMSG_SIGNER_ENCODE_INFO_0,
    pub dwKeySpec: u32,
    pub HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub pvHashAuxInfo: *mut std::ffi::c_void,
    pub cAuthAttr: u32,
    pub rgAuthAttr: *mut CRYPT_ATTRIBUTE,
    pub cUnauthAttr: u32,
    pub rgUnauthAttr: *mut CRYPT_ATTRIBUTE,
}
#[repr(C)]
pub struct CMSG_SIGNED_ENCODE_INFO {
    pub cbSize: u32,
    pub cSigners: u32,
    pub rgSigners: *mut CMSG_SIGNER_ENCODE_INFO,
    pub cCertEncoded: u32,
    pub rgCertEncoded: *mut CRYPT_INTEGER_BLOB,
    pub cCrlEncoded: u32,
    pub rgCrlEncoded: *mut CRYPT_INTEGER_BLOB,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CRYPT_INTEGER_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
}
#[repr(C)]
pub struct CRYPT_ALGORITHM_IDENTIFIER {
    pub pszObjId: *const u8,
    pub Parameters: CRYPT_INTEGER_BLOB,
}
#[repr(C)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}
#[repr(C)]
pub struct CRYPT_BIT_BLOB {
    pub cbData: u32,
    pub pbData: *mut u8,
    pub cUnusedBits: u32,
}
#[repr(C)]
pub struct CERT_PUBLIC_KEY_INFO {
    pub Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub PublicKey: CRYPT_BIT_BLOB,
}
#[repr(C)]
pub struct CERT_EXTENSION {
    pub pszObjId: *const u8,
    pub fCritical: BOOL,
    pub Value: CRYPT_INTEGER_BLOB,
}
#[repr(C)]
pub struct CERT_INFO {
    pub dwVersion: u32,
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CRYPT_INTEGER_BLOB,
    pub NotBefore: FILETIME,
    pub NotAfter: FILETIME,
    pub Subject: CRYPT_INTEGER_BLOB,
    pub SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO,
    pub IssuerUniqueId: CRYPT_BIT_BLOB,
    pub SubjectUniqueId: CRYPT_BIT_BLOB,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}
#[repr(C)]
pub struct CERT_CHAIN_POLICY_STATUS {
    pub cbSize: u32,
    pub dwError: u32,
    pub lChainIndex: i32,
    pub lElementIndex: i32,
    pub pvExtraPolicyStatus: *mut std::ffi::c_void,
}
pub type HCERTSTORE = *mut std::ffi::c_void;
#[repr(C)]
pub struct CERT_CONTEXT {
    pub dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
    pub pbCertEncoded: *mut u8,
    pub cbCertEncoded: u32,
    pub pCertInfo: *mut CERT_INFO,
    pub hCertStore: HCERTSTORE,
}
#[repr(C)]
pub struct CRL_ENTRY {
    pub SerialNumber: CRYPT_INTEGER_BLOB,
    pub RevocationDate: FILETIME,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}
#[repr(C)]
pub struct CRL_INFO {
    pub dwVersion: u32,
    pub SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub Issuer: CRYPT_INTEGER_BLOB,
    pub ThisUpdate: FILETIME,
    pub NextUpdate: FILETIME,
    pub cCRLEntry: u32,
    pub rgCRLEntry: *mut CRL_ENTRY,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}
#[repr(C)]
pub struct CRL_CONTEXT {
    pub dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
    pub pbCrlEncoded: *mut u8,
    pub cbCrlEncoded: u32,
    pub pCrlInfo: *mut CRL_INFO,
    pub hCertStore: HCERTSTORE,
}
#[repr(C)]
pub struct CERT_REVOCATION_CRL_INFO {
    pub cbSize: u32,
    pub pBaseCrlContext: *mut CRL_CONTEXT,
    pub pDeltaCrlContext: *mut CRL_CONTEXT,
    pub pCrlEntry: *mut CRL_ENTRY,
    pub fDeltaCrlEntry: BOOL,
}
#[repr(C)]
pub struct CERT_REVOCATION_INFO {
    pub cbSize: u32,
    pub dwRevocationResult: u32,
    pub pszRevocationOid: *const u8,
    pub pvOidSpecificInfo: *mut std::ffi::c_void,
    pub fHasFreshnessTime: BOOL,
    pub dwFreshnessTime: u32,
    pub pCrlInfo: *mut CERT_REVOCATION_CRL_INFO,
}
#[repr(C)]
pub struct CTL_USAGE {
    pub cUsageIdentifier: u32,
    pub rgpszUsageIdentifier: *mut *const u8,
}
#[repr(C)]
pub struct CERT_USAGE_MATCH {
    pub dwType: u32,
    pub Usage: CTL_USAGE,
}
#[repr(C)]
pub struct CERT_CHAIN_PARA {
    pub cbSize: u32,
    pub RequestedUsage: CERT_USAGE_MATCH,
}
#[repr(C)]
pub struct CERT_CHAIN_ELEMENT {
    pub cbSize: u32,
    pub pCertContext: *const CERT_CONTEXT,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub pRevocationInfo: *mut CERT_REVOCATION_INFO,
    pub pIssuanceUsage: *mut CTL_USAGE,
    pub pApplicationUsage: *mut CTL_USAGE,
    pub pwszExtendedErrorInfo: *const u16,
}
#[repr(C)]
pub struct CRYPT_ATTRIBUTE {
    pub pszObjId: *const u8,
    pub cValue: u32,
    pub rgValue: *mut CRYPT_INTEGER_BLOB,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CTL_ENTRY {
    pub SubjectIdentifier: CRYPT_INTEGER_BLOB,
    pub cAttribute: u32,
    pub rgAttribute: *mut CRYPT_ATTRIBUTE,
}
#[repr(C)]
pub struct CTL_INFO {
    pub dwVersion: u32,
    pub SubjectUsage: CTL_USAGE,
    pub ListIdentifier: CRYPT_INTEGER_BLOB,
    pub SequenceNumber: CRYPT_INTEGER_BLOB,
    pub ThisUpdate: FILETIME,
    pub NextUpdate: FILETIME,
    pub SubjectAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub cCTLEntry: u32,
    pub rgCTLEntry: *mut CTL_ENTRY,
    pub cExtension: u32,
    pub rgExtension: *mut CERT_EXTENSION,
}
#[repr(C)]
pub struct CTL_CONTEXT {
    pub dwMsgAndCertEncodingType: u32,
    pub pbCtlEncoded: *mut u8,
    pub cbCtlEncoded: u32,
    pub pCtlInfo: *mut CTL_INFO,
    pub hCertStore: HCERTSTORE,
    pub hCryptMsg: *mut std::ffi::c_void,
    pub pbCtlContent: *mut u8,
    pub cbCtlContent: u32,
}
#[repr(C)]
pub struct CERT_TRUST_LIST_INFO {
    pub cbSize: u32,
    pub pCtlEntry: *mut CTL_ENTRY,
    pub pCtlContext: *mut CTL_CONTEXT,
}
#[repr(C)]
pub struct CERT_SIMPLE_CHAIN {
    pub cbSize: u32,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub cElement: u32,
    pub rgpElement: *mut *mut CERT_CHAIN_ELEMENT,
    pub pTrustListInfo: *mut CERT_TRUST_LIST_INFO,
    pub fHasRevocationFreshnessTime: BOOL,
    pub dwRevocationFreshnessTime: u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}
pub type Guid = GUID;
#[repr(C)]
pub struct CERT_CHAIN_CONTEXT {
    pub cbSize: u32,
    pub TrustStatus: CERT_TRUST_STATUS,
    pub cChain: u32,
    pub rgpChain: *mut *mut CERT_SIMPLE_CHAIN,
    pub cLowerQualityChainContext: u32,
    pub rgpLowerQualityChainContext: *mut *mut CERT_CHAIN_CONTEXT,
    pub fHasRevocationFreshnessTime: BOOL,
    pub dwRevocationFreshnessTime: u32,
    pub dwCreateFlags: u32,
    pub ChainId: Guid,
}
#[repr(C)]
pub struct CRYPT_ATTRIBUTES {
    pub cAttr: u32,
    pub rgAttr: *mut CRYPT_ATTRIBUTE,
}
#[repr(C)]
pub struct CRYPT_PRIVATE_KEY_INFO {
    pub Version: u32,
    pub Algorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pub PrivateKey: CRYPT_INTEGER_BLOB,
    pub pAttributes: *mut CRYPT_ATTRIBUTES,
}

#[link(name = "crypt32")]
extern "system" {
    pub fn CertDuplicateCertificateChain(
        pChainContext: *const CERT_CHAIN_CONTEXT,
    ) -> *mut CERT_CHAIN_CONTEXT;
    pub fn CertFreeCertificateChain(pChainContext: *const CERT_CHAIN_CONTEXT);
    pub fn CertFreeCertificateContext(pCertContext: *const CERT_CONTEXT) -> BOOL;
    pub fn CertDuplicateCertificateContext(pCertContext: *const CERT_CONTEXT) -> *mut CERT_CONTEXT;
    pub fn CryptEncodeObjectEx(
        dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
        lpszStructType: *const u8,
        pvStructInfo: *const std::ffi::c_void,
        dwFlags: CRYPT_ENCODE_OBJECT_FLAGS,
        pEncodePara: *const CRYPT_ENCODE_PARA,
        pvEncoded: *mut std::ffi::c_void,
        pcbEncoded: *mut u32,
    ) -> BOOL;
    pub fn CryptBinaryToStringA(
        pbBinary: *const u8,
        cbBinary: u32,
        dwFlags: CRYPT_STRING,
        pszString: *const u8,
        pcchString: *mut u32,
    ) -> BOOL;
    pub fn CryptHashCertificate(
        hCryptProv: HCRYPTPROV_LEGACY,
        Algid: u32,
        dwFlags: u32,
        pbEncoded: *const u8,
        cbEncoded: u32,
        pbComputedHash: *mut u8,
        pcbComputedHash: *mut u32,
    ) -> BOOL;
    pub fn CertVerifyTimeValidity(
        pTimeToVerify: *const FILETIME,
        pCertInfo: *const CERT_INFO,
    ) -> i32;
    pub fn CertDeleteCertificateFromStore(pCertContext: *const CERT_CONTEXT) -> BOOL;
    pub fn CertGetEnhancedKeyUsage(
        pCertContext: *const CERT_CONTEXT,
        dwFlags: u32,
        pUsage: *mut CTL_USAGE,
        pcbUsage: *mut u32,
    ) -> BOOL;
    pub fn CertDuplicateStore(hCertStore: HCERTSTORE) -> HCERTSTORE;
    pub fn CertGetCertificateContextProperty(
        pCertContext: *const CERT_CONTEXT,
        dwPropId: u32,
        pvData: *mut std::ffi::c_void,
        pcbData: *mut u32,
    ) -> BOOL;
    pub fn CertSetCertificateContextProperty(
        pCertContext: *const CERT_CONTEXT,
        dwPropId: u32,
        dwFlags: u32,
        pvData: *const std::ffi::c_void,
    ) -> BOOL;
    pub fn CryptAcquireCertificatePrivateKey(
        pCert: *const CERT_CONTEXT,
        dwFlags: CRYPT_ACQUIRE_FLAGS,
        pvParameters: *const std::ffi::c_void,
        phCryptProvOrNCryptKey: *mut HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
        pdwKeySpec: *mut CERT_KEY_SPEC,
        pfCallerFreeProvOrNCryptKey: *mut BOOL,
    ) -> BOOL;
    pub fn CryptMsgEncodeAndSignCTL(
        dwMsgEncodingType: u32,
        pCtlInfo: *const CTL_INFO,
        pSignInfo: *const CMSG_SIGNED_ENCODE_INFO,
        dwFlags: u32,
        pbEncoded: *mut u8,
        pcbEncoded: *mut u32,
    ) -> BOOL;
    pub fn CertCreateCTLEntryFromCertificateContextProperties(
        pCertContext: *const CERT_CONTEXT,
        cOptAttr: u32,
        rgOptAttr: *const CRYPT_ATTRIBUTE,
        dwFlags: u32,
        pvReserved: *const std::ffi::c_void,
        pCtlEntry: *mut CTL_ENTRY,
        pcbCtlEntry: *mut u32,
    ) -> BOOL;
    pub fn CertAddEncodedCTLToStore(
        hCertStore: HCERTSTORE,
        dwMsgAndCertEncodingType: CERT_QUERY_ENCODING_TYPE,
        pbCtlEncoded: *const u8,
        cbCtlEncoded: u32,
        dwAddDisposition: u32,
        ppCtlContext: *mut *mut CTL_CONTEXT,
    ) -> BOOL;
    pub fn CertAddEncodedCertificateToStore(
        hCertStore: HCERTSTORE,
        dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
        pbCertEncoded: *const u8,
        cbCertEncoded: u32,
        dwAddDisposition: u32,
        ppCertContext: *mut *mut CERT_CONTEXT,
    ) -> BOOL;
    pub fn CertAddCertificateContextToStore(
        hCertStore: HCERTSTORE,
        pCertContext: *const CERT_CONTEXT,
        dwAddDisposition: u32,
        ppStoreContext: *mut *mut CERT_CONTEXT,
    ) -> BOOL;
    pub fn CertOpenStore(
        lpszStoreProvider: *const u8,
        dwEncodingType: CERT_QUERY_ENCODING_TYPE,
        hCryptProv: HCRYPTPROV_LEGACY,
        dwFlags: CERT_OPEN_STORE_FLAGS,
        pvPara: *const std::ffi::c_void,
    ) -> HCERTSTORE;
    pub fn PFXImportCertStore(
        pPFX: *const CRYPT_INTEGER_BLOB,
        szPassword: *const u16,
        dwFlags: CRYPT_KEY_FLAGS,
    ) -> HCERTSTORE;
    pub fn PFXExportCertStore(
        hStore: HCERTSTORE,
        pPFX: *mut CRYPT_INTEGER_BLOB,
        szPassword: *const u16,
        dwFlags: u32,
    ) -> BOOL;
    pub fn CertEnumCertificatesInStore(
        hCertStore: HCERTSTORE,
        pPrevCertContext: *const CERT_CONTEXT,
    ) -> *mut CERT_CONTEXT;
    pub fn CryptAcquireContextW(
        phProv: *mut usize,
        szContainer: *const u16,
        szProvider: *const u16,
        dwProvType: u32,
        dwFlags: u32,
    ) -> BOOL;
    pub fn CryptStringToBinaryA(
        pszString: *const u8,
        cchString: u32,
        dwFlags: CRYPT_STRING,
        pbBinary: *mut u8,
        pcbBinary: *mut u32,
        pdwSkip: *mut u32,
        pdwFlags: *mut u32,
    ) -> BOOL;
    pub fn CryptDecodeObjectEx(
        dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
        lpszStructType: *const u8,
        pbEncoded: *const u8,
        cbEncoded: u32,
        dwFlags: u32,
        pDecodePara: *const CRYPT_DECODE_PARA,
        pvStructInfo: *mut std::ffi::c_void,
        pcbStructInfo: *mut u32,
    ) -> BOOL;
    pub fn CertVerifyCertificateChainPolicy(
        pszPolicyOID: *const u8,
        pChainContext: *const CERT_CHAIN_CONTEXT,
        pPolicyPara: *const CERT_CHAIN_POLICY_PARA,
        pPolicyStatus: *mut CERT_CHAIN_POLICY_STATUS,
    ) -> BOOL;
    pub fn CertGetCertificateChain(
        hChainEngine: HCERTCHAINENGINE,
        pCertContext: *const CERT_CONTEXT,
        pTime: *const FILETIME,
        hAdditionalStore: HCERTSTORE,
        pChainPara: *const CERT_CHAIN_PARA,
        dwFlags: u32,
        pvReserved: *const std::ffi::c_void,
        ppChainContext: *mut *mut CERT_CHAIN_CONTEXT,
    ) -> BOOL;
    pub fn CertFreeCTLContext(pCtlContext: *const CTL_CONTEXT) -> BOOL;
    pub fn CertCloseStore(hCertStore: HCERTSTORE, dwFlags: u32) -> BOOL;
    pub fn CertCreateCertificateContext(
        dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
        pbCertEncoded: *const u8,
        cbCertEncoded: u32,
    ) -> *mut CERT_CONTEXT;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn CryptReleaseContext(hProv: usize, dwFlags: u32) -> BOOL;
    pub fn CryptImportKey(
        hProv: usize,
        pbData: *const u8,
        dwDataLen: u32,
        hPubKey: usize,
        dwFlags: CRYPT_KEY_FLAGS,
        phKey: *mut usize,
    ) -> BOOL;
    pub fn CryptDestroyKey(hKey: usize) -> BOOL;
}
