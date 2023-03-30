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

pub(crate) mod cryptography;
pub(crate) mod identity;

// Uncomment this to regenerate bindings
// #[cfg(test)]
// mod regenerate {
//     #[test]
//     fn bindings() {
//         let apis = [
//             "Windows.Win32.Security.Credentials.SecHandle",

//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_ALERT",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_APPLICATION_PROTOCOLS",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_DATA",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_EMPTY",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_EXTRA",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_MISSING",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_STREAM_HEADER",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_STREAM_TRAILER",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_TOKEN",
//             "Windows.Win32.Security.Authentication.Identity.SECBUFFER_VERSION",

//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_SSL3_CLIENT",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_SSL3_SERVER",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_0_CLIENT",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_0_SERVER",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_1_CLIENT",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_1_SERVER",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_2_CLIENT",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_2_SERVER",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_3_CLIENT",
//             "Windows.Win32.Security.Authentication.Identity.SP_PROT_TLS1_3_SERVER",

//             "Windows.Win32.Security.Authentication.Identity.ASC_REQ_FLAGS",
//             "Windows.Win32.Security.Authentication.Identity.ISC_REQ_FLAGS",
//             "Windows.Win32.Security.Authentication.Identity.SCHANNEL_CRED",
//             "Windows.Win32.Security.Authentication.Identity.SCHANNEL_CRED_VERSION",
//             "Windows.Win32.Security.Authentication.Identity.SCHANNEL_CRED_FLAGS",
//             "Windows.Win32.Security.Authentication.Identity.SCHANNEL_SHUTDOWN",
//             "Windows.Win32.Security.Authentication.Identity.SecBuffer",
//             "Windows.Win32.Security.Authentication.Identity.SecBufferDesc",
//             "Windows.Win32.Security.Authentication.Identity.SecHandle",
//             "Windows.Win32.Security.Authentication.Identity.SEC_APPLICATION_PROTOCOL_LIST",
//             "Windows.Win32.Security.Authentication.Identity.SEC_APPLICATION_PROTOCOLS",
//             "Windows.Win32.Security.Authentication.Identity.SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT",
//             "Windows.Win32.Security.Authentication.Identity.SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS",
//             "Windows.Win32.Security.Authentication.Identity.SecPkgContext_ApplicationProtocol",
//             "Windows.Win32.Security.Authentication.Identity.SecPkgContext_SessionInfo",
//             "Windows.Win32.Security.Authentication.Identity.SecPkgContext_StreamSizes",
//             "Windows.Win32.Security.Authentication.Identity.SECPKG_ATTR",
//             "Windows.Win32.Security.Authentication.Identity.SECPKG_ATTR_APPLICATION_PROTOCOL",
//             "Windows.Win32.Security.Authentication.Identity.SECPKG_CRED",
//             "Windows.Win32.Security.Authentication.Identity.SEC_GET_KEY_FN",
//             "Windows.Win32.Security.Authentication.Identity.SSL_SESSION_RECONNECT",
//             "Windows.Win32.Security.Authentication.Identity._HMAPPER",

//             "Windows.Win32.Security.Authentication.Identity.AcceptSecurityContext",
//             "Windows.Win32.Security.Authentication.Identity.AcquireCredentialsHandleA",
//             "Windows.Win32.Security.Authentication.Identity.ApplyControlToken",
//             "Windows.Win32.Security.Authentication.Identity.DecryptMessage",
//             "Windows.Win32.Security.Authentication.Identity.DeleteSecurityContext",
//             "Windows.Win32.Security.Authentication.Identity.EncryptMessage",
//             "Windows.Win32.Security.Authentication.Identity.FreeContextBuffer",
//             "Windows.Win32.Security.Authentication.Identity.FreeCredentialsHandle",
//             "Windows.Win32.Security.Authentication.Identity.InitializeSecurityContextW",
//             "Windows.Win32.Security.Authentication.Identity.QueryContextAttributesW",
//         ];

//         let bindings = windows_bindgen::standalone(&apis);
//         std::fs::write("src/bindings/identity.rs", bindings)
//             .expect("failed to generate identity bindings");

//         let apis = [
//             "Windows.Win32.Foundation.BOOL",
//             "Windows.Win32.Foundation.FILETIME",

//             "Windows.Win32.Security.Cryptography.ALG_CLASS_DATA_ENCRYPT",
//             "Windows.Win32.Security.Cryptography.ALG_CLASS_HASH",
//             "Windows.Win32.Security.Cryptography.ALG_CLASS_KEY_EXCHANGE",
//             "Windows.Win32.Security.Cryptography.ALG_CLASS_SIGNATURE",
//             "Windows.Win32.Security.Cryptography.ALG_SID_AES",
//             "Windows.Win32.Security.Cryptography.ALG_SID_AES_128",
//             "Windows.Win32.Security.Cryptography.ALG_SID_AES_192",
//             "Windows.Win32.Security.Cryptography.ALG_SID_AES_256",
//             "Windows.Win32.Security.Cryptography.ALG_SID_AGREED_KEY_ANY",
//             "Windows.Win32.Security.Cryptography.ALG_SID_ANY",
//             "Windows.Win32.Security.Cryptography.ALG_SID_CYLINK_MEK",
//             "Windows.Win32.Security.Cryptography.ALG_SID_DES",
//             "Windows.Win32.Security.Cryptography.ALG_SID_DESX",
//             "Windows.Win32.Security.Cryptography.ALG_SID_DH_EPHEM",
//             "Windows.Win32.Security.Cryptography.ALG_SID_DH_SANDF",
//             "Windows.Win32.Security.Cryptography.ALG_SID_DSS_ANY",
//             "Windows.Win32.Security.Cryptography.ALG_SID_ECDH",
//             "Windows.Win32.Security.Cryptography.ALG_SID_ECDH_EPHEM",
//             "Windows.Win32.Security.Cryptography.ALG_SID_ECDSA",
//             "Windows.Win32.Security.Cryptography.ALG_SID_HASH_REPLACE_OWF",
//             "Windows.Win32.Security.Cryptography.ALG_SID_HMAC",
//             "Windows.Win32.Security.Cryptography.ALG_SID_MAC",
//             "Windows.Win32.Security.Cryptography.ALG_SID_MD2",
//             "Windows.Win32.Security.Cryptography.ALG_SID_MD4",
//             "Windows.Win32.Security.Cryptography.ALG_SID_MD5",
//             "Windows.Win32.Security.Cryptography.ALG_SID_RC2",
//             "Windows.Win32.Security.Cryptography.ALG_SID_RC4",
//             "Windows.Win32.Security.Cryptography.ALG_SID_RC5",
//             "Windows.Win32.Security.Cryptography.ALG_SID_RSA_ANY",
//             "Windows.Win32.Security.Cryptography.ALG_SID_SHA1",
//             "Windows.Win32.Security.Cryptography.ALG_SID_SHA_256",
//             "Windows.Win32.Security.Cryptography.ALG_SID_SHA_384",
//             "Windows.Win32.Security.Cryptography.ALG_SID_SHA_512",
//             "Windows.Win32.Security.Cryptography.ALG_SID_3DES",
//             "Windows.Win32.Security.Cryptography.ALG_SID_3DES_112",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_ANY",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_BLOCK",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_DH",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_DSS",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_ECDH",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_RSA",
//             "Windows.Win32.Security.Cryptography.ALG_TYPE_STREAM",

//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_CACHE_END_CERT",
//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_POLICY_SSL",
//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY",
//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT",

//             "Windows.Win32.Security.Cryptography.CERT_DESCRIPTION_PROP_ID",
//             "Windows.Win32.Security.Cryptography.CERT_FRIENDLY_NAME_PROP_ID",
//             "Windows.Win32.Security.Cryptography.CERT_SIGNATURE_HASH_PROP_ID",
//             "Windows.Win32.Security.Cryptography.CERT_SIGN_HASH_CNG_ALG_PROP_ID",

//             "Windows.Win32.Security.Cryptography.CMSG_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG",
//             "Windows.Win32.Security.Cryptography.CMSG_ENCODE_SORTED_CTL_FLAG",

//             "Windows.Win32.Security.Cryptography.PROV_DH_SCHANNEL",
//             "Windows.Win32.Security.Cryptography.PROV_DSS",
//             "Windows.Win32.Security.Cryptography.PROV_DSS_DH",
//             "Windows.Win32.Security.Cryptography.PROV_FORTEZZA",
//             "Windows.Win32.Security.Cryptography.PROV_MS_EXCHANGE",
//             "Windows.Win32.Security.Cryptography.PROV_RSA_AES",
//             "Windows.Win32.Security.Cryptography.PROV_RSA_FULL",
//             "Windows.Win32.Security.Cryptography.PROV_RSA_SCHANNEL",
//             "Windows.Win32.Security.Cryptography.PROV_RSA_SIG",
//             "Windows.Win32.Security.Cryptography.PROV_SSL",

//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_ALWAYS",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_NEW",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_NEWER",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_REPLACE_EXISTING",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_ADD_USE_EXISTING",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_PROV_MEMORY",
//             "Windows.Win32.Security.Cryptography.CERT_STORE_PROV_SYSTEM_W",

//             "Windows.Win32.Security.Cryptography.CERT_SYSTEM_STORE_CURRENT_USER_ID",
//             "Windows.Win32.Security.Cryptography.CERT_SYSTEM_STORE_LOCAL_MACHINE_ID",
//             "Windows.Win32.Security.Cryptography.CERT_SYSTEM_STORE_LOCATION_SHIFT",

//             "Windows.Win32.Security.Cryptography.CRYPT_KEY_PROV_INFO",
//             "Windows.Win32.Security.Cryptography.CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG",
//             "Windows.Win32.Security.Cryptography.CERT_KEY_PROV_INFO_PROP_ID",
//             "Windows.Win32.Security.Cryptography.CERT_KEY_SPEC",
//             "Windows.Win32.Security.Cryptography.CERT_OPEN_STORE_FLAGS",
//             "Windows.Win32.Security.Cryptography.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG",
//             "Windows.Win32.Security.Cryptography.CRYPT_ACQUIRE_FLAGS",
//             "Windows.Win32.Security.Cryptography.CRYPT_ALGORITHM_IDENTIFIER",
//             "Windows.Win32.Security.Cryptography.CRYPT_BIT_BLOB",
//             "Windows.Win32.Security.Cryptography.CRYPT_DECODE_ALLOC_FLAG",
//             "Windows.Win32.Security.Cryptography.CRYPT_ENCODE_OBJECT_FLAGS",
//             "Windows.Win32.Security.Cryptography.CRYPT_INTEGER_BLOB",
//             "Windows.Win32.Security.Cryptography.CRYPT_KEY_FLAGS",
//             "Windows.Win32.Security.Cryptography.CRYPT_KEY_PROV_PARAM",
//             "Windows.Win32.Security.Cryptography.CRYPT_NEWKEYSET",
//             "Windows.Win32.Security.Cryptography.CRYPT_PRIVATE_KEY_INFO",
//             "Windows.Win32.Security.Cryptography.CRYPT_SILENT",
//             "Windows.Win32.Security.Cryptography.CRYPT_STRING",
//             "Windows.Win32.Security.Cryptography.CRYPT_VERIFYCONTEXT",
//             "Windows.Win32.Security.Cryptography.EXPORT_PRIVATE_KEYS",
//             "Windows.Win32.Security.Cryptography.HCERTCHAINENGINE",
//             "Windows.Win32.Security.Cryptography.HCRYPTPROV_LEGACY",
//             "Windows.Win32.Security.Cryptography.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE",
//             "Windows.Win32.Security.Cryptography.NCRYPT_KEY_HANDLE",
//             "Windows.Win32.Security.Cryptography.PKCS_PRIVATE_KEY_INFO",
//             "Windows.Win32.Security.Cryptography.PKCS_RSA_PRIVATE_KEY",
//             "Windows.Win32.Security.Cryptography.USAGE_MATCH_TYPE_OR",

//             "Windows.Win32.Security.Cryptography.HTTPSPOLICY_CALLBACK_DATA_AUTH_TYPE",
//             "Windows.Win32.Security.Cryptography.HTTPSPolicyCallbackData",

//             "Windows.Win32.Security.Cryptography.CERT_PUBLIC_KEY_INFO",
//             "Windows.Win32.Security.Cryptography.CERT_INFO",
//             "Windows.Win32.Security.Cryptography.CERT_QUERY_ENCODING_TYPE",
//             "Windows.Win32.Security.Cryptography.HCERTSTORE",
//             "Windows.Win32.Security.Cryptography.CERT_CONTEXT",

//             "Windows.Win32.Security.Cryptography.CERT_EXTENSION",
//             "Windows.Win32.Security.Cryptography.CRYPT_ATTRIBUTE",
//             "Windows.Win32.Security.Cryptography.CRYPT_ATTRIBUTES",
//             "Windows.Win32.Security.Cryptography.CRL_INFO",
//             "Windows.Win32.Security.Cryptography.CRL_ENTRY",
//             "Windows.Win32.Security.Cryptography.CRL_CONTEXT",
//             "Windows.Win32.Security.Cryptography.CTL_V1",
//             "Windows.Win32.Security.Cryptography.CTL_ENTRY",
//             "Windows.Win32.Security.Cryptography.CTL_ENTRY_FROM_PROP_CHAIN_FLAG",
//             "Windows.Win32.Security.Cryptography.CTL_INFO",
//             "Windows.Win32.Security.Cryptography.CTL_USAGE",
//             "Windows.Win32.Security.Cryptography.CTL_CONTEXT",

//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_PARA",
//             "Windows.Win32.Security.Cryptography.CERT_USAGE_MATCH",

//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_CONTEXT",
//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_ELEMENT",
//             "Windows.Win32.Security.Cryptography.CERT_REVOCATION_CRL_INFO",
//             "Windows.Win32.Security.Cryptography.CERT_REVOCATION_INFO",
//             "Windows.Win32.Security.Cryptography.CERT_SIMPLE_CHAIN",
//             "Windows.Win32.Security.Cryptography.CERT_TRUST_LIST_INFO",
//             "Windows.Win32.Security.Cryptography.CERT_TRUST_STATUS",

//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_POLICY_FLAGS",
//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_POLICY_PARA",
//             "Windows.Win32.Security.Cryptography.CERT_CHAIN_POLICY_STATUS",

//             "Windows.Win32.Security.Cryptography.CertAddCertificateContextToStore",
//             "Windows.Win32.Security.Cryptography.CertAddEncodedCertificateToStore",
//             "Windows.Win32.Security.Cryptography.CertAddEncodedCTLToStore",
//             "Windows.Win32.Security.Cryptography.CertCloseStore",
//             "Windows.Win32.Security.Cryptography.CertCreateCertificateContext",
//             "Windows.Win32.Security.Cryptography.CertCreateCTLEntryFromCertificateContextProperties",
//             "Windows.Win32.Security.Cryptography.CertDeleteCertificateFromStore",
//             "Windows.Win32.Security.Cryptography.CertDuplicateCertificateChain",
//             "Windows.Win32.Security.Cryptography.CertDuplicateCertificateContext",
//             "Windows.Win32.Security.Cryptography.CertDuplicateStore",
//             "Windows.Win32.Security.Cryptography.CertEnumCertificatesInStore",
//             "Windows.Win32.Security.Cryptography.CertFreeCertificateChain",
//             "Windows.Win32.Security.Cryptography.CertFreeCertificateContext",
//             "Windows.Win32.Security.Cryptography.CertFreeCTLContext",
//             "Windows.Win32.Security.Cryptography.CertGetEnhancedKeyUsage",
//             "Windows.Win32.Security.Cryptography.CertGetCertificateChain",
//             "Windows.Win32.Security.Cryptography.CertGetCertificateContextProperty",
//             "Windows.Win32.Security.Cryptography.CertOpenStore",
//             "Windows.Win32.Security.Cryptography.CertSetCertificateContextProperty",
//             "Windows.Win32.Security.Cryptography.CertVerifyCertificateChainPolicy",
//             "Windows.Win32.Security.Cryptography.CertVerifyTimeValidity",
//             "Windows.Win32.Security.Cryptography.PFXExportCertStore",
//             "Windows.Win32.Security.Cryptography.PFXImportCertStore",

//             "Windows.Win32.Security.Cryptography.CMSG_SIGNER_ENCODE_INFO",
//             "Windows.Win32.Security.Cryptography.CMSG_SIGNED_ENCODE_INFO",

//             "Windows.Win32.Security.Cryptography.PFN_CRYPT_ALLOC",
//             "Windows.Win32.Security.Cryptography.PFN_CRYPT_FREE",
//             "Windows.Win32.Security.Cryptography.CRYPT_DECODE_PARA",
//             "Windows.Win32.Security.Cryptography.CRYPT_ENCODE_PARA",

//             "Windows.Win32.Security.Cryptography.CryptAcquireCertificatePrivateKey",
//             "Windows.Win32.Security.Cryptography.CryptAcquireContextW",
//             "Windows.Win32.Security.Cryptography.CryptBinaryToStringA",
//             "Windows.Win32.Security.Cryptography.CryptDecodeObjectEx",
//             "Windows.Win32.Security.Cryptography.CryptDestroyKey",
//             "Windows.Win32.Security.Cryptography.CryptEncodeObjectEx",
//             "Windows.Win32.Security.Cryptography.CryptHashCertificate",
//             "Windows.Win32.Security.Cryptography.CryptImportKey",
//             "Windows.Win32.Security.Cryptography.CryptMsgEncodeAndSignCTL",
//             "Windows.Win32.Security.Cryptography.CryptReleaseContext",
//             "Windows.Win32.Security.Cryptography.CryptStringToBinaryA",
//         ];

//         let bindings = windows_bindgen::standalone(&apis);
//         std::fs::write("src/bindings/cryptography.rs", bindings)
//             .expect("failed to generate cryptography bindings");
//     }
// }
