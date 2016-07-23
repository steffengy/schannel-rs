use winapi;
use secur32;
use std::io;
use std::mem;
use std::ptr;

use Inner;

lazy_static! {
    static ref UNISP_NAME: Vec<u8> = winapi::UNISP_NAME.bytes().chain(Some(0)).collect();
}

#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375549(v=vs.85).aspx
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Algorithm {
    /// Advanced Encryption Standard (AES).
    Aes = winapi::CALG_AES,
    /// 128 bit AES.
    Aes128 = winapi::CALG_AES_128,
    /// 192 bit AES.
    Aes192 = winapi::CALG_AES_192,
    /// 256 bit AES.
    Aes256 = winapi::CALG_AES_256,
    /// Temporary algorithm identifier for handles of Diffie-Hellman–agreed keys.
    AgreedkeyAny = winapi::CALG_AGREEDKEY_ANY,
    /// An algorithm to create a 40-bit DES key that has parity bits and zeroed key bits to make
    /// its key length 64 bits.
    CylinkMek = winapi::CALG_CYLINK_MEK,
    /// DES encryption algorithm.
    Des = winapi::CALG_DES,
    /// DESX encryption algorithm.
    Desx = winapi::CALG_DESX,
    /// Diffie-Hellman ephemeral key exchange algorithm.
    DhEphem = winapi::CALG_DH_EPHEM,
    /// Diffie-Hellman store and forward key exchange algorithm.
    DhSf = winapi::CALG_DH_SF,
    /// DSA public key signature algorithm.
    DssSign = winapi::CALG_DSS_SIGN,
    /// Elliptic curve Diffie-Hellman key exchange algorithm.
    Ecdh = winapi::CALG_ECDH,
    // https://github.com/retep998/winapi-rs/issues/287
    // /// Ephemeral elliptic curve Diffie-Hellman key exchange algorithm.
    // EcdhEphem = winapi::CALG_ECDH_EPHEM,
    /// Elliptic curve digital signature algorithm.
    Ecdsa = winapi::CALG_ECDSA,
    /// One way function hashing algorithm.
    HashReplaceOwf = winapi::CALG_HASH_REPLACE_OWF,
    /// Hughes MD5 hashing algorithm.
    HughesMd5 = winapi::CALG_HUGHES_MD5,
    /// HMAC keyed hash algorithm.
    Hmac = winapi::CALG_HMAC,
    /// MAC keyed hash algorithm.
    Mac = winapi::CALG_MAC,
    /// MD2 hashing algorithm.
    Md2 = winapi::CALG_MD2,
    /// MD4 hashing algorithm.
    Md4 = winapi::CALG_MD4,
    /// MD5 hashing algorithm.
    Md5 = winapi::CALG_MD5,
    /// No signature algorithm..
    NoSign = winapi::CALG_NO_SIGN,
    /// RC2 block encryption algorithm.
    Rc2 = winapi::CALG_RC2,
    /// RC4 stream encryption algorithm.
    Rc4 = winapi::CALG_RC4,
    /// RC5 block encryption algorithm.
    Rc5 = winapi::CALG_RC5,
    /// RSA public key exchange algorithm.
    RsaKeyx = winapi::CALG_RSA_KEYX,
    /// RSA public key signature algorithm.
    RsaSign = winapi::CALG_RSA_SIGN,
    /// SHA hashing algorithm.
    Sha1 = winapi::CALG_SHA1,
    /// 256 bit SHA hashing algorithm.
    Sha256 = winapi::CALG_SHA_256,
    /// 384 bit SHA hashing algorithm.
    Sha384 = winapi::CALG_SHA_384,
    /// 512 bit SHA hashing algorithm.
    Sha512 = winapi::CALG_SHA_512,
    /// Triple DES encryption algorithm.
    TripleDes = winapi::CALG_3DES,
    /// Two-key triple DES encryption with effective key length equal to 112 bits.
    TripleDes112 = winapi::CALG_3DES_112,
    #[doc(hidden)]
    __ForExtensibility,
}

#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    /// Secure Sockets Layer 3.0
    Ssl3,
    /// Transport Layer Security 1.0
    Tls10,
    /// Transport Layer Security 1.1
    Tls11,
    /// Transport Layer Security 1.2
    Tls12,
    #[doc(hidden)]
    __ForExtensibility,
}

impl Protocol {
    fn dword(self, direction: Direction) -> winapi::DWORD {
        match (self, direction) {
            (Protocol::Ssl3, Direction::Inbound) => winapi::SP_PROT_SSL3_SERVER,
            (Protocol::Tls10, Direction::Inbound) => winapi::SP_PROT_TLS1_0_SERVER,
            (Protocol::Tls11, Direction::Inbound) => winapi::SP_PROT_TLS1_1_SERVER,
            (Protocol::Tls12, Direction::Inbound) => winapi::SP_PROT_TLS1_2_SERVER,
            (Protocol::Ssl3, Direction::Outbound) => winapi::SP_PROT_SSL3_CLIENT,
            (Protocol::Tls10, Direction::Outbound) => winapi::SP_PROT_TLS1_0_CLIENT,
            (Protocol::Tls11, Direction::Outbound) => winapi::SP_PROT_TLS1_1_CLIENT,
            (Protocol::Tls12, Direction::Outbound) => winapi::SP_PROT_TLS1_2_CLIENT,
            (Protocol::__ForExtensibility, _) => unreachable!(),
        }
    }
}

pub struct Builder {
    supported_algorithms: Option<Vec<Algorithm>>,
    enabled_protocols: Option<Vec<Protocol>>,
}

impl Builder {
    /// Sets the algorithms supported for sessions created from this builder.
    pub fn supported_algorithms(mut self,
                                supported_algorithms: &[Algorithm])
                                -> Builder {
        self.supported_algorithms = Some(supported_algorithms.to_owned());
        self
    }

    /// Sets the protocols enabled for sessions created from this builder.
    pub fn enabled_protocols(mut self, enabled_protocols: &[Protocol]) -> Builder {
        self.enabled_protocols = Some(enabled_protocols.to_owned());
        self
    }

    pub fn acquire(&self, direction: Direction) -> io::Result<SchannelCred> {
        unsafe {
            let mut handle = mem::uninitialized();
            let mut cred_data: winapi::SCHANNEL_CRED = mem::zeroed();
            cred_data.dwVersion = winapi::SCHANNEL_CRED_VERSION;
            cred_data.dwFlags = winapi::SCH_USE_STRONG_CRYPTO;
            if let Some(ref supported_algorithms) = self.supported_algorithms {
                cred_data.cSupportedAlgs = supported_algorithms.len() as winapi::DWORD;
                cred_data.palgSupportedAlgs = supported_algorithms.as_ptr() as *mut _;
            }
            if let Some(ref enabled_protocols) = self.enabled_protocols {
                cred_data.grbitEnabledProtocols = enabled_protocols.iter()
                                                                   .map(|p| p.dword(direction))
                                                                   .fold(0, |acc, p| acc | p);
            }

            let direction = match direction {
                Direction::Inbound => winapi::SECPKG_CRED_INBOUND,
                Direction::Outbound => winapi::SECPKG_CRED_OUTBOUND,
            };

            match secur32::AcquireCredentialsHandleA(ptr::null_mut(),
                                                     UNISP_NAME.as_ptr() as *const _ as *mut _,
                                                     direction,
                                                     ptr::null_mut(),
                                                     &mut cred_data as *mut _ as *mut _,
                                                     None,
                                                     ptr::null_mut(),
                                                     &mut handle,
                                                     ptr::null_mut()) {
                winapi::SEC_E_OK => Ok(SchannelCred(handle)),
                err => Err(io::Error::from_raw_os_error(err as i32)),
            }
        }
    }
}

pub struct SchannelCred(winapi::CredHandle);

impl Drop for SchannelCred {
    fn drop(&mut self) {
        unsafe {
            secur32::FreeCredentialsHandle(&mut self.0);
        }
    }
}

impl Inner<winapi::CredHandle> for SchannelCred {
    unsafe fn from_inner(inner: winapi::CredHandle) -> SchannelCred {
        SchannelCred(inner)
    }

    fn as_inner(&self) -> winapi::CredHandle {
        self.0
    }

    fn get_mut(&mut self) -> &mut winapi::CredHandle {
        &mut self.0
    }
}

impl SchannelCred {
    pub fn builder() -> Builder {
        Builder {
            supported_algorithms: None,
            enabled_protocols: None,
        }
    }
}