use std::env;
use std::io::{self, Error, Read, Write};
use std::mem;
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::sync::Once;
use std::thread;

use crate::alpn_list::AlpnList;
use crate::bindings::cryptography as Cryptography;
use crate::bindings::BOOL;
use crate::cert_context::{CertContext, HashAlgorithm, KeySpec};
use crate::cert_store::{CertAdd, CertStore, Memory};
use crate::crypt_prov::{AcquireOptions, ProviderType};
use crate::schannel_cred::{Algorithm, Direction, Protocol, SchannelCred};
use crate::tls_stream::{self, HandshakeError};
use crate::Inner;

#[allow(non_camel_case_types, non_snake_case)]
mod time {
    #[repr(C)]
    pub struct SYSTEMTIME {
        pub wYear: u16,
        pub wMonth: u16,
        pub wDayOfWeek: u16,
        pub wDay: u16,
        pub wHour: u16,
        pub wMinute: u16,
        pub wSecond: u16,
        pub wMilliseconds: u16,
    }
    #[repr(C)]
    pub struct FILETIME {
        pub dwLowDateTime: u32,
        pub dwHighDateTime: u32,
    }
    #[link(name = "windows")] // kernel32
    extern "system" {
        pub fn GetSystemTime(lpSystemTime: *mut SYSTEMTIME);
        pub fn SystemTimeToFileTime(
            lpSystemTime: *const SYSTEMTIME,
            lpFileTime: *mut FILETIME,
        ) -> super::BOOL;
        pub fn FileTimeToSystemTime(
            lpFileTime: *const FILETIME,
            lpSystemTime: *mut SYSTEMTIME,
        ) -> super::BOOL;
    }
}

#[allow(non_camel_case_types, non_snake_case)]
mod test_bindings {
    use super::Cryptography::*;
    use super::BOOL;

    pub const CERT_E_EXPIRED: i32 = -2146762495;
    pub const CERT_E_CN_NO_MATCH: i32 = -2146762481;
    pub const SEC_E_ALGORITHM_MISMATCH: i32 = -2146893007;
    pub const SEC_E_UNSUPPORTED_FUNCTION: i32 = -2146893054;
    pub const CERT_E_UNTRUSTEDROOT: i32 = -2146762487;

    pub type CERT_STRING_TYPE = u32;
    pub const CERT_X500_NAME_STR: CERT_STRING_TYPE = 3;

    pub type CERT_CREATE_SELFSIGN_FLAGS = u32;

    #[repr(C)]
    pub struct CERT_EXTENSION {
        pub pszObjId: *const u8,
        pub fCritical: BOOL,
        pub Value: CRYPT_INTEGER_BLOB,
    }
    #[repr(C)]
    pub struct CERT_EXTENSIONS {
        pub cExtension: u32,
        pub rgExtension: *mut CERT_EXTENSION,
    }

    #[link(name = "windows")] // crypt32
    extern "system" {
        pub fn CertCreateSelfSignCertificate(
            hCryptProvOrNCryptKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
            pSubjectIssuerBlob: *const CRYPT_INTEGER_BLOB,
            dwFlags: CERT_CREATE_SELFSIGN_FLAGS,
            pKeyProvInfo: *const CRYPT_KEY_PROV_INFO,
            pSignatureAlgorithm: *const CRYPT_ALGORITHM_IDENTIFIER,
            pStartTime: *const super::time::SYSTEMTIME,
            pEndTime: *const super::time::SYSTEMTIME,
            pExtensions: *const CERT_EXTENSIONS,
        ) -> *mut CERT_CONTEXT;

        pub fn CertStrToNameW(
            dwCertEncodingType: CERT_QUERY_ENCODING_TYPE,
            pszX500: *const u16,
            dwStrType: CERT_STRING_TYPE,
            pvReserved: *const std::ffi::c_void,
            pbEncoded: *mut u8,
            pcbEncoded: *mut u32,
            ppszError: *mut *mut u16,
        ) -> BOOL;
    }

    #[link(name = "windows")] // advapi32
    extern "system" {
        pub fn CryptGenKey(
            hProv: usize,
            Algid: u32,
            dwFlags: CRYPT_KEY_FLAGS,
            phKey: *mut usize,
        ) -> BOOL;
    }
}

#[test]
fn basic() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

#[test]
fn invalid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Rc2, Algorithm::Ecdsa])
        .acquire(Direction::Outbound);
    assert_eq!(
        creds.err().unwrap().raw_os_error().unwrap(),
        test_bindings::SEC_E_ALGORITHM_MISMATCH
    );
}

#[test]
fn valid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Aes128, Algorithm::Ecdsa])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

fn unwrap_handshake<S>(e: HandshakeError<S>) -> io::Error {
    match e {
        HandshakeError::Failure(e) => e,
        HandshakeError::Interrupted(_) => panic!("not an I/O error"),
    }
}

#[test]
#[ignore] // google's inconsistent about disallowing sslv3
fn invalid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Ssl3])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        test_bindings::SEC_E_UNSUPPORTED_FUNCTION
    );
}

#[test]
fn valid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

#[test]
fn valid_protocol_with_intermediate_certs() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("lh3.googleusercontent.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("lh3.googleusercontent.com")
        .connect(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK") || out.starts_with(b"HTTP/1.0 302 Found"));
    assert!(out.ends_with(b"</html>") || out.ends_with(b"</HTML>\r\n"));
}

#[test]
fn expired_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("expired.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("expired.badssl.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(err.raw_os_error().unwrap(), test_bindings::CERT_E_EXPIRED);
}

#[test]
fn self_signed_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        test_bindings::CERT_E_UNTRUSTEDROOT
    );
}

#[test]
fn self_signed_cert_manual_trust() {
    let cert = include_bytes!("../test/self-signed.badssl.com.cer");
    let mut store = Memory::new().unwrap();
    store.add_encoded_certificate(cert).unwrap();

    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .cert_store(store.into_store())
        .connect(creds, stream)
        .unwrap();
}

#[test]
fn wrong_host_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("wrong.host.badssl.com")
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        test_bindings::CERT_E_CN_NO_MATCH
    );
}

#[test]
fn wrong_host_cert_ignored() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    tls_stream::Builder::new()
        .domain("wrong.host.badssl.com")
        .accept_invalid_hostnames(true)
        .connect(creds, stream)
        .unwrap();
}

#[test]
fn shutdown() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    stream.shutdown().unwrap();
}

#[test]
fn validation_failure_is_permanent() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    // temporarily switch to nonblocking to allow us to construct the stream
    // without validating
    stream.set_nonblocking(true).unwrap();
    let stream = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .connect(creds, stream);
    let stream = match stream {
        Err(HandshakeError::Interrupted(s)) => s,
        _ => panic!(),
    };
    stream.get_ref().set_nonblocking(false).unwrap();
    let err = unwrap_handshake(stream.handshake().err().unwrap());
    assert_eq!(
        err.raw_os_error().unwrap(),
        test_bindings::CERT_E_UNTRUSTEDROOT
    );
}

#[test]
fn verify_callback_success() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let mut stream = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .verify_callback(|validation_result| {
            assert!(validation_result.result().is_err());
            Ok(())
        })
        .connect(creds, stream)
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: self-signed.badssl.com\r\n\r\n")
        .unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.1 200 OK"));
    assert!(out.ends_with(b"</html>\n"));
}

#[test]
fn verify_callback_error() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("google.com")
        .verify_callback(|validation_result| {
            assert!(validation_result.result().is_ok());
            Err(io::Error::from_raw_os_error(
                test_bindings::CERT_E_UNTRUSTEDROOT,
            ))
        })
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        test_bindings::CERT_E_UNTRUSTEDROOT
    );
}

#[test]
fn verify_callback_gives_failed_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let err = tls_stream::Builder::new()
        .domain("self-signed.badssl.com")
        .verify_callback(|validation_result| {
            let expected_finger = include_bytes!("../test/self-signed.badssl.com.cer.sha1").to_vec();
            assert_eq!(
                validation_result
                    .failed_certificate()
                    .unwrap()
                    .fingerprint(HashAlgorithm::sha1())
                    .unwrap(),
                expected_finger
            );
            Err(io::Error::from_raw_os_error(
                test_bindings::CERT_E_UNTRUSTEDROOT,
            ))
        })
        .connect(creds, stream)
        .err()
        .unwrap();
    let err = unwrap_handshake(err);
    assert_eq!(
        err.raw_os_error().unwrap(),
        test_bindings::CERT_E_UNTRUSTEDROOT
    );
}

#[test]
fn no_session_resumed() {
    for _ in 0..2 {
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let stream = TcpStream::connect("google.com:443").unwrap();
        let stream = tls_stream::Builder::new()
            .domain("google.com")
            .connect(creds, stream)
            .unwrap();
        assert!(!stream.session_resumed().unwrap());
    }
}

#[test]
fn basic_session_resumed() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let creds_copy = creds.clone();

    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds_copy, stream)
        .unwrap();
    assert!(!stream.session_resumed().unwrap());

    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    assert!(stream.session_resumed().unwrap());
}

#[test]
fn session_resumption_thread_safety() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();

    // Connect once so that the session ticket is cached.
    let creds_copy = creds.clone();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .domain("google.com")
        .connect(creds_copy, stream)
        .unwrap();
    assert!(!stream.session_resumed().unwrap());

    let mut threads = vec![];
    for _ in 0..4 {
        let creds_copy = creds.clone();
        threads.push(thread::spawn(move || {
            for _ in 0..10 {
                let creds = creds_copy.clone();
                let stream = TcpStream::connect("google.com:443").unwrap();
                let stream = tls_stream::Builder::new()
                    .domain("google.com")
                    .connect(creds, stream)
                    .unwrap();
                assert!(stream.session_resumed().unwrap());
            }
        }));
    }

    for thread in threads.into_iter() {
        thread.join().unwrap()
    }
}

const FRIENDLY_NAME: &str = "schannel-rs localhost testing cert";

const szOID_RSA_SHA256RSA: &[u8] = b"1.2.840.113549.1.1.11\0";

fn install_certificate() -> io::Result<CertContext> {
    unsafe {
        let mut provider = 0;
        let mut hkey = 0;

        let mut buffer = "schannel-rs test suite"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let res = Cryptography::CryptAcquireContextW(
            &mut provider,
            buffer.as_ptr(),
            ptr::null(),
            Cryptography::PROV_RSA_FULL,
            Cryptography::CRYPT_MACHINE_KEYSET,
        );
        if res == 0 {
            // create a new key container (since it does not exist)
            let res = Cryptography::CryptAcquireContextW(
                &mut provider,
                buffer.as_ptr(),
                ptr::null(),
                Cryptography::PROV_RSA_FULL,
                Cryptography::CRYPT_NEWKEYSET | Cryptography::CRYPT_MACHINE_KEYSET,
            );
            if res == 0 {
                return Err(Error::last_os_error());
            }
        }

        // create a new keypair (RSA-2048)
        let res = test_bindings::CryptGenKey(
            provider,
            Cryptography::AT_SIGNATURE,
            0x0800 << 16 | Cryptography::CRYPT_EXPORTABLE,
            &mut hkey,
        );
        if res == 0 {
            return Err(Error::last_os_error());
        }

        // start creating the certificate
        let name = "CN=localhost,O=schannel-rs,OU=schannel-rs,G=schannel_rs"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut cname_buffer: [u16; 257] = mem::zeroed();
        let mut cname_len = cname_buffer.len() as u32;
        let res = test_bindings::CertStrToNameW(
            Cryptography::X509_ASN_ENCODING,
            name.as_ptr(),
            test_bindings::CERT_X500_NAME_STR,
            ptr::null_mut(),
            cname_buffer.as_mut_ptr() as *mut u8,
            &mut cname_len,
            ptr::null_mut(),
        );
        if res == 0 {
            return Err(Error::last_os_error());
        }

        let subject_issuer = Cryptography::CRYPT_INTEGER_BLOB {
            cbData: cname_len,
            pbData: cname_buffer.as_ptr() as *mut u8,
        };
        let key_provider = Cryptography::CRYPT_KEY_PROV_INFO {
            pwszContainerName: buffer.as_mut_ptr(),
            pwszProvName: ptr::null_mut(),
            dwProvType: Cryptography::PROV_RSA_FULL,
            dwFlags: Cryptography::CRYPT_MACHINE_KEYSET,
            cProvParam: 0,
            rgProvParam: ptr::null_mut(),
            dwKeySpec: Cryptography::AT_SIGNATURE,
        };
        let sig_algorithm = Cryptography::CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: szOID_RSA_SHA256RSA.as_ptr() as *mut _,
            Parameters: mem::zeroed(),
        };
        let mut expiration_date: time::SYSTEMTIME = mem::zeroed();
        time::GetSystemTime(&mut expiration_date);
        let mut file_time: time::FILETIME = mem::zeroed();
        let res = time::SystemTimeToFileTime(&expiration_date, &mut file_time);
        if res == 0 {
            return Err(Error::last_os_error());
        }
        let mut timestamp: u64 =
            file_time.dwLowDateTime as u64 | (file_time.dwHighDateTime as u64) << 32;
        // one day, timestamp unit is in 100 nanosecond intervals
        timestamp += (1E9 as u64) / 100 * (60 * 60 * 24);
        file_time.dwLowDateTime = timestamp as u32;
        file_time.dwHighDateTime = (timestamp >> 32) as u32;
        let res = time::FileTimeToSystemTime(&file_time, &mut expiration_date);
        if res == 0 {
            return Err(Error::last_os_error());
        }

        // create a self signed certificate
        let cert_context = test_bindings::CertCreateSelfSignCertificate(
            Cryptography::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default(),
            &subject_issuer,
            test_bindings::CERT_CREATE_SELFSIGN_FLAGS::default(),
            &key_provider,
            &sig_algorithm,
            ptr::null_mut(),
            &expiration_date,
            ptr::null_mut(),
        );
        if cert_context.is_null() {
            return Err(Error::last_os_error());
        }
        let cert_context = CertContext::from_inner(cert_context);
        cert_context.set_friendly_name(FRIENDLY_NAME)?;

        // install the certificate to the machine's local store
        io::stdout()
            .write_all(
                br#"

The schannel-rs test suite is about to add a certificate to your set of root
and trusted certificates. This certificate should be for the domain "localhost"
with the description related to "schannel". This certificate is only valid for
one day and will be automatically deleted if you re-run the schannel-rs test
suite later.

If you would rather not do this please cancel the addition and re-run the
test suite with SCHANNEL_RS_SKIP_SERVER_TESTS=1.

"#,
            )
            .unwrap();
        local_root_store().add_cert(&cert_context, CertAdd::ReplaceExisting)?;
        Ok(cert_context)
    }
}

fn local_root_store() -> CertStore {
    if env::var("APPVEYOR").is_ok() || env::var("CI").is_ok() {
        CertStore::open_local_machine("Root").unwrap()
    } else {
        CertStore::open_current_user("Root").unwrap()
    }
}

fn localhost_cert() -> Option<CertContext> {
    if env::var("SCHANNEL_RS_SKIP_SERVER_TESTS").is_ok() {
        return None;
    }

    // Our tests need a certficiate that the system trusts to run with, and we
    // do this by basically generating a certificate on the fly. This
    // initialization block synchronizes tests to ensure that we only generate
    // one certificate which is then used by all the tests.
    //
    // First we check to see if the root trust store already has one of our
    // certificates, identified by the "friendly name" we set when the
    // certificate was created. If it's expired, then we delete it and generate
    // another. If none is found, we also generate another.
    //
    // Note that generating a certificate and adding it to the root trust store
    // will likely trigger a prompt to the user asking if they want to do that,
    // so we generate certificates that are valid for some amount of time so you
    // don't have to hit the "OK" button each time you run `cargo test`.
    //
    // After the initialization is performed we just probe the root store again
    // and find the certificate we added (or was already there).
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        for cert in local_root_store().certs() {
            let name = match cert.friendly_name() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if name != FRIENDLY_NAME {
                continue;
            }
            if !cert.is_time_valid().unwrap() {
                io::stdout()
                    .write_all(
                        br#"

The schannel-rs test suite is about to delete an old copy of one of its
certificates from your root trust store. This certificate was only valid for one
day and it is no longer needed. The host should be "localhost" and the
description should mention "schannel".

"#,
                    )
                    .unwrap();
                cert.delete().unwrap();
            } else {
                return;
            }
        }

        install_certificate().unwrap();
    });

    for cert in local_root_store().certs() {
        let name = match cert.friendly_name() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if name == FRIENDLY_NAME {
            return Some(cert);
        }
    }

    panic!("couldn't find a cert");
}

#[test]
fn accept_a_socket() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, stream)
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let mut stream = tls_stream::Builder::new().accept(creds, stream).unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    let mut buf = [0; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    t.join().unwrap();
}

#[test]
fn accept_one_byte_at_a_time() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    #[derive(Debug)]
    struct OneByteAtATime<S> {
        inner: S,
    }

    impl<S: Read> Read for OneByteAtATime<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(&mut buf[..1])
        }
    }

    impl<S: Write> Write for OneByteAtATime<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(&buf[..1])
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, OneByteAtATime { inner: stream })
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let mut stream = tls_stream::Builder::new()
        .accept(creds, OneByteAtATime { inner: stream })
        .unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    let mut buf = [0; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    t.join().unwrap();
}

#[test]
fn split_cert_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let cert = include_bytes!("../test/cert.der");
        let mut store = Memory::new().unwrap();
        store.add_encoded_certificate(cert).unwrap();
        let store = store.into_store();

        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("foobar.com")
            .cert_store(store)
            .connect(creds, stream)
            .unwrap();
        stream.write_all(&[1, 2, 3, 4]).unwrap();
        stream.flush().unwrap();
        assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
        stream.shutdown().unwrap();
    });

    let cert = include_bytes!("../test/cert.der");
    let cert = CertContext::new(cert).unwrap();

    let mut options = AcquireOptions::new();
    options.container("schannel-test");
    let type_ = ProviderType::rsa_full();

    let mut container = match options.acquire(type_) {
        Ok(container) => container,
        Err(_) => options.new_keyset(true).acquire(type_).unwrap(),
    };
    let key = include_bytes!("../test/key.key");
    container.import().import(key).unwrap();

    cert.set_key_prov_info()
        .container("schannel-test")
        .type_(type_)
        .keep_open(true)
        .key_spec(KeySpec::key_exchange())
        .set()
        .unwrap();

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let mut stream = tls_stream::Builder::new().accept(creds, stream).unwrap();
    assert_eq!(stream.read(&mut [0; 1024]).unwrap(), 4);
    stream.write_all(&[1, 2, 3, 4]).unwrap();
    stream.flush().unwrap();
    let mut buf = [0; 1];
    assert_eq!(stream.read(&mut buf).unwrap(), 0);

    t.join().unwrap();
}

#[test]
fn test_loopback_alpn() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .request_application_protocols(&[b"h2"])
            .connect(creds, stream)
            .unwrap();
        assert_eq!(
            stream
                .negotiated_application_protocol()
                .expect("localhost unreachable"),
            Some(b"h2".to_vec())
        );

        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let stream = tls_stream::Builder::new()
        .request_application_protocols(&[b"h2"])
        .accept(creds, stream)
        .unwrap();
    assert_eq!(
        stream
            .negotiated_application_protocol()
            .expect("localhost unreachable"),
        Some(b"h2".to_vec())
    );

    t.join().unwrap();
}

#[test]
fn test_loopback_alpn_mismatch() {
    let cert = match localhost_cert() {
        Some(cert) => cert,
        None => return,
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let t = thread::spawn(move || {
        let stream = TcpStream::connect(&addr).unwrap();
        let creds = SchannelCred::builder()
            .acquire(Direction::Outbound)
            .unwrap();
        let mut stream = tls_stream::Builder::new()
            .domain("localhost")
            .connect(creds, stream)
            .unwrap();
        assert_eq!(
            stream
                .negotiated_application_protocol()
                .expect("localhost unreachable"),
            None
        );

        stream.shutdown().unwrap();
    });

    let stream = listener.accept().unwrap().0;
    let creds = SchannelCred::builder()
        .cert(cert)
        .acquire(Direction::Inbound)
        .unwrap();
    let stream = tls_stream::Builder::new()
        .request_application_protocols(&[b"h2"])
        .accept(creds, stream)
        .unwrap();
    assert_eq!(
        stream
            .negotiated_application_protocol()
            .expect("localhost unreachable"),
        None
    );

    t.join().unwrap();
}

#[test]
fn test_external_alpn() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let stream = tls_stream::Builder::new()
        .request_application_protocols(&[b"h2"])
        .domain("google.com")
        .connect(creds, stream)
        .unwrap();
    assert_eq!(
        stream
            .negotiated_application_protocol()
            .expect("google.com unreachable"),
        Some(b"h2".to_vec())
    );
}

#[test]
fn test_alpn_list() {
    let raw_proto_alpn_list = b"\x02h2";
    // Little-endian bit representation of the expected `SEC_APPLICATION_PROTOCOL_LIST`.
    let proto_list = &[
        // `sspi::SecApplicationProtocolNegotiationExt_ALPN` equals 2.
        &[2, 0, 0, 0, raw_proto_alpn_list.len() as u8, 0] as &[u8],
        raw_proto_alpn_list,
    ]
    .concat();
    let full_alpn_list = [&[proto_list.len() as u8, 0, 0, 0] as &[u8], proto_list].concat();
    assert_eq!(
        &AlpnList::new(&[b"h2".to_vec()]) as &[u8],
        &full_alpn_list as &[u8]
    );

    let raw_proto_alpn_list = b"\x02h2\x08http/1.1";
    // Little-endian bit representation of the expected `SEC_APPLICATION_PROTOCOL_LIST`.
    let proto_list = &[
        // `sspi::SecApplicationProtocolNegotiationExt_ALPN` equals 2.
        &[2, 0, 0, 0, raw_proto_alpn_list.len() as u8, 0] as &[u8],
        raw_proto_alpn_list,
    ]
    .concat();
    let full_alpn_list = [&[proto_list.len() as u8, 0, 0, 0] as &[u8], proto_list].concat();
    assert_eq!(
        &AlpnList::new(&[b"h2".to_vec(), b"http/1.1".to_vec()]) as &[u8],
        &full_alpn_list as &[u8]
    );
}
