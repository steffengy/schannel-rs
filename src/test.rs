use std::io::{Read, Write};
use std::net::TcpStream;
use winapi;

use super::*;

#[test]
fn basic() {
    let creds = SchannelCred::builder().acquire(Direction::Outbound).unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = TlsStreamBuilder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK"));
    assert!(out.ends_with(b"</html>"));
}

#[test]
fn invalid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Rc2, Algorithm::Ecdsa])
        .acquire(Direction::Outbound);
    assert_eq!(creds.err().unwrap().raw_os_error().unwrap(),
               winapi::SEC_E_ALGORITHM_MISMATCH as i32);
}

#[test]
fn valid_algorithms() {
    let creds = SchannelCred::builder()
        .supported_algorithms(&[Algorithm::Aes128, Algorithm::Ecdsa])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = TlsStreamBuilder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK"));
    assert!(out.ends_with(b"</html>"));
}

#[test]
#[ignore] // google's inconsistent about disallowing sslv3
fn invalid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Ssl3])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let err = TlsStreamBuilder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    assert_eq!(err.raw_os_error().unwrap(), winapi::SEC_E_UNSUPPORTED_FUNCTION as i32);
}

#[test]
fn valid_protocol() {
    let creds = SchannelCred::builder()
        .enabled_protocols(&[Protocol::Tls12])
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = TlsStreamBuilder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut out = vec![];
    stream.read_to_end(&mut out).unwrap();
    assert!(out.starts_with(b"HTTP/1.0 200 OK"));
    assert!(out.ends_with(b"</html>"));
}

#[test]
fn expired_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("expired.badssl.com:443").unwrap();
    let err = TlsStreamBuilder::new()
        .domain("expired.badssl.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    assert_eq!(err.raw_os_error().unwrap(), winapi::CERT_E_EXPIRED as i32);
}

#[test]
fn self_signed_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("self-signed.badssl.com:443").unwrap();
    let err = TlsStreamBuilder::new()
        .domain("self-signed.badssl.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    assert_eq!(err.raw_os_error().unwrap(), winapi::CERT_E_UNTRUSTEDROOT as i32);
}

#[test]
fn wrong_host_cert() {
    let creds = SchannelCred::builder()
        .acquire(Direction::Outbound)
        .unwrap();
    let stream = TcpStream::connect("wrong.host.badssl.com:443").unwrap();
    let err = TlsStreamBuilder::new()
        .domain("wrong.host.badssl.com")
        .initialize(creds, stream)
        .err()
        .unwrap();
    assert_eq!(err.raw_os_error().unwrap(), winapi::CERT_E_CN_NO_MATCH as i32);
}

#[test]
fn shutdown() {
    let creds = SchannelCred::builder().acquire(Direction::Outbound).unwrap();
    let stream = TcpStream::connect("google.com:443").unwrap();
    let mut stream = TlsStreamBuilder::new()
        .domain("google.com")
        .initialize(creds, stream)
        .unwrap();
    stream.shutdown().unwrap();
}
