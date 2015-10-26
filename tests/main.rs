extern crate schannel;

#[macro_use]
extern crate log;
extern crate env_logger;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use schannel::*;

#[test]
fn test_client() 
{
    let info = Arc::new(SslInfo::Client(SslInfoClient::new()));
    let tcp_stream = TcpStream::connect("google.com:443").unwrap();
    tcp_stream.set_read_timeout(Some(Duration::from_millis(250)));

    let mut ssl_stream = match SslStream::new(tcp_stream, &info) {
        Err(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
        Ok(x) => x
    };
    ssl_stream.set_host("google.com");
    match ssl_stream.init() {
        Some(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
        None => ()
    }
    ssl_stream.write(b"GET / HTTP/1.0\r\nHost: google.com\r\n\r\n");
    let mut target = [0; 8192];
    ssl_stream.read(&mut target);
    assert!(std::str::from_utf8(&target).unwrap().contains(".google"));
}

#[test]
fn test_server()
{
    //TODO: integrate these tests (test the server against a client, shutdown the server properly, ...)
    return;
    let listener = TcpListener::bind("127.0.0.1:8443").unwrap();
    // Fetch a certificate from HKLM by the SHA1 fingerprint, in this case only works for my local development machine IIS-express test certificate
    let server_info = SslInfoServer::new(SslCertStore::LocalMachine, SslCertCondition::SubjectContains("localhost".to_owned())).unwrap();
    let info = Arc::new(SslInfo::Server(server_info));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let mut server_stream = match SslStream::new(stream, &info) {
                   Err(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
                   Ok(x) => x 
                };
                match server_stream.init() {
                    Some(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
                    None => ()
                }
                println!("Sending...");
                server_stream.write("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nab".as_bytes());
            },
            Err(x) => { println!("Connection failed!"); }
        }
    }
}
