extern crate schannel;

use std::net::TcpListener;
use std::net::TcpStream;
use std::time::Duration;
use schannel::*;

#[test]
fn test_server()
{
    let listener = TcpListener::bind("127.0.0.1:443").unwrap();
    // Fetch a certificate from HKLM by the SHA1 fingerprint, in this case only works for my local development machine IIS-express test certificate
    let server_info = SslInfoServer::new(SslCertStore::LocalMachine, SslCertCondition::SHA1HashIdentical { hash: "25f0fb4a3b81da7d41b0a3f90eebf9ca5eaefd17".to_owned() }).unwrap();
    let info = SslInfo::Server(server_info);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let mut server_stream = match SslStream::new(stream, &info) {
                   Err(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
                   Ok(x) => x 
                };
                server_stream.write("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nab".as_bytes());
            },
            Err(x) => { println!("Connection failed!"); }
        }
    }
    assert!(0 == 1)
}

#[test]
fn test_client() {
    let info = SslInfo::Client(SslInfoClient { target_name: "google.com".to_string() });
    let tcp_stream = TcpStream::connect("google.com:443").unwrap();
    tcp_stream.set_read_timeout(Some(Duration::from_millis(250)));

    let mut ssl_stream = match SslStream::new(tcp_stream, &info) {
        Err(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
        Ok(x) => x
    };
    ssl_stream.write(b"GET / HTTP/1.0\r\nHost: de.wikipedia.org\r\n\r\n");
    let mut target = [0; 8192];
    ssl_stream.read(&mut target);
    /* DBG: Fail the test to get stdout when running cargo test */
    assert!(0 == 1)
}
