extern crate schannel;

use std::net::TcpListener;
use std::net::TcpStream;
use std::time::Duration;
use schannel::*;

#[test]
fn test_server()
{
    assert!(0 == 1);
    return;
    let listener = TcpListener::bind("127.0.0.1:443").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let info = SslInfo { target_name : "todo".to_string(), server_info: None };
                let mut server_stream = match SslStream::new(stream, info) {
                   Err(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
                   Ok(x) => x 
                };
            },
            Err(x) => { println!("Connection failed!"); }
        }
    }
    assert!(0 == 1)
}

#[test]
fn test_client() {
    let info = SslInfo { target_name: "google.com".to_string(), server_info: None };
    let tcp_stream = TcpStream::connect("google.com:443").unwrap();
    tcp_stream.set_read_timeout(Some(Duration::from_millis(250)));

    let mut ssl_stream = match SslStream::new(tcp_stream, info) {
        Err(x) => { println!("An error during connection: {:?}", x); assert!(false); return; },
        Ok(x) => x
    };
    ssl_stream.write(b"GET / HTTP/1.0\r\nHost: de.wikipedia.org\r\n\r\n");
    let mut target = [0; 8192];
    ssl_stream.read(&mut target);
    /* DBG: Fail the test to get stdout when running cargo test */
    assert!(0 == 1)
}
