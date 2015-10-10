#![cfg(feature = "hyper")]
extern crate schannel;

extern crate hyper;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::sync::Arc;
use std::io::{Read, Write};
use std::thread;

use hyper::{Client, Server};
use hyper::header::{Connection, Headers, UserAgent};
use hyper::net::HttpsConnector;
use hyper::server::{Request, Response};

use schannel::*;
use schannel::hyperimpl::Schannel as HyperSchannel;

#[test]
fn test_hyper_client()
{
    let info = SslInfo::Client(SslInfoClient { disable_peer_verification: false });
    let client = Client::with_connector(
        HttpsConnector::new(
            HyperSchannel {
                info: Arc::new(info)
            }
        )
    );
    let mut res = client.get("https://www.google.com/")
        .header(UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:44.0) Gecko/20100101 Firefox/44.0".to_string()))
        .header(Connection::close())
        .send().unwrap();
    let mut body = String::new();

    /*let mut vec: Vec<u8> = Vec::new();
    res.read_to_end(&mut vec).unwrap();
    let mut f = std::fs::File::create("dmp.txt").unwrap();
    f.write_all(&vec[..]).unwrap();*/

    res.read_to_string(&mut body).unwrap();
    //println!("Response: {}", body);
    assert!(body.contains("Google"));
}

#[test]
fn test_hyper_server()
{
    env_logger::init().unwrap();
    // Fetch a certificate from HKLM by the SHA1 fingerprint, in this case only works for my local development machine IIS-express test certificate
    let server_info = SslInfoServer::new(SslCertStore::LocalMachine, SslCertCondition::SubjectContains("localhost".to_owned())).unwrap();
    let wrapper = HyperSchannel {
        info: Arc::new(SslInfo::Server(server_info))
    };

    let mut listening = Server::https("127.0.0.1:443", wrapper).unwrap().handle(|_: Request, res: Response| {
        res.send(b"Schannel works").unwrap()
    }).unwrap();

    // Integration test for our client (disabled certificate check for now)
    let client_info = SslInfo::Client(SslInfoClient { disable_peer_verification: true });
    let client = Client::with_connector(
        HttpsConnector::new(
            HyperSchannel {
                info: Arc::new(client_info)
            }
        )
    );
    let mut res = client.get("https://127.0.0.1:443")
        .header(UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:44.0) Gecko/20100101 Firefox/44.0".to_string()))
        .header(Connection::close())
        .send().unwrap();
    let mut body = String::new();
    res.read_to_string(&mut body).unwrap();
    assert!(body.contains("Schannel works"));

    // Keep the server running after that to ensure it's handled
    thread::sleep_ms(4000);
    listening.close();
}
