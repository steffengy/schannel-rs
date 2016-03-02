use hyper::net::{Ssl, HttpStream, NetworkStream};
use hyper::error::Result;
use hyper::Error as HyperError;
use std::net::{SocketAddr, Shutdown};
use std::sync::Arc;
use std::time::Duration;
use std::io;

use SslError;
use SslInfo;
use SslStream;

#[derive(Debug, Clone)]
/// Schannel context for usage in hyper, providing ssl related configuration
pub struct Schannel
{
    pub info: Arc<SslInfo>
}

impl Ssl for Schannel
{
    type Stream = SslStream<HttpStream>;

    fn wrap_client(&self, stream: HttpStream, host: &str) -> Result<Self::Stream>
    {
        let mut ssl = try!(SslStream::new(stream, &self.info));
        ssl.set_host(host);
        if let Some(e) = ssl.init() {
            return Err(HyperError::from(e))
        }
        Ok(ssl)
    }

    fn wrap_server(&self, stream: HttpStream) -> Result<Self::Stream> {
        let mut ssl = try!(SslStream::new(stream, &self.info));
        if let Some(e) = ssl.init() {
            return Err(HyperError::from(e))
        }
        Ok(ssl)
    }
}

impl NetworkStream for SslStream<HttpStream> {
    #[inline]
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.stream.0.peer_addr()
    }

    #[inline]
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.0.set_read_timeout(dur)
    }

    #[inline]
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.0.set_write_timeout(dur)
    }

    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.stream.0.shutdown(how)
    }
}

impl From<SslError> for HyperError {
    fn from(err: SslError) -> HyperError {
        match err {
            SslError::IoError(err) => HyperError::Io(err),
            err => HyperError::Ssl(Box::new(err)),
        }
    }
}
