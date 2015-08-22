use libc::{size_t, c_void};
use security_framework_sys::{ioErr, OSStatus};
use security_framework_sys::secure_transport::{SSLContextRef, SSLNewContext, SSLDisposeContext};
use security_framework_sys::secure_transport::{SSLConnectionRef, SSLGetConnection};
use security_framework_sys::secure_transport::{SSLSetIOFuncs, SSLSetConnection, SSLHandshake};
use security_framework_sys::secure_transport::{SSLClose, SSLRead, SSLWrite, errSSLClosedGraceful};
use security_framework_sys::secure_transport::{errSSLClosedAbort, errSSLWouldBlock};
use security_framework_sys::secure_transport::{SSLSetPeerDomainName, errSSLClosedNoNotify};
use std::error;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;
use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(OSStatus);

// FIXME
impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.0)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Secure Transport error"
    }
}

pub enum ProtocolSide {
    Server,
    Client,
}

#[derive(Debug)]
pub struct HandshakeError<S> {
    pub stream: S,
    pub context: SslContext,
    pub error: Error,
}

#[derive(Debug)]
pub struct SslContext(SSLContextRef);

impl SslContext {
    pub fn new(side: ProtocolSide) -> Result<SslContext> {
        unsafe {
            let is_server = match side {
                ProtocolSide::Server => 1,
                ProtocolSide::Client => 0,
            };

            let mut ctx = ptr::null_mut();
            let result = SSLNewContext(is_server, &mut ctx);

            if result != 0 {
                return Err(Error(result));
            }

            Ok(SslContext(ctx))
        }
    }

    pub fn set_peer_domain_name(&self, peer_name: &str) -> Result<()> {
        unsafe {
            // SSLSetPeerDomainName doesn't needa null terminated string so don't need CString
            let ret = SSLSetPeerDomainName(self.0, 
                                           peer_name.as_ptr() as *const _,
                                           peer_name.len() as size_t);
            if ret == 0 {
                Ok(())
            } else {
                Err(Error(ret))
            }
        }
    }

    pub fn handshake<S>(self, stream: S) -> result::Result<SslStream<S>, HandshakeError<S>>
            where S: Read + Write {
        unsafe {
            let ret = SSLSetIOFuncs(self.0, read_func::<S>, write_func::<S>);
            if ret != 0 {
                return Err(HandshakeError {
                    stream: stream,
                    context: self,
                    error: Error(ret),
                });
            }

            let stream = Connection {
                stream: stream,
                err: None,
            };
            let stream = mem::transmute::<_, SSLConnectionRef>(Box::new(stream));
            let ret = SSLSetConnection(self.0, stream);
            if ret != 0 {
                let conn = mem::transmute::<_, Box<Connection<S>>>(stream);
                return Err(HandshakeError {
                    stream: conn.stream,
                    context: self,
                    error: Error(ret),
                });
            }

            let ret = SSLHandshake(self.0);
            if ret != 0 {
                let mut stream = ptr::null();
                assert!(SSLGetConnection(self.0, &mut stream) == 0);
                SSLSetConnection(self.0, ptr::null_mut());
                let conn = mem::transmute::<_, Box<Connection<S>>>(stream);
                return Err(HandshakeError {
                    stream: conn.stream,
                    context: self,
                    error: Error(ret),
                });
            }

            Ok(SslStream {
                ctx: self,
                _m: PhantomData,
            })
        }
    }
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe {
            SSLDisposeContext(self.0);
        }
    }
}

struct Connection<S> {
    stream: S,
    err: Option<io::Error>,
}

// the logic here is based off of libcurl's
fn translate_err(e: &io::Error) -> OSStatus {
    match e.kind() {
        io::ErrorKind::NotFound => errSSLClosedGraceful,
        io::ErrorKind::ConnectionReset => errSSLClosedAbort,
        io::ErrorKind::WouldBlock => errSSLWouldBlock,
        _ => ioErr,
    }
}

extern fn read_func<S: Read>(connection: SSLConnectionRef,
                             data: *mut c_void,
                             data_length: *mut size_t)
                             -> OSStatus {
    unsafe {
        let mut conn: &mut Connection<S> = mem::transmute(connection);
        let mut data = slice::from_raw_parts_mut(data as *mut u8, *data_length as usize);
        let mut start = 0;
        let mut ret = 0;

        while start < data.len() {
            match conn.stream.read(&mut data[start..]) {
                Ok(0) => {
                    ret = errSSLClosedNoNotify;
                    break;
                }
                Ok(len) => start += len,
                Err(e) => {
                    ret = translate_err(&e);
                    conn.err = Some(e);
                    break;
                }
            }
        }

        *data_length = start as size_t;
        ret
    }
}

extern fn write_func<S: Write>(connection: SSLConnectionRef,
                               data: *const c_void,
                               data_length: *mut size_t)
                               -> OSStatus {
    unsafe {
        let mut conn: &mut Connection<S> = mem::transmute(connection);
        let data = slice::from_raw_parts(data as *mut u8, *data_length as usize);
        let mut start = 0;
        let mut ret = 0;

        while start < data.len() {
            match conn.stream.write(&data[start..]) {
                Ok(0) => {
                    ret = errSSLClosedNoNotify;
                    break;
                },
                Ok(len) => start += len,
                Err(e) => {
                    ret = translate_err(&e);
                    conn.err = Some(e);
                    break;
                }
            }
        }

        *data_length = start as size_t;
        ret
    }
}

pub struct SslStream<S> {
    ctx: SslContext,
    _m: PhantomData<S>,
}

impl<S> Drop for SslStream<S> {
    fn drop(&mut self) {
        unsafe {
            SSLClose(self.ctx.0);

            let mut conn = ptr::null();
            let ret = SSLGetConnection(self.ctx.0, &mut conn);
            assert!(ret == 0);
            mem::transmute::<_, Box<Connection<S>>>(conn);
        }
    }
}

impl<S> SslStream<S> {
    fn connection(&mut self) -> &mut Connection<S> {
        unsafe {
            let mut conn = ptr::null();
            let ret = SSLGetConnection(self.ctx.0, &mut conn);
            assert!(ret == 0);

            mem::transmute(conn)
        }
    }

    fn get_error(&mut self, ret: OSStatus) -> io::Error {
        let conn = self.connection();
        if let Some(err) = conn.err.take() {
            err
        } else {
            io::Error::new(io::ErrorKind::Other, Error(ret))
        }
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut nread = 0;
            let ret = SSLRead(self.ctx.0,
                              buf.as_mut_ptr() as *mut _,
                              buf.len() as size_t,
                              &mut nread);
            match ret {
                0 => Ok(nread as usize),
                errSSLClosedGraceful
                    | errSSLClosedAbort
                    | errSSLClosedNoNotify => Ok(0),
                _ => Err(self.get_error(ret)),
            }
        }
    }
}

impl<S: Read + Write> Write for SslStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let mut nwritten = 0;
            let ret = SSLWrite(self.ctx.0,
                               buf.as_ptr() as *const _,
                               buf.len() as size_t,
                               &mut nwritten);
            if ret == 0 {
                Ok(nwritten as usize)
            } else {
                Err(self.get_error(ret))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.connection().stream.flush()
    }
}

#[cfg(test)]
mod test {
    use std::io::prelude::*;
    use std::net::TcpStream;

    use super::*;

    macro_rules! p {
        ($e:expr) => {
            match $e {
                Ok(s) => s,
                Err(e) => panic!("{:?}", e),
            }
        }
    }

    #[test]
    fn connect() {
        let ctx = p!(SslContext::new(ProtocolSide::Client));
        p!(ctx.set_peer_domain_name("google.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        p!(ctx.handshake(stream));
    }

    #[test]
    fn connect_bad_domain() {
        let ctx = p!(SslContext::new(ProtocolSide::Client));
        p!(ctx.set_peer_domain_name("foobar.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        match ctx.handshake(stream) {
            Ok(_) => panic!("expected failure"),
            Err(_) => {}
        }
    }

    #[test]
    fn load_page() {
        let ctx = p!(SslContext::new(ProtocolSide::Client));
        p!(ctx.set_peer_domain_name("google.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        let mut stream = p!(ctx.handshake(stream));
        p!(stream.write_all(b"GET / HTTP/1.0\r\n\r\n"));
        p!(stream.flush());
        let mut buf = String::new();
        p!(stream.read_to_string(&mut buf));
        println!("{}", buf);
    }
}
