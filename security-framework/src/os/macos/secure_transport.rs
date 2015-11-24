use security_framework_sys::secure_transport::*;
use secure_transport::SslContext;
use std::ptr;
use std::slice;

use base::Result;
use {cvt, AsInner};

pub trait SslContextExt {
    fn diffie_hellman_params(&self) -> Result<&[u8]>;
    fn set_diffie_hellman_params(&mut self, dh_params: &[u8]) -> Result<()>;
}

impl SslContextExt for SslContext {
    fn diffie_hellman_params(&self) -> Result<&[u8]> {
        unsafe {
            let mut ptr = ptr::null();
            let mut len = 0;
            try!(cvt(SSLGetDiffieHellmanParams(self.as_inner(), &mut ptr, &mut len)));
            Ok(slice::from_raw_parts(ptr as *const u8, len))
        }
    }

    fn set_diffie_hellman_params(&mut self, dh_params: &[u8]) -> Result<()> {
        unsafe {
            cvt(SSLSetDiffieHellmanParams(self.as_inner(),
                                          dh_params.as_ptr() as *const _,
                                          dh_params.len()))
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::prelude::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use tempdir::TempDir;

    use test::certificate;
    use os::macos::test::identity;
    use cipher_suite::CipherSuite;
    use secure_transport::*;

    #[test]
    fn server_client() {
        let listener = p!(TcpListener::bind("localhost:15410"));

        let handle = thread::spawn(move || {
            let dir = p!(TempDir::new("server_client"));

            let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
            let identity = identity(dir.path());
            p!(ctx.set_certificate(&identity, &[]));

            let stream = p!(listener.accept()).0;
            let mut stream = p!(ctx.handshake(stream));

            let mut buf = [0; 12];
            p!(stream.read(&mut buf));
            assert_eq!(&buf[..], b"hello world!");
        });

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_break_on_server_auth(true));
        let stream = p!(TcpStream::connect("localhost:15410"));

        let stream = match ctx.handshake(stream) {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::ServerAuthCompleted(stream)) => stream,
            Err(err) => panic!("unexpected error {:?}", err),
        };

        let mut peer_trust = p!(stream.context().peer_trust());
        p!(peer_trust.set_anchor_certificates(&[certificate()]));
        let result = p!(peer_trust.evaluate());
        assert!(result.success());

        let mut stream = p!(stream.handshake());
        p!(stream.write_all(b"hello world!"));

        handle.join().unwrap();
    }

    #[test]
    fn negotiated_cipher() {
        let listener = p!(TcpListener::bind("localhost:15411"));

        let handle = thread::spawn(move || {
            let dir = p!(TempDir::new("negotiated_cipher"));

            let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
            let identity = identity(dir.path());
            p!(ctx.set_certificate(&identity, &[]));
            p!(ctx.set_enabled_ciphers(&[CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                                         CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256]));

            let stream = p!(listener.accept()).0;
            let mut stream = p!(ctx.handshake(stream));
            assert_eq!(CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                       p!(stream.context().negotiated_cipher()));
            let mut buf = [0; 1];
            p!(stream.read(&mut buf));
        });

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_break_on_server_auth(true));
        p!(ctx.set_enabled_ciphers(&[CipherSuite::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
                                     CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256]));
        let stream = p!(TcpStream::connect("localhost:15411"));

        let stream = match ctx.handshake(stream) {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::ServerAuthCompleted(stream)) => stream,
            Err(err) => panic!("unexpected error {:?}", err),
        };

        let mut stream = p!(stream.handshake());
        assert_eq!(CipherSuite::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                   p!(stream.context().negotiated_cipher()));
        p!(stream.write(&[0]));

        handle.join().unwrap();
    }
}
