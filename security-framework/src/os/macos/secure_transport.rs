use security_framework_sys::secure_transport::*;
use secure_transport::SslContext;
use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use std::ptr;
use std::slice;

use base::Result;
use certificate::SecCertificate;
use {cvt, AsInner};

pub trait SslContextExt {
    fn diffie_hellman_params(&self) -> Result<Option<&[u8]>>;
    fn set_diffie_hellman_params(&mut self, dh_params: &[u8]) -> Result<()>;
    fn certificate_authorities(&self) -> Result<Option<Vec<SecCertificate>>>;
    fn set_certificate_authorities(&mut self, certs: &[SecCertificate]) -> Result<()>;
    fn add_certificate_authorities(&mut self, certs: &[SecCertificate]) -> Result<()>;
}

impl SslContextExt for SslContext {
    fn diffie_hellman_params(&self) -> Result<Option<&[u8]>> {
        unsafe {
            let mut ptr = ptr::null();
            let mut len = 0;
            try!(cvt(SSLGetDiffieHellmanParams(self.as_inner(), &mut ptr, &mut len)));
            if ptr.is_null() {
                Ok(None)
            } else {
                Ok(Some(slice::from_raw_parts(ptr as *const u8, len)))
            }
        }
    }

    fn set_diffie_hellman_params(&mut self, dh_params: &[u8]) -> Result<()> {
        unsafe {
            cvt(SSLSetDiffieHellmanParams(self.as_inner(),
                                          dh_params.as_ptr() as *const _,
                                          dh_params.len()))
        }
    }

    fn certificate_authorities(&self) -> Result<Option<Vec<SecCertificate>>> {
        unsafe {
            let mut raw_certs = ptr::null();
            try!(cvt(SSLCopyCertificateAuthorities(self.as_inner(), &mut raw_certs)));
            if raw_certs.is_null() {
                Ok(None)
            } else {
                let certs = CFArray::wrap_under_create_rule(raw_certs)
                                .iter()
                                .map(|c| SecCertificate::wrap_under_get_rule(c as *mut _))
                                .collect();
                Ok(Some(certs))
            }
        }
    }

    fn set_certificate_authorities(&mut self, certs: &[SecCertificate]) -> Result<()> {
        unsafe {
            let certs = CFArray::from_CFTypes(certs);
            cvt(SSLSetCertificateAuthorities(self.as_inner(), certs.as_CFTypeRef(), 1))
        }
    }

    fn add_certificate_authorities(&mut self, certs: &[SecCertificate]) -> Result<()> {
        unsafe {
            let certs = CFArray::from_CFTypes(certs);
            cvt(SSLSetCertificateAuthorities(self.as_inner(), certs.as_CFTypeRef(), 0))
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::prelude::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use tempdir::TempDir;

    use super::*;
    use test::{next_port, certificate};
    use os::macos::test::identity;
    use cipher_suite::CipherSuite;
    use secure_transport::*;

    #[test]
    fn server_client() {
        let port = next_port();
        let listener = p!(TcpListener::bind(("localhost", port)));

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
        let stream = p!(TcpStream::connect(("localhost", port)));

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
        let port = next_port();
        let listener = p!(TcpListener::bind(("localhost", port)));

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
        let stream = p!(TcpStream::connect(("localhost", port)));

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

    #[test]
    fn dh_params() {
        let params = include_bytes!("../../../test/dhparam.der");

        let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        assert!(p!(ctx.diffie_hellman_params()).is_none());
        p!(ctx.set_diffie_hellman_params(params));
        assert_eq!(p!(ctx.diffie_hellman_params()).unwrap(), &params[..]);
    }

    #[test]
    fn try_authenticate_no_cert() {
        let port = next_port();
        let listener = p!(TcpListener::bind(("localhost", port)));

        let handle = thread::spawn(move || {
            let dir = p!(TempDir::new("negotiated_cipher"));

            let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
            let identity = identity(dir.path());
            p!(ctx.set_certificate(&identity, &[]));
            p!(ctx.set_client_side_authenticate(SslAuthenticate::Try));

            let stream = p!(listener.accept()).0;
            let mut stream = p!(ctx.handshake(stream));
            let mut buf = [0; 1];
            p!(stream.read(&mut buf));
        });

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_break_on_server_auth(true));
        let stream = p!(TcpStream::connect(("localhost", port)));

        let stream = match ctx.handshake(stream) {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::ServerAuthCompleted(stream)) => stream,
            Err(err) => panic!("unexpected error {:?}", err),
        };

        let mut stream = p!(stream.handshake());
        p!(stream.write(&[0]));

        handle.join().unwrap();
    }

    #[test]
    fn always_authenticate_no_cert() {
        let port = next_port();
        let listener = p!(TcpListener::bind(("localhost", port)));

        let handle = thread::spawn(move || {
            let dir = p!(TempDir::new("negotiated_cipher"));

            let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
            let identity = identity(dir.path());
            p!(ctx.set_certificate(&identity, &[]));
            p!(ctx.set_client_side_authenticate(SslAuthenticate::Always));

            let stream = p!(listener.accept()).0;

            match ctx.handshake(stream) {
                Ok(_) => panic!("unexpected success"),
                Err(HandshakeError::Failure(_)) => {},
                Err(err) => panic!("unexpected error {:?}", err),
            }
        });

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_break_on_server_auth(true));
        let stream = p!(TcpStream::connect(("localhost", port)));

        let stream = match ctx.handshake(stream) {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::ServerAuthCompleted(stream)) => stream,
            Err(err) => panic!("unexpected error {:?}", err),
        };

        match stream.handshake() {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::Failure(_)) => {},
            Err(err) => panic!("unexpected error {:?}", err),
        }

        handle.join().unwrap();
    }

    #[test]
    fn always_authenticate_with_cert() {
        let port = next_port();
        let listener = p!(TcpListener::bind(("localhost", port)));

        let handle = thread::spawn(move || {
            let dir = p!(TempDir::new("negotiated_cipher"));

            let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
            let identity = identity(dir.path());
            p!(ctx.set_certificate(&identity, &[]));
            p!(ctx.set_client_side_authenticate(SslAuthenticate::Always));

            let stream = p!(listener.accept()).0;

            match ctx.handshake(stream) {
                Ok(_) => panic!("unexpected success"),
                Err(HandshakeError::Failure(_)) => {},
                Err(err) => panic!("unexpected error {:?}", err),
            }
        });

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_break_on_server_auth(true));
        let dir = p!(TempDir::new("negotiated_cipher"));
        let identity = identity(dir.path());
        p!(ctx.set_certificate(&identity, &[]));
        let stream = p!(TcpStream::connect(("localhost", port)));

        let stream = match ctx.handshake(stream) {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::ServerAuthCompleted(stream)) => stream,
            Err(err) => panic!("unexpected error {:?}", err),
        };

        match stream.handshake() {
            Ok(_) => panic!("unexpected success"),
            Err(HandshakeError::Failure(_)) => {},
            Err(err) => panic!("unexpected error {:?}", err),
        }

        handle.join().unwrap();
    }

    #[test]
    fn certificate_authorities() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        assert!(p!(ctx.certificate_authorities()).is_none());
        p!(ctx.set_certificate_authorities(&[certificate()]));
        assert_eq!(p!(ctx.certificate_authorities()).unwrap().len(), 1);
    }
}
