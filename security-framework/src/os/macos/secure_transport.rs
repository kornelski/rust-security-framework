//! OSX specific extensions to Secure Transport functionality.

use security_framework_sys::secure_transport::*;
use secure_transport::SslContext;
use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use std::ptr;
use std::slice;

use base::Result;
use certificate::SecCertificate;
use {cvt, AsInner};

/// An extension trait adding OSX specific functionality to the `SslContext`
/// type.
pub trait SslContextExt {
    /// Returns the DER encoded data specifying the parameters used for
    /// Diffie-Hellman key exchange.
    fn diffie_hellman_params(&self) -> Result<Option<&[u8]>>;

    /// Sets the parameters used for Diffie-Hellman key exchange, in the
    /// DER format used by OpenSSL.
    ///
    /// If a cipher suite which uses Diffie-Hellman key exchange is selected,
    /// parameters will automatically be generated if none are provided with
    /// this method, but this process can take up to 30 seconds.
    ///
    /// This can only be called on server-side sessions.
    fn set_diffie_hellman_params(&mut self, dh_params: &[u8]) -> Result<()>;

    /// Returns the certificate authorities used to validate client
    /// certificates.
    fn certificate_authorities(&self) -> Result<Option<Vec<SecCertificate>>>;

    /// Sets the certificate authorities used to validate client certificates,
    /// replacing any that are already present.
    fn set_certificate_authorities(&mut self, certs: &[SecCertificate]) -> Result<()>;

    /// Adds certificate authorities used to validate client certificates.
    fn add_certificate_authorities(&mut self, certs: &[SecCertificate]) -> Result<()>;

    /// If enabled, server identity changes are allowed during renegotiation.
    ///
    /// It is disabled by default to protect against triple handshake attacks.
    ///
    /// Requires the `OSX_10_11` (or greater) feature.
    #[cfg(feature = "OSX_10_11")]
    fn allow_server_identity_change(&self) -> Result<bool>;

    /// If enabled, server identity changes are allowed during renegotiation.
    ///
    /// It is disabled by default to protect against triple handshake attacks.
    ///
    /// Requires the `OSX_10_11` (or greater) feature.
    #[cfg(feature = "OSX_10_11")]
    fn set_allow_server_identity_change(&mut self, value: bool) -> Result<()>;

    /// If enabled, fallback countermeasures will be used during negotiation.
    ///
    /// It should be enabled when renegotiating with a peer with a lower
    /// maximum protocol version due to an earlier failure to connect.
    ///
    /// Requires the `OSX_10_10` (or greater) feature.
    #[cfg(feature = "OSX_10_10")]
    fn fallback(&self) -> Result<bool>;

    /// If enabled, fallback countermeasures will be used during negotiation.
    ///
    /// It should be enabled when renegotiating with a peer with a lower
    /// maximum protocol version due to an earlier failure to connect.
    ///
    /// Requires the `OSX_10_10` (or greater) feature.
    #[cfg(feature = "OSX_10_10")]
    fn set_fallback(&mut self, value: bool) -> Result<()>;

    /// If enabled, the handshake process will pause and return when the client
    /// hello is recieved to support server name identification.
    ///
    /// Requires the `OSX_10_11` feature.
    #[cfg(feature = "OSX_10_11")]
    fn break_on_client_hello(&self) -> Result<bool>;

    /// If enabled, the handshake process will pause and return when the client
    /// hello is recieved to support server name identification.
    ///
    /// Requires the `OSX_10_11` feature.
    #[cfg(feature = "OSX_10_11")]
    fn set_break_on_client_hello(&mut self, value: bool) -> Result<()>;
}

macro_rules! impl_options {
    ($($(#[$a:meta])* const $opt:ident: $get:ident & $set:ident,)*) => {
        $(
            $(#[$a])*
            fn $set(&mut self, value: bool) -> Result<()> {
                unsafe {
                    cvt(SSLSetSessionOption(self.as_inner(),
                                            $opt,
                                            value as ::core_foundation::base::Boolean))
                }
            }

            $(#[$a])*
            fn $get(&self) -> Result<bool> {
                let mut value = 0;
                unsafe { try!(cvt(SSLGetSessionOption(self.as_inner(), $opt, &mut value))); }
                Ok(value != 0)
            }
        )*
    }
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

    impl_options! {
        #[cfg(feature = "OSX_10_11")]
        const kSSLSessionOptionAllowServerIdentityChange: allow_server_identity_change & set_allow_server_identity_change,
        #[cfg(feature = "OSX_10_10")]
        const kSSLSessionOptionFallback: fallback & set_fallback,
        #[cfg(feature = "OSX_10_11")]
        const kSSLSessionOptionBreakOnClientHello: break_on_client_hello & set_break_on_client_hello,
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
                Err(HandshakeError::Failure(_)) => {}
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
            Err(HandshakeError::Failure(_)) => {}
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
                Err(HandshakeError::Failure(_)) => {}
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
            Err(HandshakeError::Failure(_)) => {}
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
