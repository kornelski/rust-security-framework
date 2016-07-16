//! SSL/TLS encryption support using Secure Transport.
//!
//! # Examples
//!
//! To connect as a client to a server with a certificate trusted by the system:
//!
//! ```rust
//! use std::io::prelude::*;
//! use std::net::TcpStream;
//! use security_framework::secure_transport::ClientBuilder;
//!
//! let stream = TcpStream::connect("google.com:443").unwrap();
//! let mut stream = ClientBuilder::new().handshake("google.com", stream).unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut page = vec![];
//! stream.read_to_end(&mut page).unwrap();
//! println!("{}", String::from_utf8_lossy(&page));
//! ```
//!
//! To connect to a server with a certificate that's *not* trusted by the
//! system, specify the root certificates for the server's chain to the
//! `ClientBuilder`:
//!
//! ```rust,no_run
//! use std::io::prelude::*;
//! use std::net::TcpStream;
//! use security_framework::secure_transport::ClientBuilder;
//!
//! # let root_cert = unsafe { std::mem::zeroed() };
//! let stream = TcpStream::connect("my_server.com:443").unwrap();
//! let mut stream = ClientBuilder::new()
//!                      .anchor_certificates(&[root_cert])
//!                      .handshake("my_server.com", stream)
//!                      .unwrap();
//!
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
//! let mut page = vec![];
//! stream.read_to_end(&mut page).unwrap();
//! println!("{}", String::from_utf8_lossy(&page));
//! ```
//!
//! For more advanced configuration, the `SslContext` type can be used directly.
//!
//! To run a server:
//!
//! ```rust,no_run
//! use std::net::TcpListener;
//! use std::thread;
//! use security_framework::secure_transport::{SslContext, ProtocolSide, ConnectionType};
//!
//! // Create a TCP listener and start accepting on it.
//! let mut listener = TcpListener::bind("0.0.0.0:443").unwrap();
//!
//! for stream in listener.incoming() {
//!     let stream = stream.unwrap();
//!     thread::spawn(move || {
//!         // Create a new context configured to operate on the server side of
//!         // a traditional SSL/TLS session.
//!         let mut ctx = SslContext::new(ProtocolSide::Server, ConnectionType::Stream)
//!                           .unwrap();
//!
//!         // Install the certificate chain that we will be using.
//!         # let identity = unsafe { std::mem::zeroed() };
//!         # let intermediate_cert = unsafe { std::mem::zeroed() };
//!         # let root_cert = unsafe { std::mem::zeroed() };
//!         ctx.set_certificate(identity, &[intermediate_cert, root_cert]).unwrap();
//!
//!         // Perform the SSL/TLS handshake and get our stream.
//!         let mut stream = ctx.handshake(stream).unwrap();
//!     });
//! }
//!
//! ```

use libc::{size_t, c_void};
use core_foundation::array::CFArray;
use core_foundation::base::{TCFType, Boolean};
use core_foundation_sys::base::OSStatus;
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
use core_foundation_sys::base::{kCFAllocatorDefault, CFRelease};
use security_framework_sys::base::{errSecSuccess, errSecIO, errSecBadReq, errSecTrustSettingDeny,
                                   errSecNotTrusted};
use security_framework_sys::secure_transport::*;
use std::any::Any;
use std::io;
use std::io::prelude::*;
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;
use std::result;

use {cvt, ErrorNew, CipherSuiteInternals, AsInner};
use base::{Result, Error};
use certificate::SecCertificate;
use cipher_suite::CipherSuite;
use identity::SecIdentity;
use trust::{SecTrust, TrustResult};

/// Specifies a side of a TLS session.
#[derive(Debug, Copy, Clone)]
pub enum ProtocolSide {
    /// The server side of the session.
    Server,
    /// The client side of the session.
    Client,
}

/// Specifies the type of TLS session.
#[derive(Debug, Copy, Clone)]
pub enum ConnectionType {
    /// A traditional TLS stream.
    Stream,
    /// A DTLS session.
    ///
    /// Requires the `OSX_10_8` (or higher) feature.
    #[cfg(feature = "OSX_10_8")]
    Datagram,
}

/// An error or intermediate state after a TLS handshake attempt.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// The handshake failed.
    Failure(Error),
    /// The handshake was interrupted midway through.
    Interrupted(MidHandshakeSslStream<S>),
}

/// An SSL stream midway through the handshake process.
#[derive(Debug)]
pub struct MidHandshakeSslStream<S> {
    stream: SslStream<S>,
    reason: OSStatus,
}

impl<S> MidHandshakeSslStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }

    /// Returns a shared reference to the `SslContext` of the stream.
    pub fn context(&self) -> &SslContext {
        self.stream.context()
    }

    /// Returns a mutable reference to the `SslContext` of the stream.
    pub fn context_mut(&mut self) -> &mut SslContext {
        self.stream.context_mut()
    }

    /// Returns `true` iff `break_on_server_auth` was set and the handshake has
    /// progressed to that point.
    pub fn server_auth_completed(&self) -> bool {
        self.reason == errSSLPeerAuthCompleted
    }

    /// Returns `true` iff `break_on_cert_requested` was set and the handshake
    /// has progressed to that point.
    pub fn client_cert_requested(&self) -> bool {
        self.reason == errSSLClientCertRequested
    }

    /// Returns `true` iff the underlying stream returned an error with the
    /// `WouldBlock` kind.
    pub fn would_block(&self) -> bool {
        self.reason == errSSLWouldBlock
    }

    /// Returns the raw error code which caused the handshake interruption.
    pub fn reason(&self) -> OSStatus {
        self.reason
    }

    /// Restarts the handshake process.
    pub fn handshake(self) -> result::Result<SslStream<S>, HandshakeError<S>> {
        self.stream.handshake()
    }
}

/// Specifies the state of a TLS session.
#[derive(Debug)]
pub enum SessionState {
    /// The session has not yet started.
    Idle,
    /// The session is in the handshake process.
    Handshake,
    /// The session is connected.
    Connected,
    /// The session has been terminated.
    Closed,
    /// The session has been aborted due to an error.
    Aborted,
}

impl SessionState {
    fn from_raw(raw: SSLSessionState) -> SessionState {
        match raw {
            kSSLIdle => SessionState::Idle,
            kSSLHandshake => SessionState::Handshake,
            kSSLConnected => SessionState::Connected,
            kSSLClosed => SessionState::Closed,
            kSSLAborted => SessionState::Aborted,
            _ => panic!("bad session state value {}", raw),
        }
    }
}

/// Specifies a server's requirement for client certificates.
#[derive(Debug)]
pub enum SslAuthenticate {
    /// Do not request a client certificate.
    Never,
    /// Require a client certificate.
    Always,
    /// Request but do not require a client certificate.
    Try,
}

/// Specifies the state of client certificate processing.
#[derive(Debug)]
pub enum SslClientCertificateState {
    /// A client certificate has not been requested or sent.
    None,
    /// A client certificate has been requested but not recieved.
    Requested,
    /// A client certificate has been received and successfully validated.
    Sent,
    /// A client certificate has been received but has failed to validate.
    Rejected,
}

macro_rules! ssl_protocol {
    ($($(#[$a:meta])* const $variant:ident = $value:ident,)+) => {
        /// Specifies protocol versions.
        pub enum SslProtocol {
            $($(#[$a])* $variant,)+
        }

        // #[derive(Debug)] doesn't work with macro expanded cfg'd variants
        impl fmt::Debug for SslProtocol {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                use self::SslProtocol::*;

                let s = match *self {
                    $($(#[$a])* $variant => stringify!($variant),)+
                };
                fmt.write_str(s)
            }
        }

        impl SslProtocol {
            fn from_raw(raw: SSLProtocol) -> SslProtocol {
                use self::SslProtocol::*;

                match raw {
                    $($(#[$a])* $value => $variant,)+
                    _ => panic!("invalid ssl protocol {}", raw),
                }
            }

            #[cfg(feature = "OSX_10_8")]
            fn to_raw(&self) -> SSLProtocol {
                use self::SslProtocol::*;

                match *self {
                    $($(#[$a])* $variant => $value,)+
                }
            }
        }
    }
}

ssl_protocol! {
    /// No protocol has been or should be negotiated or specified; use the
    /// default.
    const Unknown = kSSLProtocolUnknown,
    /// The SSL 3.0 protocol is preferred, though SSL 2.0 may be used if the
    /// peer does not support SSL 3.0.
    const Ssl3 = kSSLProtocol3,
    /// The TLS 1.0 protocol is preferred, though lower versions may be used
    /// if the peer does not support TLS 1.0.
    const Tls1 = kTLSProtocol1,
    /// The TLS 1.1 protocol is preferred, though lower versions may be used
    /// if the peer does not support TLS 1.1.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
    #[cfg(feature = "OSX_10_8")]
    const Tls11 = kTLSProtocol11,
    /// The TLS 1.2 protocol is preferred, though lower versions may be used
    /// if the peer does not support TLS 1.2.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
    #[cfg(feature = "OSX_10_8")]
    const Tls12 = kTLSProtocol12,
    /// Only the SSL 2.0 protocol is accepted.
    const Ssl2 = kSSLProtocol2,
    /// The DTLSv1 protocol is preferred.
    #[cfg(feature = "OSX_10_8")]
    const Dtls1 = kDTLSProtocol1,
    /// Only the SSL 3.0 protocol is accepted.
    const Ssl3Only = kSSLProtocol3Only,
    /// Only the TLS 1.0 protocol is accepted.
    const Tls1Only = kTLSProtocol1Only,
    /// All supported TLS/SSL versions are accepted.
    const All = kSSLProtocolAll,
}

/// A Secure Transport SSL/TLS context object.
///
/// `SslContext` implements `TCFType` if the `OSX_10_8` (or greater) feature is
/// enabled.
pub struct SslContext(SSLContextRef);

impl Drop for SslContext {
    #[cfg(not(any(feature = "OSX_10_8", target_os = "ios")))]
    fn drop(&mut self) {
        unsafe {
            SSLDisposeContext(self.0);
        }
    }

    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.as_CFTypeRef());
        }
    }
}

#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
impl_TCFType!(SslContext, SSLContextRef, SSLContextGetTypeID);

impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("SslContext");
        if let Ok(state) = self.state() {
            builder.field("state", &state);
        }
        builder.finish()
    }
}

unsafe impl Sync for SslContext {}
unsafe impl Send for SslContext {}

impl AsInner for SslContext {
    type Inner = SSLContextRef;

    fn as_inner(&self) -> SSLContextRef {
        self.0
    }
}

macro_rules! impl_options {
    ($($(#[$a:meta])* const $opt:ident: $get:ident & $set:ident,)*) => {
        $(
            $(#[$a])*
            pub fn $set(&mut self, value: bool) -> Result<()> {
                unsafe { cvt(SSLSetSessionOption(self.0, $opt, value as Boolean)) }
            }

            $(#[$a])*
            pub fn $get(&self) -> Result<bool> {
                let mut value = 0;
                unsafe { try!(cvt(SSLGetSessionOption(self.0, $opt, &mut value))); }
                Ok(value != 0)
            }
        )*
    }
}

impl SslContext {
    /// Creates a new `SslContext` for the specified side and type of SSL
    /// connection.
    pub fn new(side: ProtocolSide, type_: ConnectionType) -> Result<SslContext> {
        SslContext::new_inner(side, type_)
    }

    #[cfg(not(any(feature = "OSX_10_8", target_os = "ios")))]
    fn new_inner(side: ProtocolSide, _: ConnectionType) -> Result<SslContext> {
        unsafe {
            let is_server = match side {
                ProtocolSide::Server => 1,
                ProtocolSide::Client => 0,
            };

            let mut ctx = ptr::null_mut();
            try!(cvt(SSLNewContext(is_server, &mut ctx)));
            Ok(SslContext(ctx))
        }
    }

    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    fn new_inner(side: ProtocolSide, type_: ConnectionType) -> Result<SslContext> {
        let side = match side {
            ProtocolSide::Server => kSSLServerSide,
            ProtocolSide::Client => kSSLClientSide,
        };

        let type_ = match type_ {
            ConnectionType::Stream => kSSLStreamType,
            #[cfg(feature = "OSX_10_8")]
            ConnectionType::Datagram => kSSLDatagramType,
        };

        unsafe {
            let ctx = SSLCreateContext(kCFAllocatorDefault, side, type_);
            Ok(SslContext(ctx))
        }
    }

    /// Sets the fully qualified domain name of the peer.
    ///
    /// This will be used on the client side of a session to validate the
    /// common name field of the server's certificate. It has no effect if
    /// called on a server-side `SslContext`.
    ///
    /// It is *highly* recommended to call this method before starting the
    /// handshake process.
    pub fn set_peer_domain_name(&mut self, peer_name: &str) -> Result<()> {
        unsafe {
            // SSLSetPeerDomainName doesn't need a null terminated string
            cvt(SSLSetPeerDomainName(self.0, peer_name.as_ptr() as *const _, peer_name.len()))
        }
    }

    /// Returns the peer domain name set by `set_peer_domain_name`.
    pub fn peer_domain_name(&self) -> Result<String> {
        unsafe {
            let mut len = 0;
            try!(cvt(SSLGetPeerDomainNameLength(self.0, &mut len)));
            let mut buf = vec![0; len];
            try!(cvt(SSLGetPeerDomainName(self.0, buf.as_mut_ptr() as *mut _, &mut len)));
            Ok(String::from_utf8(buf).unwrap())
        }
    }

    /// Sets the certificate to be used by this side of the SSL session.
    ///
    /// This must be called before the handshake for server-side connections,
    /// and can be used on the client-side to specify a client certificate.
    ///
    /// The `identity` corresponds to the leaf certificate and private
    /// key, and the `certs` correspond to extra certificates in the chain.
    pub fn set_certificate(&mut self,
                           identity: &SecIdentity,
                           certs: &[SecCertificate])
                           -> Result<()> {
        let mut arr = vec![identity.as_CFType()];
        arr.extend(certs.iter().map(|c| c.as_CFType()));
        let certs = CFArray::from_CFTypes(&arr);

        unsafe { cvt(SSLSetCertificate(self.0, certs.as_concrete_TypeRef())) }
    }

    /// Sets the peer ID of this session.
    ///
    /// A peer ID is an opaque sequence of bytes that will be used by Secure
    /// Transport to identify the peer of an SSL session. If the peer ID of
    /// this session matches that of a previously terminated session, the
    /// previous session can be resumed without requiring a full handshake.
    pub fn set_peer_id(&mut self, peer_id: &[u8]) -> Result<()> {
        unsafe { cvt(SSLSetPeerID(self.0, peer_id.as_ptr() as *const _, peer_id.len())) }
    }

    /// Returns the peer ID of this session.
    pub fn peer_id(&self) -> Result<Option<&[u8]>> {
        unsafe {
            let mut ptr = ptr::null();
            let mut len = 0;
            try!(cvt(SSLGetPeerID(self.0, &mut ptr, &mut len)));
            if ptr.is_null() {
                Ok(None)
            } else {
                Ok(Some(slice::from_raw_parts(ptr as *const _, len)))
            }
        }
    }

    /// Returns the list of ciphers that are supported by Secure Transport.
    pub fn supported_ciphers(&self) -> Result<Vec<CipherSuite>> {
        unsafe {
            let mut num_ciphers = 0;
            try!(cvt(SSLGetNumberSupportedCiphers(self.0, &mut num_ciphers)));
            let mut ciphers = vec![0; num_ciphers];
            try!(cvt(SSLGetSupportedCiphers(self.0, ciphers.as_mut_ptr(), &mut num_ciphers)));
            Ok(ciphers.iter().map(|c| CipherSuite::from_raw(*c).unwrap()).collect())
        }
    }

    /// Returns the list of ciphers that are eligible to be used for
    /// negotiation.
    pub fn enabled_ciphers(&self) -> Result<Vec<CipherSuite>> {
        unsafe {
            let mut num_ciphers = 0;
            try!(cvt(SSLGetNumberEnabledCiphers(self.0, &mut num_ciphers)));
            let mut ciphers = vec![0; num_ciphers];
            try!(cvt(SSLGetEnabledCiphers(self.0, ciphers.as_mut_ptr(), &mut num_ciphers)));
            Ok(ciphers.iter().map(|c| CipherSuite::from_raw(*c).unwrap()).collect())
        }
    }

    /// Sets the list of ciphers that are eligible to be used for negotiation.
    pub fn set_enabled_ciphers(&mut self, ciphers: &[CipherSuite]) -> Result<()> {
        let ciphers = ciphers.iter().map(|c| c.to_raw()).collect::<Vec<_>>();
        unsafe { cvt(SSLSetEnabledCiphers(self.0, ciphers.as_ptr(), ciphers.len())) }
    }

    /// Returns the cipher being used by the session.
    pub fn negotiated_cipher(&self) -> Result<CipherSuite> {
        unsafe {
            let mut cipher = 0;
            try!(cvt(SSLGetNegotiatedCipher(self.0, &mut cipher)));
            Ok(CipherSuite::from_raw(cipher).unwrap())
        }
    }

    /// Sets the requirements for client certificates.
    ///
    /// Should only be called on server-side sessions.
    pub fn set_client_side_authenticate(&mut self, auth: SslAuthenticate) -> Result<()> {
        let auth = match auth {
            SslAuthenticate::Never => kNeverAuthenticate,
            SslAuthenticate::Always => kAlwaysAuthenticate,
            SslAuthenticate::Try => kTryAuthenticate,
        };

        unsafe { cvt(SSLSetClientSideAuthenticate(self.0, auth)) }
    }

    /// Returns the state of client certificate processing.
    pub fn client_certificate_state(&self) -> Result<SslClientCertificateState> {
        let mut state = 0;

        unsafe {
            try!(cvt(SSLGetClientCertificateState(self.0, &mut state)));
        }

        let state = match state {
            kSSLClientCertNone => SslClientCertificateState::None,
            kSSLClientCertRequested => SslClientCertificateState::Requested,
            kSSLClientCertSent => SslClientCertificateState::Sent,
            kSSLClientCertRejected => SslClientCertificateState::Rejected,
            _ => panic!("got invalid client cert state {}", state),
        };
        Ok(state)
    }

    /// Returns the `SecTrust` object corresponding to the peer.
    ///
    /// This can be used in conjunction with `set_break_on_server_auth` to
    /// validate certificates which do not have roots in the default set.
    pub fn peer_trust(&self) -> Result<SecTrust> {
        // Calling SSLCopyPeerTrust on an idle connection does not seem to be well defined,
        // so explicitly check for that
        if let SessionState::Idle = try!(self.state()) {
            return Err(Error::new(errSecBadReq));
        }

        unsafe {
            let mut trust = ptr::null_mut();
            try!(cvt(SSLCopyPeerTrust(self.0, &mut trust)));
            Ok(SecTrust::wrap_under_create_rule(trust))
        }
    }

    /// Returns the state of the session.
    pub fn state(&self) -> Result<SessionState> {
        unsafe {
            let mut state = 0;
            try!(cvt(SSLGetSessionState(self.0, &mut state)));
            Ok(SessionState::from_raw(state))
        }
    }

    /// Returns the protocol version being used by the session.
    pub fn negotiated_protocol_version(&self) -> Result<SslProtocol> {
        unsafe {
            let mut version = 0;
            try!(cvt(SSLGetNegotiatedProtocolVersion(self.0, &mut version)));
            Ok(SslProtocol::from_raw(version))
        }
    }

    /// Returns the maximum protocol version allowed by the session.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
    #[cfg(feature = "OSX_10_8")]
    pub fn protocol_version_max(&self) -> Result<SslProtocol> {
        unsafe {
            let mut version = 0;
            try!(cvt(SSLGetProtocolVersionMax(self.0, &mut version)));
            Ok(SslProtocol::from_raw(version))
        }
    }

    /// Sets the maximum protocol version allowed by the session.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
    #[cfg(feature = "OSX_10_8")]
    pub fn set_protocol_version_max(&mut self, max_version: SslProtocol) -> Result<()> {
        unsafe { cvt(SSLSetProtocolVersionMax(self.0, max_version.to_raw())) }
    }

    /// Returns the minimum protocol version allowed by the session.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
    #[cfg(feature = "OSX_10_8")]
    pub fn protocol_version_min(&self) -> Result<SslProtocol> {
        unsafe {
            let mut version = 0;
            try!(cvt(SSLGetProtocolVersionMin(self.0, &mut version)));
            Ok(SslProtocol::from_raw(version))
        }
    }

    /// Sets the minimum protocol version allowed by the session.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
    #[cfg(feature = "OSX_10_8")]
    pub fn set_protocol_version_min(&mut self, min_version: SslProtocol) -> Result<()> {
        unsafe { cvt(SSLSetProtocolVersionMin(self.0, min_version.to_raw())) }
    }

    /// Returns the number of bytes which can be read without triggering a
    /// `read` call in the underlying stream.
    pub fn buffered_read_size(&self) -> Result<usize> {
        unsafe {
            let mut size = 0;
            try!(cvt(SSLGetBufferedReadSize(self.0, &mut size)));
            Ok(size)
        }
    }

    impl_options! {
    /// If enabled, the handshake process will pause and return instead of
    /// automatically validating a server's certificate.
        const kSSLSessionOptionBreakOnServerAuth: break_on_server_auth & set_break_on_server_auth,
    /// If enabled, the handshake process will pause and return after
    /// the server requests a certificate from the client.
        const kSSLSessionOptionBreakOnCertRequested: break_on_cert_requested & set_break_on_cert_requested,
    /// If enabled, the handshake process will pause and return instead of
    /// automatically validating a client's certificate.
    ///
    /// Requires the `OSX_10_8` (or greater) feature.
        #[cfg(feature = "OSX_10_8")]
        const kSSLSessionOptionBreakOnClientAuth: break_on_client_auth & set_break_on_client_auth,
    /// If enabled, TLS false start will be performed if an appropriate
    /// cipher suite is negotiated.
    ///
    /// Requires the `OSX_10_9` (or greater) feature.
        #[cfg(feature = "OSX_10_9")]
        const kSSLSessionOptionFalseStart: false_start & set_false_start,
    /// If enabled, 1/n-1 record splitting will be enabled for TLS 1.0
    /// connections using block ciphers to mitigate the BEAST attack.
    ///
    /// Requires the `OSX_10_9` (or greater) feature.
        #[cfg(feature = "OSX_10_9")]
        const kSSLSessionOptionSendOneByteRecord: send_one_byte_record & set_send_one_byte_record,
    }

    /// Performs the SSL/TLS handshake.
    pub fn handshake<S>(self, stream: S) -> result::Result<SslStream<S>, HandshakeError<S>>
        where S: Read + Write
    {
        unsafe {
            let ret = SSLSetIOFuncs(self.0, read_func::<S>, write_func::<S>);
            if ret != errSecSuccess {
                return Err(HandshakeError::Failure(Error::new(ret)));
            }

            let stream = Connection {
                stream: stream,
                err: None,
                panic: None,
            };
            let stream = Box::into_raw(Box::new(stream));
            let ret = SSLSetConnection(self.0, stream as *mut _);
            if ret != errSecSuccess {
                let _conn = Box::from_raw(stream);
                return Err(HandshakeError::Failure(Error::new(ret)));
            }

            let stream = SslStream {
                ctx: self,
                _m: PhantomData,
            };
            stream.handshake()
        }
    }
}

struct Connection<S> {
    stream: S,
    err: Option<io::Error>,
    panic: Option<Box<Any + Send>>,
}

#[cfg(feature = "nightly")]
fn catch_unwind<F, T>(f: F) -> ::std::result::Result<T, Box<Any + Send>>
    where F: FnOnce() -> T
{
    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(f))
}

#[cfg(not(feature = "nightly"))]
fn catch_unwind<F, T>(f: F) -> ::std::result::Result<T, Box<Any + Send>>
    where F: FnOnce() -> T
{
    Ok(f())
}

// the logic here is based off of libcurl's

fn translate_err(e: &io::Error) -> OSStatus {
    println!("{}", e);
    match e.kind() {
        io::ErrorKind::NotFound => errSSLClosedGraceful,
        io::ErrorKind::ConnectionReset => errSSLClosedAbort,
        io::ErrorKind::WouldBlock => errSSLWouldBlock,
        _ => errSecIO,
    }
}

unsafe extern "C" fn read_func<S: Read>(connection: SSLConnectionRef,
                                        data: *mut c_void,
                                        data_length: *mut size_t)
                                        -> OSStatus {
    let mut conn: &mut Connection<S> = mem::transmute(connection);
    let data = slice::from_raw_parts_mut(data as *mut u8, *data_length);
    let mut start = 0;
    let mut ret = errSecSuccess;

    while start < data.len() {
        match catch_unwind(|| conn.stream.read(&mut data[start..])) {
            Ok(Ok(0)) => {
                ret = errSSLClosedNoNotify;
                break;
            }
            Ok(Ok(len)) => start += len,
            Ok(Err(e)) => {
                ret = translate_err(&e);
                conn.err = Some(e);
                break;
            }
            Err(e) => {
                ret = errSecIO;
                conn.panic = Some(e);
                break;
            }
        }
    }

    *data_length = start;
    ret
}

unsafe extern "C" fn write_func<S: Write>(connection: SSLConnectionRef,
                                          data: *const c_void,
                                          data_length: *mut size_t)
                                          -> OSStatus {
    let mut conn: &mut Connection<S> = mem::transmute(connection);
    let data = slice::from_raw_parts(data as *mut u8, *data_length);
    let mut start = 0;
    let mut ret = errSecSuccess;

    while start < data.len() {
        match catch_unwind(|| conn.stream.write(&data[start..])) {
            Ok(Ok(0)) => {
                ret = errSSLClosedNoNotify;
                break;
            }
            Ok(Ok(len)) => start += len,
            Ok(Err(e)) => {
                ret = translate_err(&e);
                conn.err = Some(e);
                break;
            }
            Err(e) => {
                ret = errSecIO;
                conn.panic = Some(e);
                break;
            }
        }
    }

    *data_length = start;
    ret
}

#[cfg(feature = "nightly")]
use std::panic::resume_unwind;

#[cfg(not(feature = "nightly"))]
use std::mem::drop as resume_unwind;

/// A type implementing SSL/TLS encryption over an underlying stream.
pub struct SslStream<S> {
    ctx: SslContext,
    _m: PhantomData<S>,
}

impl<S: fmt::Debug> fmt::Debug for SslStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SslStream")
           .field("context", &self.ctx)
           .field("stream", self.get_ref())
           .finish()
    }
}

impl<S> Drop for SslStream<S> {
    fn drop(&mut self) {
        unsafe {
            SSLClose(self.ctx.0);

            let mut conn = ptr::null();
            let ret = SSLGetConnection(self.ctx.0, &mut conn);
            assert!(ret == errSecSuccess);
            Box::<Connection<S>>::from_raw(conn as *mut _);
        }
    }
}

impl<S> SslStream<S> {
    fn handshake(mut self) -> result::Result<SslStream<S>, HandshakeError<S>> {
        match unsafe { SSLHandshake(self.ctx.0) } {
            errSecSuccess => Ok(self),
            reason @ errSSLPeerAuthCompleted |
            reason @ errSSLClientCertRequested |
            reason @ errSSLWouldBlock |
            reason @ errSSLClientHelloReceived => {
                Err(HandshakeError::Interrupted(MidHandshakeSslStream {
                    stream: self,
                    reason: reason,
                }))
            }
            err => {
                self.check_panic();
                Err(HandshakeError::Failure(Error::new(err)))
            }
        }
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.connection().stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.connection_mut().stream
    }

    /// Returns a shared reference to the `SslContext` of the stream.
    pub fn context(&self) -> &SslContext {
        &self.ctx
    }

    /// Returns a mutable reference to the `SslContext` of the stream.
    pub fn context_mut(&mut self) -> &mut SslContext {
        &mut self.ctx
    }

    fn connection(&self) -> &Connection<S> {
        unsafe {
            let mut conn = ptr::null();
            let ret = SSLGetConnection(self.ctx.0, &mut conn);
            assert!(ret == errSecSuccess);

            mem::transmute(conn)
        }
    }

    fn connection_mut(&mut self) -> &mut Connection<S> {
        unsafe {
            let mut conn = ptr::null();
            let ret = SSLGetConnection(self.ctx.0, &mut conn);
            assert!(ret == errSecSuccess);

            mem::transmute(conn)
        }
    }

    fn check_panic(&mut self) {
        let conn = self.connection_mut();
        if let Some(err) = conn.panic.take() {
            resume_unwind(err);
        }
    }

    fn get_error(&mut self, ret: OSStatus) -> io::Error {
        self.check_panic();

        if let Some(err) = self.connection_mut().err.take() {
            err
        } else {
            io::Error::new(io::ErrorKind::Other, Error::new(ret))
        }
    }
}

impl<S: Read + Write> Read for SslStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut nread = 0;
            let ret = SSLRead(self.ctx.0,
                              buf.as_mut_ptr() as *mut _,
                              buf.len(),
                              &mut nread);
            // SSLRead can return an error at the same time it returns the last
            // chunk of data (!)
            if nread > 0 {
                return Ok(nread as usize);
            }

            match ret {
                errSSLClosedGraceful |
                errSSLClosedAbort |
                errSSLClosedNoNotify => Ok(0),
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
                               buf.len(),
                               &mut nwritten);
            // just to be safe, base success off of nwritten rather than ret
            // for the same reason as in read
            if nwritten > 0 {
                Ok(nwritten as usize)
            } else {
                Err(self.get_error(ret))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.connection_mut().stream.flush()
    }
}

/// A builder type to simplify the creation of client side `SslStream`s.
#[derive(Debug)]
pub struct ClientBuilder {
    certs: Option<Vec<SecCertificate>>,
}

impl Default for ClientBuilder {
    fn default() -> ClientBuilder {
        ClientBuilder::new()
    }
}

impl ClientBuilder {
    /// Creates a new builder with default options.
    pub fn new() -> Self {
        ClientBuilder { certs: None }
    }

    /// Specifies the set of additional root certificates to trust when
    /// verifying the server's certificate.
    pub fn anchor_certificates(&mut self, certs: &[SecCertificate]) -> &mut Self {
        self.certs = Some(certs.to_owned());
        self
    }

    /// Initiates a new SSL/TLS session over a stream connected to the specified
    /// domain.
    pub fn handshake<S>(&self, domain: &str, stream: S) -> Result<SslStream<S>>
        where S: Read + Write
    {
        let mut ctx = try!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        try!(ctx.set_peer_domain_name(domain));

        if self.certs.is_some() {
            try!(ctx.set_break_on_server_auth(true));
        }

        let mut result = ctx.handshake(stream);
        loop {
            match result {
                Ok(stream) => return Ok(stream),
                Err(HandshakeError::Interrupted(stream)) => {
                    if stream.server_auth_completed() {
                        if let Some(ref certs) = self.certs {
                            let mut trust = try!(stream.context().peer_trust());
                            try!(trust.set_anchor_certificates(certs));
                            let trusted = try!(trust.evaluate());
                            match trusted {
                                TrustResult::Invalid |
                                TrustResult::OtherError => return Err(Error::new(errSecBadReq)),
                                TrustResult::Proceed | TrustResult::Unspecified => {}
                                TrustResult::Deny => return Err(Error::new(errSecTrustSettingDeny)),
                                TrustResult::RecoverableTrustFailure |
                                TrustResult::FatalTrustFailure => {
                                    return Err(Error::new(errSecNotTrusted));
                                }
                            }
                        } else {
                            return Err(Error::new(stream.reason()));
                        }
                    } else {
                        return Err(Error::new(stream.reason()));
                    }

                    result = stream.handshake();
                }
                Err(HandshakeError::Failure(err)) => return Err(err),
            }
        }
    }
}

/// A builder type to simplify the creation of server-side `SslStream`s.
#[derive(Debug)]
pub struct ServerBuilder {
    identity: SecIdentity,
    certs: Vec<SecCertificate>,
}

impl ServerBuilder {
    /// Creates a new `ServerBuilder` which will use the specified identity
    /// and certificate chain for handshakes.
    pub fn new(identity: &SecIdentity, certs: &[SecCertificate]) -> ServerBuilder {
        ServerBuilder {
            identity: identity.clone(),
            certs: certs.to_owned(),
        }
    }

    /// Initiates a new SSL/TLS session over a stream.
    pub fn handshake<S>(&self, stream: S) -> Result<SslStream<S>>
        where S: Read + Write
    {
        let mut ctx = try!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        try!(ctx.set_certificate(&self.identity, &self.certs));
        match ctx.handshake(stream) {
            Ok(stream) => Ok(stream),
            Err(HandshakeError::Interrupted(stream)) => Err(Error::new(stream.reason())),
            Err(HandshakeError::Failure(err)) => Err(err),
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "nightly")]
    use std::io;
    use std::io::prelude::*;
    use std::net::TcpStream;

    use super::*;

    #[test]
    fn connect() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_peer_domain_name("google.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        p!(ctx.handshake(stream));
    }

    #[test]
    fn connect_bad_domain() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_peer_domain_name("foobar.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        match ctx.handshake(stream) {
            Ok(_) => panic!("expected failure"),
            Err(_) => {}
        }
    }

    #[test]
    fn load_page() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_peer_domain_name("google.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        let mut stream = p!(ctx.handshake(stream));
        p!(stream.write_all(b"GET / HTTP/1.0\r\n\r\n"));
        p!(stream.flush());
        let mut buf = vec![];
        p!(stream.read_to_end(&mut buf));
        println!("{}", String::from_utf8_lossy(&buf));
        assert!(buf.starts_with(b"HTTP/1.0 200 OK"));
        assert!(buf.ends_with(b"</html>"));
    }

    #[test]
    fn client_bad_domain() {
        let stream = p!(TcpStream::connect("google.com:443"));
        assert!(ClientBuilder::new().handshake("foobar.com", stream).is_err());
    }

    #[test]
    fn load_page_client() {
        let stream = p!(TcpStream::connect("google.com:443"));
        let mut stream = p!(ClientBuilder::new().handshake("google.com", stream));
        p!(stream.write_all(b"GET / HTTP/1.0\r\n\r\n"));
        p!(stream.flush());
        let mut buf = vec![];
        p!(stream.read_to_end(&mut buf));
        println!("{}", String::from_utf8_lossy(&buf));
        assert!(buf.starts_with(b"HTTP/1.0 200 OK"));
        assert!(buf.ends_with(b"</html>"));
    }

    #[test]
    #[cfg_attr(target = "ios", ignore)] // FIXME what's going on with ios?
    fn cipher_configuration() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        let ciphers = p!(ctx.enabled_ciphers());
        let ciphers = ciphers.iter()
                             .enumerate()
                             .filter_map(|(i, c)| {
                                 if i % 2 == 0 {
                                     Some(*c)
                                 } else {
                                     None
                                 }
                             })
                             .collect::<Vec<_>>();
        p!(ctx.set_enabled_ciphers(&ciphers));
        assert_eq!(ciphers, p!(ctx.enabled_ciphers()));
    }

    #[test]
    fn idle_context_peer_trust() {
        let ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        assert!(ctx.peer_trust().is_err());
    }

    #[test]
    fn peer_id() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Server, ConnectionType::Stream));
        assert!(p!(ctx.peer_id()).is_none());
        p!(ctx.set_peer_id(b"foobar"));
        assert_eq!(p!(ctx.peer_id()), Some(&b"foobar"[..]));
    }

    #[test]
    fn peer_domain_name() {
        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        assert_eq!("", p!(ctx.peer_domain_name()));
        p!(ctx.set_peer_domain_name("foobar.com"));
        assert_eq!("foobar.com", p!(ctx.peer_domain_name()));
    }

    #[test]
    #[should_panic(expected = "blammo")]
    #[cfg(feature = "nightly")]
    fn write_panic() {
        struct ExplodingStream(TcpStream);

        impl Read for ExplodingStream {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
        }

        impl Write for ExplodingStream {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("blammo");
            }

            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_peer_domain_name("google.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        let _ = ctx.handshake(ExplodingStream(stream));
    }

    #[test]
    #[should_panic(expected = "blammo")]
    #[cfg(feature = "nightly")]
    fn read_panic() {
        struct ExplodingStream(TcpStream);

        impl Read for ExplodingStream {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("blammo");
            }
        }

        impl Write for ExplodingStream {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.write(buf)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }

        let mut ctx = p!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
        p!(ctx.set_peer_domain_name("google.com"));
        let stream = p!(TcpStream::connect("google.com:443"));
        let _ = ctx.handshake(ExplodingStream(stream));
    }
}
