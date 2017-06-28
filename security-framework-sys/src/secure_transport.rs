use libc::{c_void, c_char, size_t, c_int};
use core_foundation_sys::base::{Boolean, OSStatus, CFTypeRef};
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
use core_foundation_sys::base::CFAllocatorRef;
use core_foundation_sys::array::CFArrayRef;

use cipher_suite::SSLCipherSuite;
use trust::SecTrustRef;

pub type SSLContext = c_void;
pub type SSLContextRef = *mut SSLContext;

pub type SSLConnectionRef = *const c_void;

pub type SSLProtocol = c_int;
pub const kSSLProtocolUnknown: SSLProtocol = 0;
pub const kSSLProtocol3: SSLProtocol = 2;
pub const kTLSProtocol1: SSLProtocol = 4;
pub const kTLSProtocol11: SSLProtocol = 7;
pub const kTLSProtocol12: SSLProtocol = 8;
pub const kDTLSProtocol1: SSLProtocol = 9;
pub const kSSLProtocol2: SSLProtocol = 1;
pub const kSSLProtocol3Only: SSLProtocol = 3;
pub const kTLSProtocol1Only: SSLProtocol = 5;
pub const kSSLProtocolAll: SSLProtocol = 6;

pub type SSLSessionOption = c_int;
pub const kSSLSessionOptionBreakOnServerAuth: SSLSessionOption = 0;
pub const kSSLSessionOptionBreakOnCertRequested: SSLSessionOption = 1;
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub const kSSLSessionOptionBreakOnClientAuth: SSLSessionOption = 2;
#[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
pub const kSSLSessionOptionFalseStart: SSLSessionOption = 3;
#[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
pub const kSSLSessionOptionSendOneByteRecord: SSLSessionOption = 4;
#[cfg(all(feature = "OSX_10_11", not(target_os = "ios")))]
pub const kSSLSessionOptionAllowServerIdentityChange: SSLSessionOption = 5;
#[cfg(all(feature = "OSX_10_10", not(target_os = "ios")))]
pub const kSSLSessionOptionFallback: SSLSessionOption = 6;
#[cfg(all(feature = "OSX_10_11", not(target_os = "ios")))]
pub const kSSLSessionOptionBreakOnClientHello: SSLSessionOption = 7;

pub type SSLSessionState = c_int;
pub const kSSLIdle: SSLSessionState = 0;
pub const kSSLHandshake: SSLSessionState = 1;
pub const kSSLConnected: SSLSessionState = 2;
pub const kSSLClosed: SSLSessionState = 3;
pub const kSSLAborted: SSLSessionState = 4;

pub type SSLReadFunc = unsafe extern "C" fn(connection: SSLConnectionRef,
                                            data: *mut c_void,
                                            dataLength: *mut size_t)
                                            -> OSStatus;

pub type SSLWriteFunc = unsafe extern "C" fn(connection: SSLConnectionRef,
                                             data: *const c_void,
                                             dataLength: *mut size_t)
                                             -> OSStatus;

#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub type SSLProtocolSide = c_int;
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub const kSSLServerSide: SSLProtocolSide = 0;
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub const kSSLClientSide: SSLProtocolSide = 1;

#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub type SSLConnectionType = c_int;
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub const kSSLStreamType: SSLConnectionType = 0;
#[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
pub const kSSLDatagramType: SSLConnectionType = 1;

pub const errSSLProtocol: OSStatus = -9800;
pub const errSSLNegotiation: OSStatus = -9801;
pub const errSSLFatalAlert: OSStatus = -9802;
pub const errSSLWouldBlock: OSStatus = -9803;
pub const errSSLSessionNotFound: OSStatus = -9804;
pub const errSSLClosedGraceful: OSStatus = -9805;
pub const errSSLClosedAbort: OSStatus = -9806;
pub const errSSLXCertChainInvalid: OSStatus = -9807;
pub const errSSLBadCert: OSStatus = -9808;
pub const errSSLCrypto: OSStatus = -9809;
pub const errSSLInternal: OSStatus = -9810;
pub const errSSLModuleAttach: OSStatus = -9811;
pub const errSSLUnknownRootCert: OSStatus = -9812;
pub const errSSLNoRootCert: OSStatus = -9813;
pub const errSSLCertExpired: OSStatus = -9814;
pub const errSSLCertNotYetValid: OSStatus = -9815;
pub const errSSLClosedNoNotify: OSStatus = -9816;
pub const errSSLBufferOverflow: OSStatus = -9817;
pub const errSSLBadCipherSuite: OSStatus = -9818;
pub const errSSLPeerUnexpectedMsg: OSStatus = -9819;
pub const errSSLPeerBadRecordMac: OSStatus = -9820;
pub const errSSLPeerDecryptionFail: OSStatus = -9821;
pub const errSSLPeerRecordOverflow: OSStatus = -9822;
pub const errSSLPeerDecompressFail: OSStatus = -9823;
pub const errSSLPeerHandshakeFail: OSStatus = -9824;
pub const errSSLPeerBadCert: OSStatus = -9825;
pub const errSSLPeerUnsupportedCert: OSStatus = -9826;
pub const errSSLPeerCertRevoked: OSStatus = -9827;
pub const errSSLPeerCertExpired: OSStatus = -9828;
pub const errSSLPeerCertUnknown: OSStatus = -9829;
pub const errSSLIllegalParam: OSStatus = -9830;
pub const errSSLPeerUnknownCA: OSStatus = -9831;
pub const errSSLPeerAccessDenied: OSStatus = -9832;
pub const errSSLPeerDecodeError: OSStatus = -9833;
pub const errSSLPeerDecryptError: OSStatus = -9834;
pub const errSSLPeerExportRestriction: OSStatus = -9835;
pub const errSSLPeerProtocolVersion: OSStatus = -9836;
pub const errSSLPeerInsufficientSecurity: OSStatus = -9837;
pub const errSSLPeerInternalError: OSStatus = -9838;
pub const errSSLPeerUserCancelled: OSStatus = -9839;
pub const errSSLPeerNoRenegotiation: OSStatus = -9840;
pub const errSSLPeerAuthCompleted: OSStatus = -9841;
pub const errSSLClientCertRequested: OSStatus = -9842;
pub const errSSLHostNameMismatch: OSStatus = -9843;
pub const errSSLConnectionRefused: OSStatus = -9844;
pub const errSSLDecryptionFail: OSStatus = -9845;
pub const errSSLBadRecordMac: OSStatus = -9846;
pub const errSSLRecordOverflow: OSStatus = -9847;
pub const errSSLBadConfiguration: OSStatus = -9848;
pub const errSSLClientHelloReceived: OSStatus = -9851;

pub type SSLAuthenticate = c_int;
pub const kNeverAuthenticate: SSLAuthenticate = 0;
pub const kAlwaysAuthenticate: SSLAuthenticate = 1;
pub const kTryAuthenticate: SSLAuthenticate = 2;

pub type SSLClientCertificateState = c_int;
pub const kSSLClientCertNone: SSLClientCertificateState = 0;
pub const kSSLClientCertRequested: SSLClientCertificateState = 1;
pub const kSSLClientCertSent: SSLClientCertificateState = 2;
pub const kSSLClientCertRejected: SSLClientCertificateState = 3;

extern "C" {
    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    pub fn SSLContextGetTypeID() -> ::core_foundation_sys::base::CFTypeID;
    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    pub fn SSLCreateContext(alloc: CFAllocatorRef,
                            protocolSide: SSLProtocolSide,
                            connectionType: SSLConnectionType)
                            -> SSLContextRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLNewContext(isServer: Boolean, contextPtr: *mut SSLContextRef) -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLDisposeContext(context: SSLContextRef) -> OSStatus;
    pub fn SSLSetConnection(context: SSLContextRef, connection: SSLConnectionRef) -> OSStatus;
    pub fn SSLGetConnection(context: SSLContextRef, connection: *mut SSLConnectionRef) -> OSStatus;
    pub fn SSLSetIOFuncs(context: SSLContextRef,
                         read: SSLReadFunc,
                         write: SSLWriteFunc)
                         -> OSStatus;
    pub fn SSLHandshake(context: SSLContextRef) -> OSStatus;
    pub fn SSLClose(context: SSLContextRef) -> OSStatus;
    pub fn SSLRead(context: SSLContextRef,
                   data: *mut c_void,
                   dataLen: size_t,
                   processed: *mut size_t)
                   -> OSStatus;
    pub fn SSLWrite(context: SSLContextRef,
                    data: *const c_void,
                    dataLen: size_t,
                    processed: *mut size_t)
                    -> OSStatus;
    pub fn SSLSetPeerDomainName(context: SSLContextRef,
                                peerName: *const c_char,
                                peerNameLen: size_t)
                                -> OSStatus;
    pub fn SSLGetPeerDomainNameLength(context: SSLContextRef,
                                      peerNameLen: *mut size_t)
                                      -> OSStatus;
    pub fn SSLGetPeerDomainName(context: SSLContextRef,
                                peerName: *mut c_char,
                                peerNameLen: *mut size_t)
                                -> OSStatus;
    pub fn SSLSetCertificate(context: SSLContextRef, certRefs: CFArrayRef) -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLSetCertificateAuthorities(context: SSLContextRef,
                                        certificateOrArray: CFTypeRef,
                                        replaceExisting: Boolean)
                                        -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLCopyCertificateAuthorities(context: SSLContextRef,
                                         certificates: *mut CFArrayRef)
                                         -> OSStatus;
    pub fn SSLSetSessionOption(context: SSLContextRef,
                               option: SSLSessionOption,
                               value: Boolean)
                               -> OSStatus;
    pub fn SSLGetSessionOption(context: SSLContextRef,
                               option: SSLSessionOption,
                               value: *mut Boolean)
                               -> OSStatus;
    pub fn SSLCopyPeerTrust(context: SSLContextRef, trust: *mut SecTrustRef) -> OSStatus;
    pub fn SSLGetSessionState(context: SSLContextRef, state: *mut SSLSessionState) -> OSStatus;
    pub fn SSLGetSupportedCiphers(context: SSLContextRef,
                                  ciphers: *mut SSLCipherSuite,
                                  numCiphers: *mut size_t)
                                  -> OSStatus;
    pub fn SSLGetNumberSupportedCiphers(context: SSLContextRef,
                                        numCiphers: *mut size_t)
                                        -> OSStatus;
    pub fn SSLGetEnabledCiphers(context: SSLContextRef,
                                ciphers: *mut SSLCipherSuite,
                                numCiphers: *mut size_t)
                                -> OSStatus;
    pub fn SSLGetNumberEnabledCiphers(context: SSLContextRef, numCiphers: *mut size_t) -> OSStatus;
    pub fn SSLSetEnabledCiphers(context: SSLContextRef,
                                ciphers: *const SSLCipherSuite,
                                numCiphers: size_t)
                                -> OSStatus;
    pub fn SSLGetNegotiatedCipher(context: SSLContextRef, cipher: *mut SSLCipherSuite) -> OSStatus;
    pub fn SSLSetClientSideAuthenticate(context: SSLContextRef, auth: SSLAuthenticate) -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLSetDiffieHellmanParams(context: SSLContextRef,
                                     dhParams: *const c_void,
                                     dhParamsLen: size_t)
                                     -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLGetDiffieHellmanParams(context: SSLContextRef,
                                     dhParams: *mut *const c_void,
                                     dhParamsLen: *mut size_t)
                                     -> OSStatus;
    pub fn SSLSetPeerID(context: SSLContextRef,
                        peerID: *const c_void,
                        peerIDLen: size_t)
                        -> OSStatus;
    pub fn SSLGetPeerID(context: SSLContextRef,
                        peerID: *mut *const c_void,
                        peerIDLen: *mut size_t)
                        -> OSStatus;
    pub fn SSLGetBufferedReadSize(context: SSLContextRef, bufSize: *mut size_t) -> OSStatus;
    pub fn SSLGetClientCertificateState(context: SSLContextRef,
                                        clientState: *mut SSLClientCertificateState)
                                        -> OSStatus;
    pub fn SSLGetNegotiatedProtocolVersion(context: SSLContextRef,
                                           protocol: *mut SSLProtocol)
                                           -> OSStatus;
    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    pub fn SSLGetProtocolVersionMax(context: SSLContextRef,
                                    maxVersion: *mut SSLProtocol)
                                    -> OSStatus;
    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    pub fn SSLGetProtocolVersionMin(context: SSLContextRef,
                                    minVersion: *mut SSLProtocol)
                                    -> OSStatus;
    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    pub fn SSLSetProtocolVersionMax(context: SSLContextRef, maxVersion: SSLProtocol) -> OSStatus;
    #[cfg(any(feature = "OSX_10_8", target_os = "ios"))]
    pub fn SSLSetProtocolVersionMin(context: SSLContextRef, minVersion: SSLProtocol) -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SSLSetProtocolVersionEnabled(context: SSLContextRef,
                                        protocol: SSLProtocol,
                                        enable: Boolean) -> OSStatus;
}
