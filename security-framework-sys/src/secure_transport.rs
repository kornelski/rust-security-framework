use libc::{c_void, c_char, size_t};
use {Boolean, OSStatus};

pub type SSLContext = c_void;
pub type SSLContextRef = *mut SSLContext;

pub type SSLConnectionRef = *const c_void;

#[repr(C)]
pub enum SSLProtocol {
    kSSLProtocolUnknown = 0,
    kSSLProtocol3 = 2,
    kTLSProtocol1 = 4,
    #[cfg(feature = "OSX_10_8")]
    kTLSProtocol11 = 7,
    #[cfg(feature = "OSX_10_8")]
    kTLSProtocol12 = 8,
    #[cfg(feature = "OSX_10_8")]
    kDTLSProtocol1 = 9,
    kSSLProtocol2 = 1,
    kSSLProtocol3Only = 3,
    kTLSProtocol1Only = 5,
    kSSLProtocolAll = 6,
}

#[repr(C)]
pub enum SSLSessionOption {
    kSSLSessionOptionBreakOnServerAuth = 0,
    kSSLSessionOptionBreakOnCertRequested = 1,
    #[cfg(feature = "OSX_10_8")]
    kSSLSessionOptionBreakOnClientAuth = 2,
    #[cfg(feature = "OSX_10_9")]
    kSSLSessionOptionFalseStart = 3,
    #[cfg(feature = "OSX_10_9")]
    kSSLSessionOptionSendOneByteRecord = 4,
    #[cfg(feature = "OSX_10_10")]
    kSSLSessionOptionFallback = 6,
}

#[repr(C)]
pub enum SSLSessionState {
    kSSLIdle,
    kSSLHandshake,
    kSSLConnected,
    kSSLClosed,
    kSSLAborted,
}

#[repr(C)]
pub enum SSLClientCertificateState {
    kSSLClientCertNone,
    kSSLClientCertRequested,
    kSSLClientCertSent,
    kSSLClientCertRejected
}

pub type SSLReadFunc = extern fn(connection: SSLConnectionRef,
                                 data: *mut c_void,
                                 dataLength: *mut size_t) -> OSStatus;

pub type SSLWriteFunc = extern fn(connection: SSLConnectionRef,
                                  data: *const c_void,
                                  dataLength: *mut size_t) -> OSStatus;

#[repr(C)]
pub enum SSLProtocolSide {
    kSSLServerSide,
    kSSLClientSide,
}

#[repr(C)]
#[cfg(feature = "OSX_10_8")]
pub enum SSLConnectionType {
    kSSLStreamType,
    kSSLDatagramType,
}

pub const errSSLProtocol: OSStatus = -9800;
pub const errSSLWouldBlock: OSStatus = -9803;
pub const errSSLClosedGraceful: OSStatus = -9805;
pub const errSSLClosedAbort: OSStatus = -9806;
pub const errSSLClosedNoNotify: OSStatus = -9816;

extern {
    pub fn SSLNewContext(isServer: Boolean, contextPtr: *mut SSLContextRef) -> OSStatus;
    pub fn SSLDisposeContext(context: SSLContextRef) -> OSStatus;
    pub fn SSLSetConnection(context: SSLContextRef, connection: SSLConnectionRef) -> OSStatus;
    pub fn SSLGetConnection(context: SSLContextRef, connection: *mut SSLConnectionRef) -> OSStatus;
    pub fn SSLSetIOFuncs(context: SSLContextRef, read: SSLReadFunc, write: SSLWriteFunc) -> OSStatus;
    pub fn SSLHandshake(context: SSLContextRef) -> OSStatus;
    pub fn SSLClose(context: SSLContextRef) -> OSStatus;
    pub fn SSLRead(context: SSLContextRef, data: *mut c_void, dataLen: size_t, processed: *mut size_t) -> OSStatus;
    pub fn SSLWrite(context: SSLContextRef, data: *const c_void, dataLen: size_t, processed: *mut size_t) -> OSStatus;
    pub fn SSLSetProtocolVersionMax(context: SSLContextRef, maxVersion: SSLProtocol) -> OSStatus;
    pub fn SSLSetPeerDomainName(context: SSLContextRef, peerName: *const c_char, peerNameLen: size_t) -> OSStatus;
}
