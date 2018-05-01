use libc::{c_void, size_t};
use core_foundation_sys::base::OSStatus;

use secure_transport::SSLContextRef;

#[cfg(all(feature = "OSX_10_11", not(feature = "OSX_10_13"), feature = "alpn_use_private_api"))]
pub type SSLALPNFunc = unsafe extern "C" fn(ctx: SSLContextRef,
                                            info: *mut c_void,
                                            alpnData: *const c_void,
                                            alpnDataLength: size_t);

extern "C" {
    #[cfg(all(feature = "OSX_10_11", not(feature = "OSX_10_13"), feature = "alpn_use_private_api"))]
    pub fn SSLSetALPNFunc(context: SSLContextRef,
                          alpnFunc: SSLALPNFunc,
                          info: *mut c_void);
    #[cfg(all(feature = "OSX_10_11", not(feature = "OSX_10_13"), feature = "alpn_use_private_api"))]
    pub fn SSLSetALPNData(context: SSLContextRef,
                          length: size_t) -> OSStatus;
    #[cfg(all(feature = "OSX_10_11", not(feature = "OSX_10_13"), feature = "alpn_use_private_api"))]
    pub fn SSLGetALPNData(context: SSLContextRef,
                          length: *mut size_t) -> *const c_void;
}