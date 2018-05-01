#[cfg(feature = "OSX_10_11")]
pub type SSLALPNFunc = unsafe extern "C" fn(ctx: SSLContextRef,
                                            info: *mut c_void,
                                            alpnData: *const c_void,
                                            alpnDataLength: size_t);

extern "C" {
    #[cfg(feature = "OSX_10_11")]
    pub fn SSLSetALPNFunc(context: SSLContextRef,
                          alpnFunc: SSLALPNFunc,
                          info: *mut c_void);
    #[cfg(feature = "OSX_10_11")]
    pub fn SSLSetALPNData(context: SSLContextRef,
                          length: size_t) -> OSStatus;
    #[cfg(feature = "OSX_10_11")]
    pub fn SSLGetALPNData(context: SSLContextRef,
                          length: *mut size_t) -> *const c_void;
}