use libc::c_void;
use core_foundation_sys::base::{Boolean, OSStatus, CFTypeID};
use core_foundation_sys::array::CFArrayRef;

pub type SecTrustResultType = u32;

pub const kSecTrustResultInvalid: SecTrustResultType = 0;
pub const kSecTrustResultProceed: SecTrustResultType = 1;
pub const kSecTrustResultDeny: SecTrustResultType = 3;
pub const kSecTrustResultUnspecified: SecTrustResultType = 4;
pub const kSecTrustResultRecoverableTrustFailure: SecTrustResultType = 5;
pub const kSecTrustResultFatalTrustFailure: SecTrustResultType = 6;
pub const kSecTrustResultOtherError: SecTrustResultType = 7;

#[repr(C)]
struct __SecTrust(c_void);

pub type SecTrustRef = *mut __SecTrust;

extern {
    pub fn SecTrustGetTypeID() -> CFTypeID;
    pub fn SecTrustSetAnchorCertificates(trust: SecTrustRef,
                                         anchorCertificates: CFArrayRef)
                                         -> OSStatus;
    pub fn SecTrustSetAnchorCertificatesOnly(trust: SecTrustRef,
                                             anchorCertificatesOnly: Boolean)
                                             -> OSStatus;
    pub fn SecTrustEvaluate(trust: SecTrustRef, result: *mut SecTrustResultType) -> OSStatus;
}
