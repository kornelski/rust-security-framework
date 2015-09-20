use core_foundation_sys::base::{OSStatus, CFTypeID};
use core_foundation_sys::string::CFStringRef;

use base::{SecCertificateRef, SecKeyRef};

extern {
    pub fn SecCertificateGetTypeID() -> CFTypeID;
    pub fn SecCertificateCopyCommonName(certificate: SecCertificateRef,
                                        common_name: *mut CFStringRef) -> OSStatus;
    pub fn SecCertificateCopyPublicKey(certificate: SecCertificateRef,
                                       key: *mut SecKeyRef) -> OSStatus;
}
