use core_foundation_sys::base::{OSStatus, CFTypeID, CFAllocatorRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::string::CFStringRef;

use base::{SecCertificateRef, SecKeyRef};

extern "C" {
    pub fn SecCertificateGetTypeID() -> CFTypeID;
    pub fn SecCertificateCreateWithData(allocator: CFAllocatorRef,
                                        data: CFDataRef)
                                        -> SecCertificateRef;
    pub fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;
    pub fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) -> CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SecCertificateCopyCommonName(certificate: SecCertificateRef,
                                        common_name: *mut CFStringRef)
                                        -> OSStatus;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SecCertificateCopyPublicKey(certificate: SecCertificateRef,
                                       key: *mut SecKeyRef)
                                       -> OSStatus;
}
