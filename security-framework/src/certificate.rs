use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::SecCertificateRef;
use security_framework_sys::certificate::*;
use std::mem;

#[derive(Debug)] // FIXME
pub struct SecCertificate(SecCertificateRef);

impl Drop for SecCertificate {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);
