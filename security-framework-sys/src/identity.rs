use core_foundation_sys::base::{OSStatus, CFTypeID};

use base::{SecCertificateRef, SecKeyRef, SecIdentityRef};

extern {
    pub fn SecIdentityGetTypeID() -> CFTypeID;
    pub fn SecIdentityCopyCertificate(identity: SecIdentityRef,
                                      certificate_ref: *mut SecCertificateRef) -> OSStatus;
    pub fn SecIdentityCopyPrivateKey(identity: SecIdentityRef,
                                     key_ref: *mut SecKeyRef) -> OSStatus;
}
