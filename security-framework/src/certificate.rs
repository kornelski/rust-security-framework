use core_foundation_sys::base::{CFTypeID, CFTypeRef, CFRelease, CFRetain};
use core_foundation::base::TCFType;
use security_framework_sys::base::SecCertificateRef;
use security_framework_sys::certificate::{SecCertificateGetTypeID};

pub struct SecCertificate(SecCertificateRef);

impl Drop for SecCertificate {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl TCFType<SecCertificateRef> for SecCertificate {
    #[inline]
    fn as_concrete_TypeRef(&self) -> SecCertificateRef {
        self.0
    }

    #[inline]
    unsafe fn wrap_under_get_rule(reference: SecCertificateRef) -> SecCertificate {
        CFRetain(reference as *mut _);
        TCFType::wrap_under_create_rule(reference)
    }

    #[inline]
    fn as_CFTypeRef(&self) -> CFTypeRef {
        self.as_concrete_TypeRef() as *mut _
    }

    #[inline]
    unsafe fn wrap_under_create_rule(obj: SecCertificateRef) -> SecCertificate {
        SecCertificate(obj)
    }

    #[inline]
    fn type_id() -> CFTypeID {
        unsafe {
            SecCertificateGetTypeID()
        }
    }
}
