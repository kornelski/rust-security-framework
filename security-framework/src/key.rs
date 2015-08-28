use core_foundation_sys::base::{CFTypeID, CFTypeRef, CFRelease, CFRetain};
use core_foundation::base::TCFType;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::key::{SecKeyGetTypeID};

pub struct SecKey(SecKeyRef);

impl Drop for SecKey {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl TCFType<SecKeyRef> for SecKey {
    #[inline]
    fn as_concrete_TypeRef(&self) -> SecKeyRef {
        self.0
    }

    #[inline]
    unsafe fn wrap_under_get_rule(reference: SecKeyRef) -> SecKey {
        CFRetain(reference as *mut _);
        TCFType::wrap_under_create_rule(reference)
    }

    #[inline]
    fn as_CFTypeRef(&self) -> CFTypeRef {
        self.as_concrete_TypeRef() as *mut _
    }

    #[inline]
    unsafe fn wrap_under_create_rule(obj: SecKeyRef) -> SecKey {
        SecKey(obj)
    }

    #[inline]
    fn type_id() -> CFTypeID {
        unsafe {
            SecKeyGetTypeID()
        }
    }
}
