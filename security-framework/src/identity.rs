use core_foundation_sys::base::{CFTypeID, CFTypeRef, CFRelease, CFRetain};
use core_foundation::base::TCFType;
use security_framework_sys::base::SecIdentityRef;
use security_framework_sys::identity::{SecIdentityGetTypeID};

pub struct SecIdentity(SecIdentityRef);

impl Drop for SecIdentity {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl TCFType<SecIdentityRef> for SecIdentity {
    #[inline]
    fn as_concrete_TypeRef(&self) -> SecIdentityRef {
        self.0
    }

    #[inline]
    unsafe fn wrap_under_get_rule(reference: SecIdentityRef) -> SecIdentity {
        CFRetain(reference as *mut _);
        TCFType::wrap_under_create_rule(reference)
    }

    #[inline]
    fn as_CFTypeRef(&self) -> CFTypeRef {
        self.as_concrete_TypeRef() as *mut _
    }

    #[inline]
    unsafe fn wrap_under_create_rule(obj: SecIdentityRef) -> SecIdentity {
        SecIdentity(obj)
    }

    #[inline]
    fn type_id() -> CFTypeID {
        unsafe {
            SecIdentityGetTypeID()
        }
    }
}
