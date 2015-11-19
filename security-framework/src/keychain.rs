use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::SecKeychainRef;
use security_framework_sys::keychain::*;
use std::mem;

pub struct SecKeychain(SecKeychainRef);

impl Drop for SecKeychain {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl Clone for SecKeychain {
    fn clone(&self) -> SecKeychain {
        unsafe {
            SecKeychain::wrap_under_get_rule(self.as_concrete_TypeRef())
        }
    }
}

impl_TCFType!(SecKeychain, SecKeychainRef, SecKeychainGetTypeID);
