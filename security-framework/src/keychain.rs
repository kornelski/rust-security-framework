use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::{errSecSuccess, SecKeychainRef};
use security_framework_sys::keychain::*;
use std::ptr;
use std::mem;

use ErrorNew;
use base::{Error, Result};

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

impl SecKeychain {
    pub fn default() -> Result<SecKeychain> {
        unsafe {
            let mut keychain = ptr::null_mut();
            let ret = SecKeychainCopyDefault(&mut keychain);
            if ret != errSecSuccess {
                return Err(Error::new(ret));
            }
            Ok(SecKeychain::wrap_under_create_rule(keychain))
        }
    }
}
