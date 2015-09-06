use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::SecIdentityRef;
use security_framework_sys::identity::{SecIdentityGetTypeID};
use std::mem;

pub struct SecIdentity(SecIdentityRef);

impl Drop for SecIdentity {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl_TCFType!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);
