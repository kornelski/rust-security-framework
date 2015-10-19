use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::key::{SecKeyGetTypeID};
use std::mem;

#[derive(Debug)] // FIXME
pub struct SecKey(SecKeyRef);

impl Drop for SecKey {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);
