use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::SecAccessRef;
use security_framework_sys::access::SecAccessGetTypeID;
use std::mem;

pub struct SecAccess(SecAccessRef);

impl Drop for SecAccess {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.0 as *mut _);
        }
    }
}

impl_TCFType!(SecAccess, SecAccessRef, SecAccessGetTypeID);
