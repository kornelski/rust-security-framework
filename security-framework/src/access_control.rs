//! Access Control support.

use std::ptr::{self, null};

use core_foundation::base::{TCFType, CFOptionFlags, kCFAllocatorDefault};
use security_framework_sys::access_control::{SecAccessControlGetTypeID, SecAccessControlCreateWithFlags};
use security_framework_sys::base::{SecAccessControlRef, errSecParam};
use crate::base::{Error, Result};

declare_TCFType! {
    /// A type representing sec access control settings.
    SecAccessControl, SecAccessControlRef
}
impl_TCFType!(
    SecAccessControl,
    SecAccessControlRef,
    SecAccessControlGetTypeID
);

unsafe impl Sync for SecAccessControl {}
unsafe impl Send for SecAccessControl {}

impl SecAccessControl {
    /// Create `AccessControl` object from flags
    pub fn create_with_flags(flags: CFOptionFlags) -> Result<Self> {
        unsafe {
            let access_control = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                null(),
                flags,
                ptr::null_mut(),
            );
            if access_control.is_null() {
                Err(Error::from_code(errSecParam))
            } else {
                Ok(Self::wrap_under_create_rule(access_control))
            }
        }
    }
}
