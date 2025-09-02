#![allow(unused_imports)]
//! Access functionality.
use core_foundation::base::TCFType;
use core_foundation::{declare_TCFType, impl_TCFType};
use security_framework_sys::access::SecAccessGetTypeID;
use security_framework_sys::base::SecAccessRef;

declare_TCFType! {
    /// A type representing access settings.
    SecAccess, SecAccessRef
}
impl_TCFType!(SecAccess, SecAccessRef, SecAccessGetTypeID);

unsafe impl Sync for SecAccess {}
unsafe impl Send for SecAccess {}
