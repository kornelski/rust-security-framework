//! Access control functionality.

use security_framework_sys::base::SecAccessRef;
use security_framework_sys::access::SecAccessGetTypeID;

make_wrapper! {
    /// A type representing access control settings.
    struct SecAccess, SecAccessRef, SecAccessGetTypeID
}

unsafe impl Sync for SecAccess {}
unsafe impl Send for SecAccess {}
