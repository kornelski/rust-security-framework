//! Encryption key support

use security_framework_sys::base::SecKeyRef;
use security_framework_sys::key::SecKeyGetTypeID;
use std::fmt;

make_wrapper! {
    /// A type representing an encryption key.
    struct SecKey, SecKeyRef, SecKeyGetTypeID
}

unsafe impl Sync for SecKey {}
unsafe impl Send for SecKey {}

// FIXME
impl fmt::Debug for SecKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}
