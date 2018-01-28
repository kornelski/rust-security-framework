//! Encryption key support

use core_foundation::base::TCFType;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::key::SecKeyGetTypeID;
use std::fmt;

declare_TCFType! {
    /// A type representing an encryption key.
    SecKey, SecKeyRef
}
impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);

unsafe impl Sync for SecKey {}
unsafe impl Send for SecKey {}

// FIXME
impl fmt::Debug for SecKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}
