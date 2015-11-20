use core_foundation::base::TCFType;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::key::SecKeyGetTypeID;
use std::mem;
use std::fmt;

make_wrapper!(SecKey, SecKeyRef, SecKeyGetTypeID);

// FIXME
impl fmt::Debug for SecKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}
