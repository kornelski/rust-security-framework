use core_foundation_sys::base::{Boolean, CFTypeID};
use core_foundation_sys::string::CFStringRef;

use base::SecPolicyRef;

extern {
    pub fn SecPolicyCreateSSL(server: Boolean, hostname: CFStringRef) -> SecPolicyRef;
    pub fn SecPolicyGetTypeID() -> CFTypeID;
}