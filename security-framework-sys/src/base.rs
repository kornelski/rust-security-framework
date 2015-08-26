use core_foundation_sys::base::{OSStatus};
use core_foundation_sys::string::CFStringRef;
use libc::c_void;

#[repr(C)]
struct OpaqueSecCertificateRef;

pub type SecCertificateRef = *mut OpaqueSecCertificateRef;

pub const errSecIO: OSStatus = -36;

extern {
    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;
}
