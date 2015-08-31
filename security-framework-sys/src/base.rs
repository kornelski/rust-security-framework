use core_foundation_sys::base::{OSStatus};
use core_foundation_sys::string::CFStringRef;
use libc::c_void;

#[repr(C)]
struct OpaqueSecKeychainRef;
pub type SecKeychainRef = *mut OpaqueSecKeychainRef;

#[repr(C)]
struct OpaqueSecCertificateRef;
pub type SecCertificateRef = *mut OpaqueSecCertificateRef;

#[repr(C)]
struct OpaqueSecAccessRef;
pub type SecAccessRef = *mut OpaqueSecAccessRef;

#[repr(C)]
struct OpaqueSecKeyRef;
pub type SecKeyRef = *mut OpaqueSecKeyRef;

#[repr(C)]
struct OpaqueSecIdentityRef;
pub type SecIdentityRef = *mut OpaqueSecIdentityRef;

pub const errSecSuccess: OSStatus = 0;
pub const errSecIO: OSStatus = -36;
pub const errSecBadReq: OSStatus = -909;

extern {
    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;
}
