use core_foundation_sys::base::OSStatus;
use core_foundation_sys::string::CFStringRef;
use libc::c_void;

#[repr(C)]
struct OpaqueSecKeychainRef(c_void);
pub type SecKeychainRef = *mut OpaqueSecKeychainRef;

#[repr(C)]
struct OpaqueSecKeychainItemRef(c_void);
pub type SecKeychainItemRef = *mut OpaqueSecKeychainItemRef;

#[repr(C)]
struct OpaqueSecCertificateRef(c_void);
pub type SecCertificateRef = *mut OpaqueSecCertificateRef;

#[repr(C)]
struct OpaqueSecAccessRef(c_void);
pub type SecAccessRef = *mut OpaqueSecAccessRef;

#[repr(C)]
struct OpaqueSecKeyRef(c_void);
pub type SecKeyRef = *mut OpaqueSecKeyRef;

#[repr(C)]
struct OpaqueSecIdentityRef(c_void);
pub type SecIdentityRef = *mut OpaqueSecIdentityRef;

pub const errSecSuccess: OSStatus = 0;
pub const errSecIO: OSStatus = -36;
pub const errSecParam: OSStatus = -50;
pub const errSecBadReq: OSStatus = -909;

extern {
    #[cfg(target_os = "macos")]
    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;
}
