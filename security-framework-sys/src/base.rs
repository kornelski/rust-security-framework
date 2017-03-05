use core_foundation_sys::base::OSStatus;
use core_foundation_sys::string::CFStringRef;
use MacTypes_sys::OSType;
use libc::c_void;

#[repr(C)]
pub struct OpaqueSecKeychainRef(c_void);
pub type SecKeychainRef = *mut OpaqueSecKeychainRef;

#[repr(C)]
pub struct OpaqueSecKeychainItemRef(c_void);
pub type SecKeychainItemRef = *mut OpaqueSecKeychainItemRef;

pub type SecKeychainAttrType = OSType;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SecKeychainAttribute {
    pub tag: SecKeychainAttrType,
    pub length: u32,
    pub data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SecKeychainAttributeList {
    pub count: u32,
    pub attr: *mut SecKeychainAttribute,
}

#[repr(C)]
pub struct OpaqueSecCertificateRef(c_void);
pub type SecCertificateRef = *mut OpaqueSecCertificateRef;

#[repr(C)]
pub struct OpaqueSecAccessRef(c_void);
pub type SecAccessRef = *mut OpaqueSecAccessRef;

#[repr(C)]
pub struct OpaqueSecKeyRef(c_void);
pub type SecKeyRef = *mut OpaqueSecKeyRef;

#[repr(C)]
pub struct OpaqueSecIdentityRef(c_void);
pub type SecIdentityRef = *mut OpaqueSecIdentityRef;

#[repr(C)]
pub struct OpaqueSecPolicyRef(c_void);
pub type SecPolicyRef = *mut OpaqueSecPolicyRef;

pub const errSecSuccess: OSStatus = 0;
pub const errSecIO: OSStatus = -36;
pub const errSecParam: OSStatus = -50;
pub const errSecBadReq: OSStatus = -909;
pub const errSecAuthFailed: OSStatus = -25293;
pub const errSecTrustSettingDeny: OSStatus = -67654;
pub const errSecNotTrusted: OSStatus = -67843;

extern "C" {
    #[cfg(target_os = "macos")]
    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;
}
