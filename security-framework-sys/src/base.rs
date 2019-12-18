use core_foundation_sys::base::OSStatus;
use core_foundation_sys::string::CFStringRef;
use std::os::raw::c_void;

pub enum OpaqueSecKeychainRef {}
pub type SecKeychainRef = *mut OpaqueSecKeychainRef;

pub enum OpaqueSecKeychainItemRef {}
pub type SecKeychainItemRef = *mut OpaqueSecKeychainItemRef;

// OSType from MacTypes.h
pub type SecKeychainAttrType = u32;

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

pub enum OpaqueSecCertificateRef {}
pub type SecCertificateRef = *mut OpaqueSecCertificateRef;

pub enum OpaqueSecAccessRef {}
pub type SecAccessRef = *mut OpaqueSecAccessRef;

pub enum OpaqueSecKeyRef {}
pub type SecKeyRef = *mut OpaqueSecKeyRef;

pub enum OpaqueSecIdentityRef {}
pub type SecIdentityRef = *mut OpaqueSecIdentityRef;

pub enum OpaqueSecPolicyRef {}
pub type SecPolicyRef = *mut OpaqueSecPolicyRef;

pub const errSecSuccess: OSStatus = 0;
pub const errSecUnimplemented: OSStatus = -4;
pub const errSecIO: OSStatus = -36;
pub const errSecParam: OSStatus = -50;
pub const errSecBadReq: OSStatus = -909;
pub const errSecAuthFailed: OSStatus = -25293;
pub const errSecConversionError: OSStatus = -67594;
pub const errSecTrustSettingDeny: OSStatus = -67654;
pub const errSecNotTrusted: OSStatus = -67843;
pub const errSecNoTrustSettings: OSStatus = -25263;

extern "C" {
    #[cfg(target_os = "macos")]
    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;
}
