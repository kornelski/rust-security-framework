use core_foundation_sys::{
    base::{CFTypeID, OSStatus},
    dictionary::CFDictionaryRef,
    string::CFStringRef,
    url::CFURLRef,
};

pub enum OpaqueSecRequirementRef {}
pub type SecRequirementRef = *mut OpaqueSecRequirementRef;

pub enum OpaqueSecCodeRef {}
pub type SecCodeRef = *mut OpaqueSecCodeRef;

pub enum OpaqueSecStaticCodeRef {}
pub type SecStaticCodeRef = *mut OpaqueSecStaticCodeRef;

pub type SecCSFlags = u32;
pub const kSecCSConsiderExpiration: SecCSFlags = 1 << 31;
pub const kSecCSEnforceRevocationChecks: SecCSFlags = 1 << 30;
pub const kSecCSNoNetworkAccess: SecCSFlags = 1 << 29;
pub const kSecCSReportProgress: SecCSFlags = 1 << 28;
pub const kSecCSCheckTrustedAnchors: SecCSFlags = 1 << 27;
pub const kSecCSQuickCheck: SecCSFlags = 1 << 26;

extern "C" {
    pub static kSecGuestAttributeArchitecture: CFStringRef;
    pub static kSecGuestAttributeAudit: CFStringRef;
    pub static kSecGuestAttributeCanonical: CFStringRef;
    pub static kSecGuestAttributeDynamicCode: CFStringRef;
    pub static kSecGuestAttributeDynamicCodeInfoPlist: CFStringRef;
    pub static kSecGuestAttributeHash: CFStringRef;
    pub static kSecGuestAttributeMachPort: CFStringRef;
    pub static kSecGuestAttributePid: CFStringRef;
    pub static kSecGuestAttributeSubarchitecture: CFStringRef;

    pub fn SecCodeGetTypeID() -> CFTypeID;
    pub fn SecStaticCodeGetTypeID() -> CFTypeID;
    pub fn SecRequirementGetTypeID() -> CFTypeID;

    pub fn SecCodeCheckValidity(
        code: SecCodeRef,
        flags: SecCSFlags,
        requirement: SecRequirementRef,
    ) -> OSStatus;

    pub fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attrs: CFDictionaryRef,
        flags: SecCSFlags,
        guest: *mut SecCodeRef,
    ) -> OSStatus;

    pub fn SecCodeCopyPath(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        path: *mut CFURLRef,
    ) -> OSStatus;

    pub fn SecCodeCopySelf(flags: SecCSFlags, out: *mut SecCodeRef) -> OSStatus;

    pub fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: SecCSFlags,
        requirement: *mut SecRequirementRef,
    ) -> OSStatus;

    pub fn SecStaticCodeCheckValidity(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        requirement: SecRequirementRef,
    ) -> OSStatus;

    pub fn SecStaticCodeCreateWithPath(
        path: CFURLRef,
        flags: SecCSFlags,
        code: *mut SecStaticCodeRef,
    ) -> OSStatus;
}
