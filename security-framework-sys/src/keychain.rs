use core_foundation_sys::base::{Boolean, OSStatus, CFTypeID, CFTypeRef};
use libc::{c_char, c_void};

use base::{SecAccessRef, SecKeychainRef, SecKeychainItemRef};

pub const SEC_KEYCHAIN_SETTINGS_VERS1: u32 = 1;

#[repr(C)]
pub struct SecKeychainSettings {
    pub version: u32,
    pub lockOnSleep: Boolean,
    pub useLockInterval: Boolean,
    pub lockInterval: u32,
}

extern "C" {
    pub fn SecKeychainGetTypeID() -> CFTypeID;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainCopyDefault(keychain: *mut SecKeychainRef) -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainCreate(pathName: *const c_char,
                             passwordLength: u32,
                             password: *const c_void,
                             promptUser: Boolean,
                             initialAccess: SecAccessRef,
                             keychain: *mut SecKeychainRef)
                             -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainOpen(pathName: *const c_char, keychain: *mut SecKeychainRef) -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainUnlock(keychain: SecKeychainRef,
                             passwordLength: u32,
                             password: *const c_void,
                             usePassword: Boolean)
                             -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainSetSettings(keychain: SecKeychainRef, newSettings: *const SecKeychainSettings) -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainFindGenericPassword(keychainOrArray: CFTypeRef,
                                          serviceNameLength: u32,
                                          serviceName: *const c_char,
                                          accountNameLength: u32,
                                          accountName: *const c_char,
                                          passwordLength: *mut u32,
                                          passwordData: *mut *mut u8,
                                          itemRef: *mut SecKeychainItemRef)
                                          -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainAddGenericPassword(keychain: SecKeychainRef,
                                         serviceNameLength: u32,
                                         serviceName: *const c_char,
                                         accountNameLength: u32,
                                         accountName: *const c_char,
                                         passwordLength: u32,
                                         passwordData: *const u8,
                                         itemRef: *mut SecKeychainItemRef)
                                         -> OSStatus;
}
