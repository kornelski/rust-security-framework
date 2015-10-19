use core_foundation_sys::base::{Boolean, OSStatus, CFTypeID};
use libc::{c_char, c_void};

use base::{SecAccessRef, SecKeychainRef};

extern {
    pub fn SecKeychainGetTypeID() -> CFTypeID;
    pub fn SecKeychainCopyDefault(keychain: *mut SecKeychainRef) -> OSStatus;
    pub fn SecKeychainCreate(pathName: *const c_char,
                             passwordLength: u32,
                             password: *const c_void,
                             promptUser: Boolean,
                             initialAccess: SecAccessRef,
                             keychain: *mut SecKeychainRef) -> OSStatus;
    pub fn SecKeychainOpen(pathName: *const c_char, keychain: *mut SecKeychainRef) -> OSStatus;
    pub fn SecKeychainUnlock(keychain: SecKeychainRef,
                             passwordLength: u32,
                             password: *const c_void,
                             usePassword: Boolean) -> OSStatus;
}
