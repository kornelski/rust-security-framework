use core_foundation_sys::base::{OSStatus, CFTypeRef};
use libc::{c_char, c_void};

use base::{SecKeychainItemRef, SecKeychainRef};

extern "C" {
    #[cfg(target_os = "macos")]
    pub fn SecKeychainFindGenericPassword(keychainkeychainOrArray: CFTypeRef,
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

    #[cfg(target_os = "macos")]
    // XXX First arg should be a SecKeychainAttributeList.
    pub fn SecKeychainItemFreeContent(attrList: *const c_void,
                                      data: *const c_void)
                                      -> OSStatus;
}
