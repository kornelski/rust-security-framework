use core_foundation_sys::base::{OSStatus, CFTypeID};

use base::SecKeychainRef;

extern {
    pub fn SecKeychainGetTypeID() -> CFTypeID;
    pub fn SecKeychainCopyDefault(keychain: *mut SecKeychainRef) -> OSStatus;
}
