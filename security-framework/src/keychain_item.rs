//! Keychain item support.

use security_framework_sys::base::SecKeychainItemRef;
use security_framework_sys::keychain_item::SecKeychainItemGetTypeID;
use std::mem;
use std::fmt;

make_wrapper!(SecKeychainItem, SecKeychainItemRef, SecKeychainItemGetTypeID);

// FIXME
impl fmt::Debug for SecKeychainItem {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("SecKeychainItem")
    }
}
