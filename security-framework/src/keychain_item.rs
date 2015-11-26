use security_framework_sys::base::SecKeychainItemRef;
use security_framework_sys::keychain_item::SecKeychainItemGetTypeID;
use std::mem;

make_wrapper!(SecKeychainItem, SecKeychainItemRef, SecKeychainItemGetTypeID);
