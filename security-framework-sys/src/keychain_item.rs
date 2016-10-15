use core_foundation_sys::base::{CFTypeID, OSStatus};
use base::SecKeychainItemRef;
use libc::c_void;

extern "C" {
    pub fn SecKeychainItemGetTypeID() -> CFTypeID;

    pub fn SecKeychainItemDelete(itemRef: SecKeychainItemRef) -> OSStatus;

    pub fn SecKeychainItemModifyAttributesAndData(
        itemRef: SecKeychainItemRef,
        // XXX Should be SecKeychainAttributeList
        attrList: *const c_void,
        length: u32,
        data: *const u8)
        -> OSStatus;
}
