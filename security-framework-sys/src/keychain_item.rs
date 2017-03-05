use core_foundation_sys::base::{CFTypeID, OSStatus};
use base::{SecKeychainItemRef, SecKeychainAttributeList};

extern "C" {
    pub fn SecKeychainItemGetTypeID() -> CFTypeID;

    pub fn SecKeychainItemDelete(itemRef: SecKeychainItemRef) -> OSStatus;

    pub fn SecKeychainItemModifyAttributesAndData(
        itemRef: SecKeychainItemRef,
        attrList: *const SecKeychainAttributeList,
        length: u32,
        data: *const u8)
        -> OSStatus;
}
