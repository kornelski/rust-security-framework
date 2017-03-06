use core_foundation_sys::base::{CFTypeID, OSStatus};
use base::{SecKeychainItemRef, SecKeychainAttributeList};
use libc::c_void;

extern "C" {
    pub fn SecKeychainItemGetTypeID() -> CFTypeID;

    pub fn SecKeychainItemDelete(itemRef: SecKeychainItemRef) -> OSStatus;

    pub fn SecKeychainItemModifyAttributesAndData(
        itemRef: SecKeychainItemRef,
        attrList: *const SecKeychainAttributeList,
        length: u32,
        data: *const u8)
        -> OSStatus;
    pub fn SecKeychainItemFreeContent(attrList: *const SecKeychainAttributeList,
                                      data: *const c_void)
                                      -> OSStatus;
}
