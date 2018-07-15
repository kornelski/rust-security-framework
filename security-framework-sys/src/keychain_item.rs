use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::base::{CFTypeID, OSStatus};
use base::{SecKeychainItemRef, SecKeychainAttributeList};
use libc::c_void;

extern "C" {
    pub fn SecKeychainItemGetTypeID() -> CFTypeID;

    pub fn SecKeychainItemDelete(itemRef: SecKeychainItemRef) -> OSStatus;

    pub fn SecItemUpdate(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef) -> OSStatus;

    pub fn SecKeychainItemModifyAttributesAndData(
        itemRef: SecKeychainItemRef,
        attrList: *const SecKeychainAttributeList,
        length: u32,
        data: *const c_void)
        -> OSStatus;

    pub fn SecKeychainItemFreeContent(attrList: *mut SecKeychainAttributeList,
                                      data: *mut c_void)
                                      -> OSStatus;
}
