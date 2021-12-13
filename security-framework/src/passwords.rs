//! Support for generic password entries in the keychain.  Works on both iOS and macOS.
//!
//! If you want the extended keychain facilities only available on macOS, use the
//! version of these functions in the macOS extensions module.

use crate::base::Result;
use crate::{cvt, Error};
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFGetTypeID, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use security_framework_sys::base::{errSecDuplicateItem, errSecParam};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnData,
    kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

/// Set a password for the given service and account.  Either creates a
/// generic password keychain entry or updates the password in an existing entry.
pub fn set_generic_password(service: &str, account: &str, password: &str) -> Result<()> {
    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(password.as_bytes()).as_CFType(),
        ),
    ];
    let params = CFDictionary::from_CFType_pairs(&query);
    let mut ret = std::ptr::null();
    let status = unsafe { SecItemAdd(params.as_concrete_TypeRef(), &mut ret) };
    if status == errSecDuplicateItem {
        let params = CFDictionary::from_CFType_pairs(&query[0..2]);
        let update = CFDictionary::from_CFType_pairs(&query[3..]);
        cvt(unsafe { SecItemUpdate(params.as_concrete_TypeRef(), update.as_concrete_TypeRef()) })
    } else {
        cvt(status)
    }
}

/// Get the password for the given service and account.  Looks for a
/// generic password keychain entry for the service and account.
pub fn get_generic_password(service: &str, account: &str) -> Result<String> {
    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).as_CFType(),
        ),
    ];
    let params = CFDictionary::from_CFType_pairs(&query);
    let mut ret: CFTypeRef = std::ptr::null();
    cvt(unsafe { SecItemCopyMatching(params.as_concrete_TypeRef(), &mut ret) })?;
    let type_id = unsafe { CFGetTypeID(ret) };
    if type_id == CFData::type_id() {
        let val = unsafe { CFData::wrap_under_get_rule(ret as CFDataRef) };
        let mut vec = Vec::new();
        vec.extend_from_slice(val.bytes());
        return Ok(format!("{}", String::from_utf8_lossy(&vec)));
    }
    Err(Error::from_code(errSecParam))
}

/// Delete the generic password keychain entry for the given service and account.
pub fn delete_generic_password(service: &str, account: &str) -> Result<()> {
    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType() },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service).as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account).as_CFType(),
        ),
    ];
    let params = CFDictionary::from_CFType_pairs(&query);
    cvt(unsafe { SecItemDelete(params.as_concrete_TypeRef()) })?;
    Ok(())
}
