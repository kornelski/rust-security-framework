//! A C-ABI for the Rust `security-framework` crate callable from iOS code.
//!
//! In order to embed Rust code in an iOS application, you must provide
//! a C-ABI wrapper that can be called into from Objective C or Swift.
//! This wrapper provides that for the Generic Password entries in
//! the security-framework crate, and can be used as a model for
//! wrappers of other public functionality.
//!
//! Since the Core Foundation provides a C-ABI mechanism for using
//! Objective-C memory management, including ARC, and since the
//! keychain API involves transferring objects from the system
//! to the user process, this API uses CF objects for its parameters
//! rather than pure C strings and arrays.
//!
//! There is an accompanying header `iospw.h` in this crate that provides Objective-C
//! annotations for these functions which are needed by the C compiler.
//! For a good overview of the process by which Rust is embedded in
//! an iOS application, see
//! [this article](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html),
//! but be aware that it was written long enough ago that some of the processor
//! architectures it refers to are no longer in use.
use core_foundation::base::{CFRetain, OSStatus, TCFType};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::base::{errSecBadReq, errSecSuccess};

/// Set a generic password for the given service and account.
/// Creates or updates a keychain entry.
#[no_mangle]
pub extern "C" fn RustSecSetGenericPassword(
    service: CFStringRef,
    user: CFStringRef,
    password: CFDataRef,
) -> OSStatus {
    if service.is_null() || user.is_null() || password.is_null() {
        return errSecBadReq;
    }
    let service = unsafe { CFString::wrap_under_get_rule(service) }.to_string();
    let account = unsafe { CFString::wrap_under_get_rule(user) }.to_string();
    let password = unsafe { CFData::wrap_under_get_rule(password) }.to_vec();
    match security_framework::passwords::set_generic_password(&service, &account, &password) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

/// Get the password for the given service and account.  If no keychain entry
/// exists for the service and account, returns `errSecItemNotFound`.
#[no_mangle]
pub extern "C" fn RustSecCopyGenericPassword(
    service: CFStringRef,
    user: CFStringRef,
    password: *mut CFDataRef,
) -> OSStatus {
    if service.is_null() || user.is_null() {
        return errSecBadReq;
    }
    let service = unsafe { CFString::wrap_under_get_rule(service) }.to_string();
    let account = unsafe { CFString::wrap_under_get_rule(user) }.to_string();
    match security_framework::passwords::get_generic_password(&service, &account) {
        Ok(bytes) => {
            if !password.is_null() {
                let data = CFData::from_buffer(bytes.as_slice());
                // take an extra retain count to hand to our caller
                unsafe { CFRetain(data.as_CFTypeRef()) };
                unsafe { *password = data.as_concrete_TypeRef() };
            }
            errSecSuccess
        }
        Err(err) => err.code(),
    }
}

/// Delete the keychain entry for the given service and account.  If none
/// exists, returns `errSecItemNotFound`.
#[no_mangle]
pub extern "C" fn RustSecDeleteGenericPassword(
    service: CFStringRef,
    user: CFStringRef,
) -> OSStatus {
    if service.is_null() || user.is_null() {
        return errSecBadReq;
    }
    let service = unsafe { CFString::wrap_under_get_rule(service) }.to_string();
    let account = unsafe { CFString::wrap_under_get_rule(user) }.to_string();
    match security_framework::passwords::delete_generic_password(&service, &account) {
        Ok(_) => errSecSuccess,
        Err(err) => err.code(),
    }
}
