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
pub extern "C" fn RustShimSetGenericPassword(
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
///
/// # Safety
/// The `password` argument to this function is a mutable pointer to a CFDataRef.
/// This is an input-output variable, and (as per CF standards) should come in
/// either as nil (a null pointer) or as the address of a CFDataRef whose value is nil.
/// If the input passowrd value is nil, then the password will be looked up
/// and an appropriate status returned, but the password data will not be output.
/// If the input value is non-nil, then the password will be looked up and,
/// if found:
///     1. a new CFData item will be allocated and retained,
///     2. a copy of the password's bytes will be put into the CFData item, and
///     3. the CFDataRef will be reset to refer to the allocated, retained item.
/// Note that the current value of the CFDataRef on input will not be freed, so
/// if you pass in a CFDataRef to get the password it must be a nil reference.
#[no_mangle]
pub unsafe extern "C" fn RustShimCopyGenericPassword(
    service: CFStringRef,
    user: CFStringRef,
    password: *mut CFDataRef,
) -> OSStatus {
    if service.is_null() || user.is_null() {
        return errSecBadReq;
    }
    let service = CFString::wrap_under_get_rule(service).to_string();
    let account = CFString::wrap_under_get_rule(user).to_string();
    match security_framework::passwords::get_generic_password(&service, &account) {
        Ok(bytes) => {
            if !password.is_null() {
                let data = CFData::from_buffer(bytes.as_slice());
                // take an extra retain count to hand to our caller
                CFRetain(data.as_CFTypeRef());
                *password = data.as_concrete_TypeRef();
            }
            errSecSuccess
        }
        Err(err) => err.code(),
    }
}

/// Delete the keychain entry for the given service and account.  If none
/// exists, returns `errSecItemNotFound`.
#[no_mangle]
pub extern "C" fn RustShimDeleteGenericPassword(
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
