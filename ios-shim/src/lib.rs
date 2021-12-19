use core_foundation::base::{CFRetain, OSStatus, TCFType};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::base::{errSecBadReq, errSecSuccess};

#[no_mangle]
pub extern "C" fn SecSetGenericPassword(
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

#[no_mangle]
pub extern "C" fn SecCopyGenericPassword(
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

#[no_mangle]
pub extern "C" fn SecDeleteGenericPassword(service: CFStringRef, user: CFStringRef) -> OSStatus {
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
