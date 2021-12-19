use core_foundation::base::OSStatus;
use security_framework_sys::base::{errSecBadReq, errSecBufferTooSmall, errSecSuccess};
use std::ffi::CStr;
use std::os::raw::{c_char, c_uchar, c_ulong};
use std::ptr::copy_nonoverlapping;

#[no_mangle]
pub extern "C" fn set_generic_password(
    service: *const c_char,
    user: *const c_char,
    pw: *const c_uchar,
    pw_len: c_ulong,
) -> OSStatus {
    let service = unsafe { CStr::from_ptr(service) }.to_str().unwrap_or("");
    let account = unsafe { CStr::from_ptr(user) }.to_str().unwrap_or("");
    if service.len() == 0 || account.len() == 0 {
        return errSecBadReq;
    }
    let password = unsafe { std::slice::from_raw_parts(pw as *const u8, pw_len as usize) };
    match security_framework::passwords::set_generic_password(service, account, password) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

#[no_mangle]
pub extern "C" fn get_generic_password(
    service: *const c_char,
    user: *const c_char,
    buffer: *mut c_uchar,
    buf_size: c_ulong,
    pw_size: *mut c_ulong,
) -> OSStatus {
    let service = unsafe { CStr::from_ptr(service) }.to_str().unwrap_or("");
    let account = unsafe { CStr::from_ptr(user) }.to_str().unwrap_or("");
    if service.len() == 0 || account.len() == 0 {
        return errSecBadReq;
    }
    match security_framework::passwords::get_generic_password(service, account) {
        Ok(bytes) => {
            unsafe { *pw_size = bytes.len() as c_ulong };
            if bytes.len() > buf_size as usize {
                errSecBufferTooSmall
            } else {
                unsafe { copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) }
                errSecSuccess
            }
        }
        Err(err) => err.code(),
    }
}

#[no_mangle]
pub extern "C" fn delete_generic_password(service: *const c_char, user: *const c_char) -> OSStatus {
    let service = unsafe { CStr::from_ptr(service) }.to_str().unwrap_or("");
    let account = unsafe { CStr::from_ptr(user) }.to_str().unwrap_or("");
    if service.len() == 0 || account.len() == 0 {
        return errSecBadReq;
    }
    match security_framework::passwords::delete_generic_password(service, account) {
        Ok(_) => errSecSuccess,
        Err(err) => err.code(),
    }
}
