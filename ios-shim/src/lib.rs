use core_foundation::base::OSStatus;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_ulong};
use std::ptr::copy_nonoverlapping;

#[no_mangle]
pub extern "C" fn set_generic_password(
    service: *const c_char,
    user: *const c_char,
    password: *const c_char,
) -> OSStatus {
    let service = unsafe { CStr::from_ptr(service).to_string_lossy().into_owned() };
    let account = unsafe { CStr::from_ptr(user).to_string_lossy().into_owned() };
    let password = unsafe { CStr::from_ptr(password).to_string_lossy().into_owned() };
    match security_framework::passwords::set_generic_password(&service, &account, &password) {
        Ok(_) => 0,
        Err(err) => err.code(),
    }
}

#[no_mangle]
pub extern "C" fn get_generic_password(
    service: *const c_char,
    user: *const c_char,
    buffer: *mut c_char,
    buflen: c_ulong,
) -> OSStatus {
    let service = unsafe { CStr::from_ptr(service).to_string_lossy().into_owned() };
    let account = unsafe { CStr::from_ptr(user).to_string_lossy().into_owned() };
    match security_framework::passwords::get_generic_password(&service, &account) {
        Ok(s) => {
            let buflen = buflen as usize;
            let c_string = CString::new(s).unwrap();
            let clen = c_string.as_bytes_with_nul().len();
            if clen > buflen {
                unsafe { copy_nonoverlapping(c_string.as_ptr(), buffer, buflen) }
                (clen - buflen) as OSStatus
            } else {
                unsafe { copy_nonoverlapping(c_string.as_ptr(), buffer, clen) }
                0
            }
        }
        Err(err) => err.code(),
    }
}
