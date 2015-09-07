use core_foundation_sys::base::{Boolean, CFRelease};
use core_foundation::base::TCFType;
use security_framework_sys::base::{errSecSuccess, SecKeychainRef};
use security_framework_sys::keychain::*;
use libc::c_void;
use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::ptr;
use std::os::unix::ffi::OsStrExt;

use {cvt, ErrorNew};
use base::{Error, Result};

pub struct SecKeychain(SecKeychainRef);

impl Drop for SecKeychain {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl Clone for SecKeychain {
    fn clone(&self) -> SecKeychain {
        unsafe {
            SecKeychain::wrap_under_get_rule(self.as_concrete_TypeRef())
        }
    }
}

impl_TCFType!(SecKeychain, SecKeychainRef, SecKeychainGetTypeID);

impl SecKeychain {
    pub fn default() -> Result<SecKeychain> {
        unsafe {
            let mut keychain = ptr::null_mut();
            let ret = SecKeychainCopyDefault(&mut keychain);
            if ret != errSecSuccess {
                return Err(Error::new(ret));
            }
            Ok(SecKeychain::wrap_under_create_rule(keychain))
        }
    }
}

#[derive(Default)]
pub struct CreateOptions {
    password: Option<String>,
    prompt_user: bool,
}

impl CreateOptions {
    pub fn new() -> CreateOptions {
        CreateOptions::default()
    }

    pub fn password(&mut self, password: &str) -> &mut CreateOptions {
        self.password = Some(password.into());
        self
    }

    pub fn prompt_user(&mut self, prompt_user: bool) -> &mut CreateOptions {
        self.prompt_user = prompt_user;
        self
    }

    pub fn create<P: AsRef<Path>>(&self, path: P) -> Result<SecKeychain> {
        unsafe {
            let path_name = path.as_ref().as_os_str().as_bytes();
            // FIXME
            let path_name = CString::new(path_name).unwrap();

            let (password, password_len) = match self.password {
                Some(ref password) => (password.as_ptr() as *const c_void, password.len() as u32),
                None => (ptr::null(), 0),
            };

            let mut keychain = ptr::null_mut();
            try!(cvt(SecKeychainCreate(path_name.as_ptr(),
                                       password_len,
                                       password,
                                       self.prompt_user as Boolean,
                                       ptr::null_mut(),
                                       &mut keychain)));

            Ok(SecKeychain::wrap_under_create_rule(keychain))
        }
    }
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;

    use super::*;

    #[test]
    fn create_options() {
        let dir = TempDir::new("keychain").unwrap();

        CreateOptions::new()
            .password("foobar")
            .create(dir.path().join("test.keychain"))
            .unwrap();
    }
}
