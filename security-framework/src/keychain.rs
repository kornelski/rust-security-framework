use core_foundation_sys::base::{Boolean, CFRelease};
use core_foundation::base::TCFType;
use security_framework_sys::base::SecKeychainRef;
use security_framework_sys::keychain::*;
use libc::c_void;
use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::ptr;
use std::os::unix::ffi::OsStrExt;

use cvt;
use access::SecAccess;
use base::Result;

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
            try!(cvt(SecKeychainCopyDefault(&mut keychain)));
            Ok(SecKeychain::wrap_under_create_rule(keychain))
        }
    }

    pub fn open<P: AsRef<Path>>(path: P) -> Result<SecKeychain> {
        let path_name = path.as_ref().as_os_str().as_bytes();
        // FIXME
        let path_name = CString::new(path_name).unwrap();

        unsafe {
            let mut keychain = ptr::null_mut();
            try!(cvt(SecKeychainOpen(path_name.as_ptr(), &mut keychain)));
            Ok(SecKeychain::wrap_under_create_rule(keychain))
        }
    }

    pub fn unlock(&mut self, password: Option<&str>) -> Result<()> {
        let (len, ptr, use_password) = match password {
            Some(password) => (password.len(), password.as_ptr() as *const _, true),
            None => (0, ptr::null(), false)
        };

        unsafe {
            cvt(SecKeychainUnlock(self.0, len as u32, ptr, use_password as Boolean))
        }
    }
}

#[derive(Default)]
pub struct CreateOptions {
    password: Option<String>,
    prompt_user: bool,
    access: Option<SecAccess>,
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

    pub fn access(&mut self, access: SecAccess) -> &mut CreateOptions {
        self.access = Some(access);
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

            let access = match self.access {
                Some(ref access) => access.as_concrete_TypeRef(),
                None => ptr::null_mut(),
            };

            let mut keychain = ptr::null_mut();
            try!(cvt(SecKeychainCreate(path_name.as_ptr(),
                                       password_len,
                                       password,
                                       self.prompt_user as Boolean,
                                       access,
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
