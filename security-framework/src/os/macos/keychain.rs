//! Keychain support.

use core_foundation::base::{Boolean, TCFType};
use security_framework_sys::base::SecKeychainRef;
use security_framework_sys::keychain::*;
use std::path::Path;
use std::ptr;
use std::ffi::CString;
use libc::c_void;
use std::os::unix::ffi::OsStrExt;

use cvt;
use base::Result;
use os::macos::access::SecAccess;

make_wrapper! {
    /// A type representing a keychain.
    struct SecKeychain, SecKeychainRef, SecKeychainGetTypeID
}

unsafe impl Sync for SecKeychain {}
unsafe impl Send for SecKeychain {}

/// Deprecated.
pub trait SecKeychainExt {
    /// Deprecated.
    fn default() -> Result<SecKeychain>;

    /// Deprecated.
    fn open<P: AsRef<Path>>(path: P) -> Result<SecKeychain>;

    /// Deprecated.
    fn unlock(&mut self, password: Option<&str>) -> Result<()>;
}

impl SecKeychainExt for SecKeychain {
    fn default() -> Result<SecKeychain> {
        SecKeychain::default()
    }

    fn open<P: AsRef<Path>>(path: P) -> Result<SecKeychain> {
        SecKeychain::open(path)
    }

    fn unlock(&mut self, password: Option<&str>) -> Result<()> {
        SecKeychain::unlock(self, password)
    }
}

impl SecKeychain {
    /// Creates a `SecKeychain` object corresponding to the user's default
    /// keychain.
    pub fn default() -> Result<SecKeychain> {
        unsafe {
            let mut keychain = ptr::null_mut();
            try!(cvt(SecKeychainCopyDefault(&mut keychain)));
            Ok(SecKeychain::wrap_under_create_rule(keychain))
        }
    }

    /// Opens a keychain from a file.
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

    /// Unlocks the keychain.
    ///
    /// If a password is not specified, the user will be prompted to enter it.
    pub fn unlock(&mut self, password: Option<&str>) -> Result<()> {
        let (len, ptr, use_password) = match password {
            Some(password) => (password.len(), password.as_ptr() as *const _, true),
            None => (0, ptr::null(), false),
        };

        unsafe {
            cvt(SecKeychainUnlock(self.as_concrete_TypeRef(),
                                  len as u32,
                                  ptr,
                                  use_password as Boolean))
        }
    }

    /// Sets settings of the keychain.
    pub fn set_settings(&mut self, settings: &KeychainSettings) -> Result<()> {
        unsafe {
            cvt(SecKeychainSetSettings(self.as_concrete_TypeRef(), &settings.0))
        }
    }
}

/// A builder type to create new keychains.
#[derive(Default)]
pub struct CreateOptions {
    password: Option<String>,
    prompt_user: bool,
    access: Option<SecAccess>,
}

impl CreateOptions {
    /// Creates a new builder with default options.
    pub fn new() -> CreateOptions {
        CreateOptions::default()
    }

    /// Sets the password to be used to protect the keychain.
    pub fn password(&mut self, password: &str) -> &mut CreateOptions {
        self.password = Some(password.into());
        self
    }

    /// If set, the user will be prompted to provide a password used to
    /// protect the keychain.
    pub fn prompt_user(&mut self, prompt_user: bool) -> &mut CreateOptions {
        self.prompt_user = prompt_user;
        self
    }

    /// Sets the access control applied to the keychain.
    pub fn access(&mut self, access: SecAccess) -> &mut CreateOptions {
        self.access = Some(access);
        self
    }

    /// Creates a new keychain at the specified location on the filesystem.
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

/// Settings associated with a `SecKeychain`.
pub struct KeychainSettings(SecKeychainSettings);

impl KeychainSettings {
    /// Creates a new `KeychainSettings` with default settings.
    pub fn new() -> KeychainSettings {
        KeychainSettings(SecKeychainSettings {
            version: SEC_KEYCHAIN_SETTINGS_VERS1,
            lockOnSleep: 0,
            useLockInterval: 0,
            lockInterval: i32::max_value() as u32,
        })
    }

    /// If set, the keychain will automatically lock when the computer sleeps.
    ///
    /// Defaults to `false`.
    pub fn set_lock_on_sleep(&mut self, lock_on_sleep: bool) {
        self.0.lockOnSleep = lock_on_sleep as Boolean;
    }

    /// Sets the interval of time in seconds after which the keychain is
    /// automatically locked.
    ///
    /// Defaults to `None`.
    pub fn set_lock_interval(&mut self, lock_interval: Option<u32>) {
        match lock_interval {
            Some(lock_interval) => {
                self.0.useLockInterval = 1;
                self.0.lockInterval = lock_interval;
            }
            None => {
                self.0.useLockInterval = 0;
                self.0.lockInterval = i32::max_value() as u32;
            }
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

        let mut keychain = CreateOptions::new()
            .password("foobar")
            .create(dir.path().join("test.keychain"))
            .unwrap();

        keychain.set_settings(&KeychainSettings::new()).unwrap();
    }
}
