//! Password support.

use security_framework_sys::keychain::{SecKeychainFindGenericPassword,
                                       SecKeychainAddGenericPassword};
use security_framework_sys::base::{SecKeychainRef, errSecSuccess};
use security_framework_sys::keychain_item::{SecKeychainItemDelete,
                                            SecKeychainItemModifyAttributesAndData,
                                            SecKeychainItemFreeContent};
use core_foundation_sys::base::{CFTypeRef, CFRelease};
use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use keychain::SecKeychain;
use keychain_item::SecKeychainItem;
use std::ptr;
use std::ffi::CString;
use libc::c_void;

use cvt;
use base::Result;

/// Find a generic password.
///
/// The underlying system supports passwords with 0 values, so this
/// returns a vector of bytes rather than a string.
///
/// * `keychains` is an array of keychains to search or None to search
///   the default keychain.
/// * `service` is the name of the service to search for.
/// * `account` is the name of the account to search for.
pub fn find_generic_password(keychains: Option<&[SecKeychain]>,
                             service: &str, account: &str)
                             -> Result<(Vec<u8>, SecKeychainItem)> {

    let keychains_or_none = match keychains {
        None => None,
        Some(ref refs) => Some(CFArray::from_CFTypes(refs)),
    };

    let keychains_or_null = match keychains_or_none {
        None => ptr::null(),
        Some(ref keychains) => keychains.as_CFTypeRef(),
    };

    let service_name_len = service.len() as u32;
    let service_name = CString::new(service).unwrap();

    let account_name_len = account.len() as u32;
    let account_name = CString::new(account).unwrap();

    let mut raw_len = 0;
    let mut raw = ptr::null_mut();

    let mut item = ptr::null_mut();

    unsafe {
        try!(cvt(SecKeychainFindGenericPassword(keychains_or_null,
                                                service_name_len,
                                                service_name.as_ptr(),
                                                account_name_len,
                                                account_name.as_ptr(),
                                                &mut raw_len,
                                                &mut raw,
                                                &mut item)));

        // Copy the returned password.
        // https://doc.rust-lang.org/std/ptr/fn.copy.html
        let len = raw_len as usize;
        let mut password = Vec::with_capacity(len);
        password.set_len(len);
        ptr::copy(raw, password.as_mut_ptr(), len);

        // Now free the password.
        try!(cvt(SecKeychainItemFreeContent(ptr::null(),
                                            raw as *const c_void)));

        Ok((password, SecKeychainItem::wrap_under_create_rule(item as *mut _)))
    }
}

/// Set a generic password.
///
/// * `keychain_opt` is the keychain to use or None to use the default
///   keychain.
/// * `service` is the associated service name for the password.
/// * `account` is the associated account name for the password.
/// * `password` is the password itself.
pub fn set_generic_password(keychain_opt: Option<&SecKeychain>,
                            service: &str, account: &str, password: &[u8])
                            -> Result<()> {

    let keychain_ref = match keychain_opt {
        None => ptr::null(),
        Some(keychain) => keychain.as_CFTypeRef(),
    };

    let service_name_len = service.len() as u32;
    let service_name = CString::new(service).unwrap();

    let account_name_len = account.len() as u32;
    let account_name = CString::new(account).unwrap();

    let password_len = password.len() as u32;
    let mut item = ptr::null_mut();

    unsafe {
        let status = SecKeychainFindGenericPassword(keychain_ref,
                                                    service_name_len,
                                                    service_name.as_ptr(),
                                                    account_name_len,
                                                    account_name.as_ptr(),
                                                    ptr::null_mut(),
                                                    ptr::null_mut(),
                                                    &mut item);

        match status {
            errSecSuccess => {
                try!(cvt(SecKeychainItemModifyAttributesAndData(
                    item, ptr::null(), password_len, password.as_ptr())));
                CFRelease(item as CFTypeRef);
            },
            _ => {
                try!(cvt(
                    SecKeychainAddGenericPassword(
                        keychain_ref as SecKeychainRef,
                        service_name_len,
                        service_name.as_ptr(),
                        account_name_len,
                        account_name.as_ptr(),
                        password_len,
                        password.as_ptr(),
                        ptr::null_mut())
                        ));
            }
        }
    }

    Ok(())
}

/// Delete a generic password.
///
/// * `keychains` is an array of keychains to search or None to search
///   the default keychain.
/// * `service` is the associated service name for the password.
/// * `account` is the associated account name for the password.
pub fn delete_generic_password(keychains: Option<&[SecKeychain]>,
                               service: &str, account: &str) -> Result<()> {

    let keychains_or_none = match keychains {
        None => None,
        Some(ref refs) => Some(CFArray::from_CFTypes(refs)),
    };

    let keychains_or_null = match keychains_or_none {
        None => ptr::null(),
        Some(ref keychains) => keychains.as_CFTypeRef(),
    };

    let service_name_len = service.len() as u32;
    let service_name = CString::new(service).unwrap();

    let account_name_len = account.len() as u32;
    let account_name = CString::new(account).unwrap();

    let mut item = ptr::null_mut();

    unsafe {
         try!(cvt(SecKeychainFindGenericPassword(keychains_or_null,
                                                service_name_len,
                                                service_name.as_ptr(),
                                                account_name_len,
                                                account_name.as_ptr(),
                                                ptr::null_mut(),
                                                ptr::null_mut(),
                                                &mut item)));

        SecKeychainItemDelete(item);
        CFRelease(item as CFTypeRef);
        Ok(())
    }
}


#[cfg(test)]
mod test {
    use tempdir::TempDir;
    use keychain::{CreateOptions, SecKeychain};

    use super::*;

    fn temp_keychain_setup(name: &str) -> (TempDir, SecKeychain) {
        let dir = TempDir::new("passwords").expect("TempDir::new");
        let keychain = CreateOptions::new()
            .password("foobar")
            .create(dir.path().join(name.to_string() + ".keychain"))
            .expect("create keychain");

        (dir, keychain)
    }

    fn temp_keychain_teardown(dir: TempDir) -> () {
        dir.close().expect("temp dir close");
    }

    #[test]
    fn missing_password_temp() {
        let (dir, keychain) = temp_keychain_setup("missing_password");
        let keychains = vec![keychain];

        let service = "temp_this_service_does_not_exist";
        let account = "this_account_is_bogus";
        let found = find_generic_password(Some(&keychains),
                                          service, account);

        assert!(found.is_err());

        temp_keychain_teardown(dir);
    }

    #[test]
    #[cfg(feature = "default_keychain_tests")]
    fn missing_password_default() {
        let service = "default_this_service_does_not_exist";
        let account = "this_account_is_bogus";
        let found = find_generic_password(None, service, account);

        assert!(found.is_err());
    }

    #[test]
    fn round_trip_password_temp() {
        let (dir, keychain) = temp_keychain_setup("round_trip_password");
        let keychains = vec![keychain];

        let service = "test_round_trip_password_temp";
        let account = "temp_this_is_the_test_account";
        let password = String::from("deadbeef").into_bytes();

        set_generic_password(Some(&keychains[0]),
                             service, account, &password)
            .expect("set_generic_password");
        let (found, _) = find_generic_password(Some(&keychains),
                                               service, account)
            .expect("find_generic_password");
        assert_eq!(found, password);

        delete_generic_password(Some(&keychains), service, account)
            .expect("delete_generic_password");

        temp_keychain_teardown(dir);
    }

    #[test]
    #[cfg(feature = "default_keychain_tests")]
    fn round_trip_password_default() {
        let service = "test_round_trip_password_default";
        let account = "this_is_the_test_account";
        let password = String::from("deadbeef").into_bytes();

        set_generic_password(None, service, account, &password)
            .expect("set_generic_password");
        let (found, _) = find_generic_password(None, service, account)
            .expect("find_generic_password");
        assert_eq!(found, password);

        delete_generic_password(None, service, account)
            .expect("delete_generic_password");
    }

    #[test]
    fn change_password_temp() {
        let (dir, keychain) = temp_keychain_setup("change_password");
        let keychains = vec![keychain];

        let service = "test_change_password_temp";
        let account = "this_is_the_test_account";
        let pw1 = String::from("password1").into_bytes();
        let pw2 = String::from("password2").into_bytes();

        set_generic_password(Some(&keychains[0]), service, account, &pw1)
            .expect("set_generic_password1");
        let (found, _) = find_generic_password(Some(&keychains),
                                               service, account)
            .expect("find_generic_password1");
        assert_eq!(found, pw1);

        set_generic_password(Some(&keychains[0]), service, account, &pw2)
            .expect("set_generic_password2");
        let (found, _) = find_generic_password(Some(&keychains),
                                               service, account)
            .expect("find_generic_password2");
        assert_eq!(found, pw2);

        delete_generic_password(Some(&keychains), service, account)
            .expect("delete_generic_password");

        temp_keychain_teardown(dir);
    }

    #[test]
    #[cfg(feature = "default_keychain_tests")]
    fn change_password_default() {
        let service = "test_change_password_default";
        let account = "this_is_the_test_account";
        let pw1 = String::from("password1").into_bytes();
        let pw2 = String::from("password2").into_bytes();

        set_generic_password(None, service, account, &pw1)
            .expect("set_generic_password1");
        let (found, _) = find_generic_password(None, service, account)
            .expect("find_generic_password1");
        assert_eq!(found, pw1);

        set_generic_password(None, service, account, &pw2)
            .expect("set_generic_password2");
        let (found, _) = find_generic_password(None, service, account)
            .expect("find_generic_password2");
        assert_eq!(found, pw2);

        delete_generic_password(None, service, account)
            .expect("delete_generic_password");
    }

    #[test]
    fn cross_keychain_corruption_temp() {
        let (dir1, keychain1) = temp_keychain_setup("cross_corrupt1");
        let (dir2, keychain2) = temp_keychain_setup("cross_corrupt2");
        let keychains1 = vec![keychain1.clone()];
        let keychains2 = vec![keychain2.clone()];
        let both_keychains = vec![keychain1, keychain2];

        let service = "temp_this_service_does_not_exist";
        let account = "this_account_is_bogus";
        let password = String::from("deadbeef").into_bytes();

        // Make sure this password doesn't exist in either keychain.
        let found = find_generic_password(Some(&both_keychains),
                                          service, account);
        assert!(found.is_err());

        // Set a password in one keychain.
        set_generic_password(Some(&keychains1[0]),
                             service, account, &password)
            .expect("set_generic_password");

        // Make sure it's found in that keychain.
        let (found, _) = find_generic_password(Some(&keychains1),
                                               service, account)
            .expect("find_generic_password1");
        assert_eq!(found, password);

        // Make sure it's _not_ found in the other keychain.
        let found = find_generic_password(Some(&keychains2),
                                          service, account);
        assert!(found.is_err());

        // Cleanup.
        delete_generic_password(Some(&keychains1), service, account)
            .expect("delete_generic_password");

        temp_keychain_teardown(dir1);
        temp_keychain_teardown(dir2);
    }
}
