//! Test library for newer iOS-style APIs.
//!
//! This library exercises the iOS-style password APIs.
//! It will compile under either macOS or iOS, so that
//! it can be linked into a test-harness executable
//! on either platform.  Since Rust provides a built-in
//! facility for testing, this library is really only
//! useful when built for iOS.  See the ios-test-harness
//! XCode project (part of this crate) for how it gets
//! linked and used for testing.

use security_framework::passwords::{
    delete_generic_password, delete_internet_password,
    get_generic_password, get_internet_password,
    set_generic_password, set_internet_password,
};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::keychain::SecAuthenticationType::Any;
use security_framework_sys::keychain::SecProtocolType::HTTP;

#[no_mangle]
extern "C" fn test() {
    test_missing_generic_password();
    test_round_trip_empty_generic_password();
    test_round_trip_ascii_generic_password();
    test_round_trip_non_ascii_generic_password();
    test_round_trip_non_utf8_generic_password();
    test_update_generic_password();
    test_missing_internet_password();
    test_round_trip_empty_internet_password();
    test_round_trip_ascii_internet_password();
    test_round_trip_non_ascii_internet_password();
    test_round_trip_non_utf8_internet_password();
    test_update_internet_password();
}

fn test_missing_generic_password() {
    println!("test_missing_generic_password: start");
    let name = "test_missing_generic_password";
    let result = delete_generic_password(name, name);
    match result {
        Ok(()) => (),
        Err(err) if err.code() == errSecItemNotFound => (),
        Err(err) => panic!("test_missing_generic_password: delete failed with status: {}", err.code()),
    };
    let result = get_generic_password(name, name);
    match result {
        Ok(bytes) => panic!("test_missing_password: get returned {:?}", bytes),
        Err(err) if err.code() == errSecItemNotFound => (),
        Err(err) => panic!("test_missing_generic_password: get failed with status: {}", err.code()),
    };
    let result = delete_generic_password(name, name);
    match result {
        Ok(()) => panic!("test_missing_generic_password: second delete found a password"),
        Err(err) if err.code() == errSecItemNotFound => (),
        Err(err) => panic!("test_missing_generic_password: delete failed with status: {}", err.code()),
    };
    println!("test_missing_generic_password: pass");
}

fn test_round_trip_empty_generic_password() {
    println!("test_round_trip_empty_generic_password: start");
    let name = "test_empty_generic_password_input";
    let in_pass = "".as_bytes();
    set_generic_password(name, name, in_pass).unwrap();
    let out_pass = get_generic_password(name, name).unwrap();
    assert_eq!(in_pass, out_pass);
    delete_generic_password(name, name).unwrap();
    println!("test_round_trip_empty_generic_password: pass");
}

fn test_round_trip_ascii_generic_password() {
    println!("test_round_trip_ascii_generic_password: start");
    let name = "test_round_trip_ascii_generic_password";
    let password = "test ascii password".as_bytes();
    set_generic_password(name, name, password).unwrap();
    let stored_password = get_generic_password(name, name).unwrap();
    assert_eq!(stored_password, password);
    delete_generic_password(name, name).unwrap();
    println!("test_round_trip_ascii_generic_password: pass");
}

fn test_round_trip_non_ascii_generic_password() {
    println!("test_round_trip_non_ascii_generic_password: start");
    let name = "test_round_trip_non_ascii_generic_password";
    let password = "このきれいな花は桜です".as_bytes();
    set_generic_password(name, name, password).unwrap();
    let stored_password = get_generic_password(name, name).unwrap();
    assert_eq!(stored_password, password);
    delete_generic_password(name, name).unwrap();
    println!("test_round_trip_non_ascii_generic_password: pass");
}

fn test_round_trip_non_utf8_generic_password() {
    println!("test_round_trip_non_utf8_generic_password: start");
    let name = "test_round_trip_non_utf8_generic_password";
    let password: [u8; 10] = [0, 121, 122, 123, 40, 50, 126, 127, 8, 9];
    set_generic_password(name, name, &password).unwrap();
    let stored_password = get_generic_password(name, name).unwrap();
    assert_eq!(stored_password, password);
    delete_generic_password(name, name).unwrap();
    println!("test_round_trip_non_utf8_generic_password: pass");
}

fn test_update_generic_password() {
    println!("test_update_generic_password: start");
    let name = "test_update_generic_password";
    let password = "test ascii password".as_bytes();
    set_generic_password(name, name, password).unwrap();
    let stored_password = get_generic_password(name, name).unwrap();
    assert_eq!(stored_password, password);
    let password = "このきれいな花は桜です".as_bytes();
    set_generic_password(name, name, password).unwrap();
    let stored_password = get_generic_password(name, name).unwrap();
    assert_eq!(stored_password, password);
    delete_generic_password(name, name).unwrap();
    println!("test_update_generic_password: pass");
}

fn test_missing_internet_password() {
    println!("test_missing_internet_password: start");
    let name = "test_missing_internet_password";
    let result = delete_internet_password(name, None, name, "/test", None, HTTP, Any);
    match result {
        Ok(()) => (),
        Err(err) if err.code() == errSecItemNotFound => (),
        Err(err) => panic!("test_missing_internet_password: delete failed with status: {}", err.code()),
    };
    let result = get_internet_password(name, None, name, "/test", None, HTTP, Any);
    match result {
        Ok(bytes) => panic!("test_missing_password: get returned {:?}", bytes),
        Err(err) if err.code() == errSecItemNotFound => (),
        Err(err) => panic!("test_missing_internet_password: get failed with status: {}", err.code()),
    };
    let result = delete_internet_password(name, None, name, "/test", None, HTTP, Any);
    match result {
        Ok(()) => panic!("test_missing_internet_password: second delete found a password"),
        Err(err) if err.code() == errSecItemNotFound => (),
        Err(err) => panic!("test_missing_internet_password: delete failed with status: {}", err.code()),
    };
    println!("test_missing_internet_password: pass");
}

fn test_round_trip_empty_internet_password() {
    println!("test_round_trip_empty_internet_password: start");
    let name = "test_empty_internet_password_input";
    let in_pass = "".as_bytes();
    set_internet_password(name, None, name, "/test", None, HTTP, Any, in_pass).unwrap();
    let out_pass = get_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    assert_eq!(in_pass, out_pass);
    delete_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    println!("test_round_trip_empty_internet_password: pass");
}

fn test_round_trip_ascii_internet_password() {
    println!("test_round_trip_ascii_internet_password: start");
    let name = "test_round_trip_ascii_internet_password";
    let password = "test ascii password".as_bytes();
    set_internet_password(name, None, name, "/test", None, HTTP, Any, password).unwrap();
    let stored_password = get_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    assert_eq!(stored_password, password);
    delete_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    println!("test_round_trip_ascii_internet_password: pass");
}

fn test_round_trip_non_ascii_internet_password() {
    println!("test_round_trip_non_ascii_internet_password: start");
    let name = "test_round_trip_non_ascii_internet_password";
    let password = "このきれいな花は桜です".as_bytes();
    set_internet_password(name, None, name, "/test", None, HTTP, Any, password).unwrap();
    let stored_password = get_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    assert_eq!(stored_password, password);
    delete_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    println!("test_round_trip_non_ascii_internet_password: pass");
}

fn test_round_trip_non_utf8_internet_password() {
    println!("test_round_trip_non_utf8_internet_password: start");
    let name = "test_round_trip_non_utf8_internet_password";
    let password: [u8; 10] = [0, 121, 122, 123, 40, 50, 126, 127, 8, 9];
    set_internet_password(name, None, name, "/test", None, HTTP, Any, &password).unwrap();
    let stored_password = get_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    assert_eq!(stored_password, password);
    delete_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    println!("test_round_trip_non_utf8_internet_password: pass");
}

fn test_update_internet_password() {
    println!("test_update_internet_password: start");
    let name = "test_update_internet_password";
    let password = "test ascii password".as_bytes();
    set_internet_password(name, None, name, "/test", None, HTTP, Any, password).unwrap();
    let stored_password = get_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    assert_eq!(stored_password, password);
    let password = "このきれいな花は桜です".as_bytes();
    set_internet_password(name, None, name, "/test", None, HTTP, Any, password).unwrap();
    let stored_password = get_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    assert_eq!(stored_password, password);
    delete_internet_password(name, None, name, "/test", None, HTTP, Any).unwrap();
    println!("test_update_internet_password: pass");
}
