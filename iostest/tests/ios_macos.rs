//! Tests of legacy macOS versus newer iOS-style APIs.
//!
//! These tests compile under both iOS and macOS.  Of course, there's not
//! much point compiling them under iOS, since you can't run them under iOS,
//! but at least the compilation tells you that the interfaces are intact.
//! For iOS testing, compile the library and use the included ios-test-harness.
//!
//! NOTE: Some of these tests involve keychain queries for multiple items,
//! and experience shows that running multiple keychain queries on separate
//! threads in the same process simultaneously can produce interference.
//! So all the query tests have been conditioned to run serially.

use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::passwords::{delete_generic_password, set_generic_password};
use security_framework_sys::item::{kSecAttrAccount, kSecAttrService};
use serial_test::serial;

#[test]
#[serial]
fn insert_then_find_generic() {
    let service_key = format!("{}", unsafe {
        CFString::wrap_under_get_rule(kSecAttrService)
    });
    let mut names = vec![];
    for _ in 0..4 {
        let name = generate_random_string();
        set_generic_password(&name, &name, name.as_bytes()).unwrap();
        names.push(name);
    }
    let results = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .load_attributes(true)
        .limit(Limit::All)
        .search()
        .unwrap();
    assert!(results.len() >= names.len());
    let mut found = 0;
    for result in &results {
        match result {
            SearchResult::Dict(_) => {
                let dict = result.simplify_dict().unwrap();
                if let Some(val) = dict.get(&service_key) {
                    if names.contains(val) {
                        found += 1;
                    }
                }
            }
            _ => panic!("Got a non-dictionary from a password search"),
        }
    }
    assert_eq!(names.len(), found);
    for name in &names {
        delete_generic_password(name, name).unwrap();
    }
}

#[test]
#[serial]
#[cfg(target_os = "macos")]
fn insert_then_find_generic_legacy() {
    let keychain = SecKeychain::default().unwrap();
    let service_key = format!("{}", unsafe {
        CFString::wrap_under_get_rule(kSecAttrService)
    });
    // create 4 legacy and 4 modern generic passwords
    let mut legacy_names = vec![];
    for _ in 0..4 {
        let name = generate_random_string();
        keychain
            .set_generic_password(&name, &name, name.as_bytes())
            .unwrap();
        legacy_names.push(name);
    }
    let mut modern_names = vec![];
    for _ in 0..4 {
        let name = generate_random_string();
        set_generic_password(&name, &name, name.as_bytes()).unwrap();
        modern_names.push(name);
    }
    // first check to see that the legacy passwords are found by the modern search
    let results = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .load_attributes(true)
        .limit(Limit::All)
        .search()
        .unwrap();
    assert!(results.len() >= legacy_names.len());
    let mut found = 0;
    for result in &results {
        match result {
            SearchResult::Dict(_) => {
                let dict = result.simplify_dict().unwrap();
                if let Some(val) = dict.get(&service_key) {
                    if legacy_names.contains(val) {
                        found += 1;
                    }
                }
            }
            _ => panic!("Got a non-dictionary from a password search"),
        }
    }
    assert_eq!(legacy_names.len(), found);
    // next check to see that the modern passwords are found by the legacy search
    for name in &modern_names {
        keychain.find_generic_password(name, name).unwrap();
    }
    // finally delete both the legacy and the modern passwords
    for name in &legacy_names {
        let (_, item) = keychain.find_generic_password(name, name).unwrap();
        item.delete();
    }
    for name in &modern_names {
        delete_generic_password(name, name).unwrap();
    }
}

#[test]
#[serial]
fn find_leftover_test_generic_passwords() {
    let service_key = format!("{}", unsafe {
        CFString::wrap_under_get_rule(kSecAttrService)
    });
    let username_key = format!("{}", unsafe {
        CFString::wrap_under_get_rule(kSecAttrAccount)
    });
    let mut found: Vec<String> = vec![];
    let results = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .load_attributes(true)
        .limit(Limit::All)
        .search()
        .unwrap();
    for result in &results {
        match result {
            SearchResult::Dict(_) => {
                let dict = result.simplify_dict().unwrap();
                if let Some(val) = dict.get(&service_key) {
                    if val.len() == 30 {
                        if let Some(val2) = dict.get(&username_key) {
                            if val2.eq(val) {
                                // println!("Found left-over test-created entry: {}", val);
                                found.push(val.clone());
                            }
                        }
                    }
                }
            }
            _ => panic!("Got a non-dictionary from a password search"),
        }
    }
    assert!(found.is_empty(), "There are {} entries created by older tests: {:?}",
            found.len(),
            &found);
}

fn generate_random_string() -> String {
    // from the Rust Cookbook:
    // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}
