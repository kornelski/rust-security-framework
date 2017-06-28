#![doc(html_root_url = "https://sfackler.github.io/rust-security-framework/doc/v0.1.14")]
#![allow(non_upper_case_globals)]

extern crate core_foundation_sys;
extern crate libc;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod access;
pub mod base;
pub mod certificate;
pub mod cipher_suite;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod digest_transform;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod encrypt_transform;
pub mod identity;
pub mod import_export;
pub mod item;
pub mod key;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod keychain;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod keychain_item;
pub mod policy;
pub mod random;
pub mod secure_transport;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod transform;
pub mod trust;
