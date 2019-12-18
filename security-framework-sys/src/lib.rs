#![allow(bad_style)]

extern crate core_foundation_sys;
extern crate libc;

#[cfg_attr(
    any(target_os = "macos", target_os = "ios"),
    link(name = "Security", kind = "framework")
)]
extern "C" {}

#[cfg(target_os = "macos")]
pub mod access;
#[cfg(target_os = "macos")]
pub mod authorization;
pub mod base;
pub mod certificate;
#[cfg(target_os = "macos")]
pub mod certificate_oids;
pub mod cipher_suite;
#[cfg(target_os = "macos")]
pub mod digest_transform;
#[cfg(target_os = "macos")]
pub mod encrypt_transform;
pub mod identity;
pub mod import_export;
pub mod item;
pub mod key;
#[cfg(target_os = "macos")]
pub mod keychain;
#[cfg(target_os = "macos")]
pub mod keychain_item;
pub mod policy;
pub mod random;
pub mod secure_transport;
#[cfg(target_os = "macos")]
pub mod transform;
pub mod trust;
#[cfg(target_os = "macos")]
pub mod trust_settings;
