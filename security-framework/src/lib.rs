#![allow(non_upper_case_globals)]

extern crate security_framework_sys;
extern crate core_foundation;
extern crate core_foundation_sys;
extern crate libc;

use core_foundation_sys::base::OSStatus;

pub mod base;
pub mod certificate;
pub mod identity;
pub mod import_export;
pub mod key;
pub mod keychain;
pub mod secure_transport;

trait ErrorNew {
    fn new(status: OSStatus) -> Self;
}
