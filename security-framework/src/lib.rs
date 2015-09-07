#![allow(non_upper_case_globals)]

extern crate security_framework_sys;
#[macro_use]
extern crate core_foundation;
extern crate core_foundation_sys;
extern crate libc;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;

use core_foundation_sys::base::OSStatus;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::cipher_suite::SSLCipherSuite;
use base::{Result, Error};
use cipher_suite::CipherSuite;

pub mod base;
pub mod certificate;
pub mod cipher_suite;
pub mod identity;
pub mod import_export;
pub mod key;
pub mod keychain;
pub mod secure_transport;
pub mod trust;

trait ErrorNew {
    fn new(status: OSStatus) -> Self;
}

trait CipherSuiteInternals {
    fn from_raw(raw: SSLCipherSuite) -> Option<CipherSuite>;
    fn to_raw(&self) -> SSLCipherSuite;
}

fn cvt(err: OSStatus) -> Result<()> {
    match err {
        errSecSuccess => Ok(()),
        err => Err(Error::new(err)),
    }
}
