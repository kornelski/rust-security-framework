#![allow(non_upper_case_globals)]
#![cfg_attr(target_os = "ios", feature(box_raw))]

extern crate security_framework_sys;
#[macro_use]
extern crate core_foundation;
extern crate core_foundation_sys;
extern crate libc;

#[cfg(test)]
extern crate tempdir;

use core_foundation_sys::base::OSStatus;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::cipher_suite::SSLCipherSuite;
use base::{Result, Error};
use cipher_suite::CipherSuite;

#[cfg(test)]
macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(s) => s,
            Err(e) => panic!("{:?}", e),
        }
    }
}

pub mod access;
pub mod base;
pub mod certificate;
pub mod cipher_suite;
pub mod identity;
pub mod item;
pub mod key;
pub mod keychain;
pub mod os;
pub mod secure_transport;
pub mod trust;

trait ErrorNew {
    fn new(status: OSStatus) -> Self;
}

trait CipherSuiteInternals {
    fn from_raw(raw: SSLCipherSuite) -> Option<CipherSuite>;
    fn to_raw(&self) -> SSLCipherSuite;
}

trait AsInner {
    type Inner;

    fn as_inner(&self) -> Self::Inner;
}

fn cvt(err: OSStatus) -> Result<()> {
    match err {
        errSecSuccess => Ok(()),
        err => Err(Error::new(err)),
    }
}
