//! Wrappers around the OSX Security Framework.

#![warn(missing_docs)]
#![allow(non_upper_case_globals)]

extern crate security_framework_sys;
#[macro_use]
extern crate core_foundation;
extern crate core_foundation_sys;
extern crate libc;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate tempdir;

use core_foundation_sys::base::OSStatus;
use security_framework_sys::base::errSecSuccess;

use base::{Error, Result};
#[cfg(target_os = "macos")]
use os::macos::access::SecAccess;
#[cfg(target_os = "macos")]
use os::macos::keychain::SecKeychain;

#[cfg(test)]
macro_rules! p {
    ($e:expr) => {
        match $e {
            Ok(s) => s,
            Err(e) => panic!("{:?}", e),
        }
    };
}

#[cfg(all(not(feature = "OSX_10_13"), feature = "alpn"))]
#[macro_use]
mod dlsym;

pub mod base;
pub mod certificate;
pub mod cipher_suite;
pub mod identity;
pub mod import_export;
pub mod item;
pub mod key;
pub mod os;
pub mod policy;
pub mod random;
pub mod secure_transport;
pub mod trust;

#[cfg(target_os = "macos")]
trait Pkcs12ImportOptionsInternals {
    fn keychain(&mut self, keychain: SecKeychain) -> &mut Self;
    fn access(&mut self, access: SecAccess) -> &mut Self;
}

#[cfg(target_os = "macos")]
trait ItemSearchOptionsInternals {
    fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut Self;
}

trait AsInner {
    type Inner;
    fn as_inner(&self) -> Self::Inner;
}

fn cvt(err: OSStatus) -> Result<()> {
    match err {
        errSecSuccess => Ok(()),
        err => Err(Error::from_code(err)),
    }
}

#[cfg(test)]
mod test {
    use certificate::SecCertificate;

    pub fn certificate() -> SecCertificate {
        let certificate = include_bytes!("../test/server.der");
        p!(SecCertificate::from_der(certificate))
    }
}
