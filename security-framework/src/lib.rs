#![allow(non_upper_case_globals)]

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
pub mod import_export;
pub mod item;
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

#[cfg(test)]
pub mod test {
    use item::{ItemSearchOptions, ItemClass};
    use import_export::{SecItems, ImportOptions};
    use identity::SecIdentity;
    use certificate::SecCertificate;
    use keychain::SecKeychain;

    pub fn identity() -> SecIdentity {
        let mut items = p!(ItemSearchOptions::new()
            .class(ItemClass::Identity)
            .keychains(&[keychain()])
            .search());
        items.identities.pop().unwrap()
    }

    pub fn certificate() -> SecCertificate {
        let certificate = include_bytes!("../test/server.crt");
        let mut items = SecItems::default();
        p!(ImportOptions::new()
           .filename("server.crt")
           .items(&mut items)
           .import(certificate));
        items.certificates.pop().unwrap()
    }

    pub fn keychain() -> SecKeychain {
        // the path has to be absolute for some reason
        let mut keychain = p!(SecKeychain::open(concat!(env!("PWD"), "/test/server.keychain")));
        p!(keychain.unlock(Some("password123")));
        keychain
    }
}
