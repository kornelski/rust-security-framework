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
    use tempdir::TempDir;

    use keychain;
    use import_export::{SecItems, ImportOptions};
    use identity::SecIdentity;
    use certificate::SecCertificate;

    pub fn identity() -> (TempDir, SecIdentity) {
        let dir = p!(TempDir::new("identity"));
        let keychain = p!(keychain::CreateOptions::new()
            .password("password")
            .create(dir.path().join("identity.keychain")));

        let identity = include_bytes!("../test/server.p12");
        let mut items = SecItems::default();
        p!(ImportOptions::new()
           .filename("server.p12")
           .passphrase("password123")
           .items(&mut items)
           .keychain(&keychain)
           .import(identity));
        (dir, items.identities.pop().unwrap())
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
}
