#![allow(non_upper_case_globals)]

extern crate security_framework_sys;
#[macro_use]
extern crate core_foundation;
extern crate core_foundation_sys;
extern crate libc;

#[cfg(test)]
extern crate tempdir;
#[cfg(test)]
extern crate rustc_serialize;

use core_foundation_sys::base::OSStatus;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::cipher_suite::SSLCipherSuite;
use base::{Result, Error};
use cipher_suite::CipherSuite;

macro_rules! make_wrapper {
    ($name:ident, $raw:ident, $ty_fn:ident) => {
        pub struct $name($raw);

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    ::core_foundation_sys::base::CFRelease(self.0 as *mut _);
                }
            }
        }

        impl Clone for $name {
            fn clone(&self) -> $name {
                use core_foundation::base::TCFType;

                unsafe {
                    TCFType::wrap_under_get_rule(self.as_concrete_TypeRef())
                }
            }
        }

        impl_TCFType!($name, $raw, $ty_fn);
    }
}

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
pub mod keychain_item;
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

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
    use certificate::SecCertificate;

    pub fn next_port() -> u16 {
        static PORT_SHIFT: AtomicUsize = ATOMIC_USIZE_INIT;

        15410 + PORT_SHIFT.fetch_add(1, Ordering::SeqCst) as u16
    }

    pub fn certificate() -> SecCertificate {
        let certificate = include_bytes!("../test/server.der");
        p!(SecCertificate::from_der(certificate))
    }
}
