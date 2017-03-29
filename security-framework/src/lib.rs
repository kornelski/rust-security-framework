//! Wrappers around the OSX Security Framework.

#![doc(html_root_url = "https://sfackler.github.io/rust-security-framework/doc/v0.1.14")]
#![warn(missing_docs)]
#![allow(non_upper_case_globals)]

extern crate security_framework_sys;
#[macro_use]
extern crate core_foundation;
extern crate core_foundation_sys;
extern crate libc;

#[cfg(test)]
extern crate tempdir;
#[cfg(test)]
extern crate hex;

// For back compat
#[cfg(target_os = "macos")]
pub use os::macos::keychain_item;
#[cfg(target_os = "macos")]
pub use os::macos::access;
#[cfg(target_os = "macos")]
pub use os::macos::keychain;

use core_foundation_sys::base::OSStatus;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::cipher_suite::SSLCipherSuite;

use base::{Result, Error};
use cipher_suite::CipherSuite;
#[cfg(target_os = "macos")]
use os::macos::access::SecAccess;
#[cfg(target_os = "macos")]
use os::macos::keychain::SecKeychain;

macro_rules! make_wrapper {
    ($(#[$a:meta])* struct $name:ident, $raw:ident, $ty_fn:ident) => {
        $(#[$a])*
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

trait CipherSuiteInternals {
    fn from_raw(raw: SSLCipherSuite) -> Option<CipherSuite>;
    fn to_raw(&self) -> SSLCipherSuite;
}

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
