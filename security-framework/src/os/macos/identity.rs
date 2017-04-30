//! OSX specific extensions to identity functionality.
use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use std::ptr;
use security_framework_sys::identity::*;

use cvt;
use base::Result;
use certificate::SecCertificate;
use identity::SecIdentity;
use keychain::SecKeychain;

/// An extension trait adding OSX specific functionality to `SecIdentity`.
pub trait SecIdentityExt {
    /// Creates an identity corresponding to a certificate, looking in the
    /// provided keychains for the corresponding private key.
    fn with_certificate(keychains: &[SecKeychain],
                        certificate: &SecCertificate)
                        -> Result<SecIdentity>;
}

impl SecIdentityExt for SecIdentity {
    fn with_certificate(keychains: &[SecKeychain],
                        certificate: &SecCertificate)
                        -> Result<SecIdentity> {
        let keychains = CFArray::from_CFTypes(keychains);
        unsafe {
            let mut identity = ptr::null_mut();
            try!(cvt(SecIdentityCreateWithCertificate(keychains.as_CFTypeRef(),
                                                      certificate.as_concrete_TypeRef(),
                                                      &mut identity)));
            Ok(SecIdentity::wrap_under_create_rule(identity))
        }
    }
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;

    use identity::SecIdentity;
    use os::macos::test::identity;
    use os::macos::certificate::SecCertificateExt;
    use os::macos::keychain::CreateOptions;
    use os::macos::import_export::ImportOptions;
    use test;
    use super::*;

    #[test]
    fn certificate() {
        let dir = p!(TempDir::new("certificate"));
        let identity = identity(dir.path());
        let certificate = p!(identity.certificate());
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }

    #[test]
    fn private_key() {
        let dir = p!(TempDir::new("private_key"));
        let identity = identity(dir.path());
        p!(identity.private_key());
    }

    #[test]
    fn with_certificate() {
        let dir = p!(TempDir::new("with_certificate"));

        let mut keychain =
            p!(CreateOptions::new().password("foobar").create(dir.path().join("test.keychain")));

        let key = include_bytes!("../../../test/server.key");
        p!(ImportOptions::new()
            .filename("server.key")
            .keychain(&mut keychain)
            .import(key));

        let cert = test::certificate();
        p!(SecIdentity::with_certificate(&[keychain], &cert));
    }
}
