//! OSX specific extensions to certificate functionality.

use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::certificate::*;
use std::ptr;

use cvt;
use base::Result;
use certificate::SecCertificate;
use key::SecKey;

/// An extension trait adding OSX specific functionality to `SecCertificate`.
pub trait SecCertificateExt {
    /// Returns the common name associated with the certificate.
    fn common_name(&self) -> Result<String>;

    /// Returns the public key associated with the certificate.
    fn public_key(&self) -> Result<SecKey>;
}

impl SecCertificateExt for SecCertificate {
    fn common_name(&self) -> Result<String> {
        unsafe {
            let mut string = ptr::null();
            try!(cvt(SecCertificateCopyCommonName(self.as_concrete_TypeRef(), &mut string)));
            Ok(CFString::wrap_under_create_rule(string).to_string())
        }
    }

    fn public_key(&self) -> Result<SecKey> {
        unsafe {
            let mut key = ptr::null_mut();
            try!(cvt(SecCertificateCopyPublicKey(self.as_concrete_TypeRef(), &mut key)));
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }
}

#[cfg(test)]
mod test {
    use test::certificate;
    use super::SecCertificateExt;

    #[test]
    fn common_name() {
        let certificate = certificate();
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }

    #[test]
    fn public_key() {
        let certificate = certificate();
        p!(certificate.public_key());
    }
}
