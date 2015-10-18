use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use security_framework_sys::base::SecIdentityRef;
use security_framework_sys::identity::*;
use std::mem;
use std::ptr;

use cvt;
use base::Result;
use certificate::SecCertificate;
use key::SecKey;

pub struct SecIdentity(SecIdentityRef);

impl Drop for SecIdentity {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl_TCFType!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);

impl SecIdentity {
    pub fn certificate(&self) -> Result<SecCertificate> {
        unsafe {
            let mut certificate = ptr::null_mut();
            try!(cvt(SecIdentityCopyCertificate(self.0, &mut certificate)));
            Ok(SecCertificate::wrap_under_create_rule(certificate))
        }
    }

    pub fn private_key(&self) -> Result<SecKey> {
        unsafe {
            let mut key = ptr::null_mut();
            try!(cvt(SecIdentityCopyPrivateKey(self.0, &mut key)));
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }
}

#[cfg(test)]
mod test {
    use test::identity;

    #[test]
    fn certificate() {
        let (_dir, identity) = identity();
        let certificate = p!(identity.certificate());
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }

    #[test]
    fn private_key() {
        let (_dir, identity) = identity();
        p!(identity.private_key());
    }
}
