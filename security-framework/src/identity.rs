//! Identity support.
//!
//! Identities are a certificate paired with the corresponding private key.

use core_foundation::base::TCFType;
use security_framework_sys::base::SecIdentityRef;
use security_framework_sys::identity::*;
use std::mem;
use std::ptr;
use std::fmt;

use cvt;
use base::Result;
use certificate::SecCertificate;
use key::SecKey;

make_wrapper!(SecIdentity, SecIdentityRef, SecIdentityGetTypeID);

impl fmt::Debug for SecIdentity {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("SecIdentity");
        if let Ok(cert) = self.certificate() {
            builder.field("certificate", &cert);
        }
        if let Ok(key) = self.private_key() {
            builder.field("private_key", &key);
        }
        builder.finish()
    }
}

impl SecIdentity {
    /// Returns the certificate corresponding to this identity.
    pub fn certificate(&self) -> Result<SecCertificate> {
        unsafe {
            let mut certificate = ptr::null_mut();
            try!(cvt(SecIdentityCopyCertificate(self.0, &mut certificate)));
            Ok(SecCertificate::wrap_under_create_rule(certificate))
        }
    }

    /// Returns the private key corresponding to this identity.
    pub fn private_key(&self) -> Result<SecKey> {
        unsafe {
            let mut key = ptr::null_mut();
            try!(cvt(SecIdentityCopyPrivateKey(self.0, &mut key)));
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }
}
