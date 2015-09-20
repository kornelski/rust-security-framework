use core_foundation_sys::base::CFRelease;
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::base::SecCertificateRef;
use security_framework_sys::certificate::*;
use std::mem;
use std::ptr;

use cvt;
use base::Result;
use key::SecKey;

pub struct SecCertificate(SecCertificateRef);

impl Drop for SecCertificate {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);

impl SecCertificate {
    pub fn common_name(&self) -> Result<CFString> {
        unsafe {
            let mut string = ptr::null();
            try!(cvt(SecCertificateCopyCommonName(self.0, &mut string)));
            Ok(CFString::wrap_under_create_rule(string))
        }
    }

    pub fn public_key(&self) -> Result<SecKey> {
        unsafe {
            let mut key = ptr::null_mut();
            try!(cvt(SecCertificateCopyPublicKey(self.0, &mut key)));
            Ok(SecKey::wrap_under_create_rule(key))
        }
    }
}

#[cfg(test)]
mod test {
    use test::certificate;

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
