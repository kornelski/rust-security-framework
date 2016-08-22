//! Certificate support.

use core_foundation_sys::base::kCFAllocatorDefault;
use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use security_framework_sys::base::{errSecParam, SecCertificateRef};
use security_framework_sys::certificate::*;
use std::fmt;

use base::{Error, Result};

make_wrapper! {
    /// A type representing a certificate.
    struct SecCertificate, SecCertificateRef, SecCertificateGetTypeID
}

unsafe impl Sync for SecCertificate {}
unsafe impl Send for SecCertificate {}

impl fmt::Debug for SecCertificate {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SecCertificate")
           .field("subject", &self.subject_summary())
           .finish()
    }
}

impl SecCertificate {
    /// Creates a `SecCertificate` from DER encoded certificate data.
    pub fn from_der(der_data: &[u8]) -> Result<SecCertificate> {
        let der_data = CFData::from_buffer(der_data);
        unsafe {
            let certificate = SecCertificateCreateWithData(kCFAllocatorDefault,
                                                           der_data.as_concrete_TypeRef());
            if certificate.is_null() {
                Err(Error::from_code(errSecParam))
            } else {
                Ok(SecCertificate::wrap_under_create_rule(certificate))
            }
        }
    }

    /// Returns DER encoded data describing this certificate.
    pub fn to_der(&self) -> Vec<u8> {
        unsafe {
            let der_data = SecCertificateCopyData(self.0);
            CFData::wrap_under_create_rule(der_data).to_owned()
        }
    }

    /// Returns a human readable summary of this certificate.
    pub fn subject_summary(&self) -> String {
        unsafe {
            let summary = SecCertificateCopySubjectSummary(self.0);
            CFString::wrap_under_create_rule(summary).to_string()
        }
    }
}

#[cfg(test)]
mod test {
    use test::certificate;

    #[test]
    fn subject_summary() {
        let cert = certificate();
        assert_eq!("foobar.com", cert.subject_summary());
    }
}
