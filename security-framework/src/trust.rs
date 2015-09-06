use core_foundation_sys::base::{Boolean, CFRelease};
use core_foundation::base::TCFType;
use core_foundation::array::CFArray;
use security_framework_sys::trust::*;
use std::mem;

use cvt;
use base::Result;
use certificate::SecCertificate;

pub enum TrustResult {
    Invalid,
    Proceed,
    Deny,
    Unspecified,
    RecoverableTrustFailure,
    FatalTrustFailure,
    OtherError,
}

impl TrustResult {
    fn from_raw(raw: SecTrustResultType) -> TrustResult {
        match raw {
            kSecTrustResultInvalid => TrustResult::Invalid,
            kSecTrustResultProceed => TrustResult::Proceed,
            kSecTrustResultDeny => TrustResult::Deny,
            kSecTrustResultUnspecified => TrustResult::Unspecified,
            kSecTrustResultRecoverableTrustFailure => TrustResult::RecoverableTrustFailure,
            kSecTrustResultFatalTrustFailure => TrustResult::FatalTrustFailure,
            kSecTrustResultOtherError => TrustResult::OtherError,
            raw => panic!("unexpected value {}", raw),
        }
    }

    pub fn success(&self) -> bool {
        match *self {
            TrustResult::Proceed | TrustResult::Unspecified => true,
            _ => false,
        }
    }
}

pub struct SecTrust(SecTrustRef);

impl Drop for SecTrust {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0 as *mut _); }
    }
}

impl SecTrust {
    pub fn set_anchor_certificates(&self, certs: &[SecCertificate]) -> Result<()> {
        let certs = CFArray::from_CFTypes(&certs);

        unsafe {
            cvt(SecTrustSetAnchorCertificates(self.0, certs.as_concrete_TypeRef()))
        }
    }

    pub fn trust_anchor_certificates_only(&self, only: bool) -> Result<()> {
        unsafe { cvt(SecTrustSetAnchorCertificatesOnly(self.0, only as Boolean)) }
    }

    pub fn evaluate(&self) -> Result<TrustResult> {
        unsafe {
            let mut result = kSecTrustResultInvalid;
            try!(cvt(SecTrustEvaluate(self.0, &mut result)));
            Ok(TrustResult::from_raw(result))
        }
    }
}

impl_TCFType!(SecTrust, SecTrustRef, SecTrustGetTypeID);
