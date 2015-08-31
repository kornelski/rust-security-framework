use core_foundation_sys::base::{CFTypeID, CFTypeRef, CFRelease, CFRetain};
use core_foundation::base::TCFType;
use core_foundation::array::CFArray;
use security_framework_sys::trust::*;

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
        // FIXME after PR merges
        let certs = certs.iter().map(|c| c.as_CFType()).collect::<Vec<_>>();
        let certs = CFArray::from_CFTypes(&certs);

        unsafe {
            cvt(SecTrustSetAnchorCertificates(self.0, certs.as_concrete_TypeRef()))
        }
    }

    pub fn evaluate(&self) -> Result<TrustResult> {
        unsafe {
            let mut result = kSecTrustResultInvalid;
            try!(cvt(SecTrustEvaluate(self.0, &mut result)));
            Ok(TrustResult::from_raw(result))
        }
    }
}

impl TCFType<SecTrustRef> for SecTrust {
    #[inline]
    fn as_concrete_TypeRef(&self) -> SecTrustRef {
        self.0
    }

    #[inline]
    unsafe fn wrap_under_get_rule(reference: SecTrustRef) -> SecTrust {
        CFRetain(reference as *mut _);
        TCFType::wrap_under_create_rule(reference)
    }

    #[inline]
    fn as_CFTypeRef(&self) -> CFTypeRef {
        self.as_concrete_TypeRef() as *mut _
    }

    #[inline]
    unsafe fn wrap_under_create_rule(obj: SecTrustRef) -> SecTrust {
        SecTrust(obj)
    }

    #[inline]
    fn type_id() -> CFTypeID {
        unsafe {
            SecTrustGetTypeID()
        }
    }
}
