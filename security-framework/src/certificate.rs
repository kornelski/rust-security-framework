//! Certificate support.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use core_foundation_sys::base::kCFAllocatorDefault;
use security_framework_sys::base::{errSecParam, SecCertificateRef};
use security_framework_sys::certificate::*;
use std::fmt;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use std::ptr;

use base::{Error, Result};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::base::{CFComparisonResult, CFRelease};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::dictionary::CFDictionaryGetValueIfPresent;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::error::CFErrorRef;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::number::{kCFNumberSInt32Type, CFNumberGetValue};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::string::{CFStringCompareFlags, CFStringRef};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use cvt;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::base::{SecKeyRef, SecPolicyRef};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::item::*;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::key::{SecKeyCopyAttributes, SecKeyCopyExternalRepresentation};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::policy::SecPolicyCreateBasicX509;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::trust::{
    SecTrustCopyPublicKey, SecTrustCreateWithCertificates, SecTrustEvaluate, SecTrustRef,
    SecTrustResultType,
};

declare_TCFType! {
    /// A type representing a certificate.
    SecCertificate, SecCertificateRef
}
impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);

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
            let certificate =
                SecCertificateCreateWithData(kCFAllocatorDefault, der_data.as_concrete_TypeRef());
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
            CFData::wrap_under_create_rule(der_data).to_vec()
        }
    }

    /// Returns a human readable summary of this certificate.
    pub fn subject_summary(&self) -> String {
        unsafe {
            let summary = SecCertificateCopySubjectSummary(self.0);
            CFString::wrap_under_create_rule(summary).to_string()
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Returns DER encoded subjectPublicKeyInfo of certificate if available. This can be used
    /// for certificate pinning.
    pub fn public_key_info_der(&self) -> Result<Option<Vec<u8>>> {
        // Imported from TrustKit
        // https://github.com/datatheorem/TrustKit/blob/master/TrustKit/Pinning/TSKSPKIHashCache.m
        unsafe {
            let public_key = self.copy_public_key_from_certificate()?;
            let mut error: CFErrorRef = ptr::null_mut();
            let public_key_attributes = SecKeyCopyAttributes(public_key);

            let mut public_key_type: *const std::os::raw::c_void = ptr::null();
            let mut have_vals = true;
            have_vals = have_vals
                && CFDictionaryGetValueIfPresent(
                    public_key_attributes,
                    kSecAttrKeyType as _,
                    &mut public_key_type as _,
                ) > 0;
            let mut public_keysize: *const std::os::raw::c_void = ptr::null();
            have_vals = have_vals
                && CFDictionaryGetValueIfPresent(
                    public_key_attributes,
                    kSecAttrKeySizeInBits as _,
                    &mut public_keysize as *mut *const std::os::raw::c_void,
                ) > 0;
            CFRelease(public_key_attributes as _);
            if !have_vals {
                CFRelease(public_key as _);
                return Ok(None);
            }

            let mut public_keysize_val: u32 = 0;
            let public_keysize_val_ptr: *mut u32 = &mut public_keysize_val;
            have_vals = CFNumberGetValue(
                public_keysize as _,
                kCFNumberSInt32Type,
                public_keysize_val_ptr as _,
            );
            if !have_vals {
                CFRelease(public_key as _);
                return Ok(None);
            }
            let hdr_bytes = get_asn1_header_bytes(public_key_type as _, public_keysize_val);
            if hdr_bytes.len() == 0 {
                CFRelease(public_key as _);
                return Ok(None);
            }

            let public_key_data = SecKeyCopyExternalRepresentation(public_key, &mut error);
            if public_key_data == ptr::null() {
                CFRelease(public_key as _);
                return Ok(None);
            }

            let key_data_len = CFDataGetLength(public_key_data) as usize;
            let key_data_slice = std::slice::from_raw_parts(
                CFDataGetBytePtr(public_key_data) as *const u8,
                key_data_len,
            );
            let mut out = Vec::with_capacity(hdr_bytes.len() + key_data_len);
            out.extend_from_slice(hdr_bytes);
            out.extend_from_slice(key_data_slice);

            CFRelease(public_key_data as _);
            CFRelease(public_key as _);
            Ok(Some(out))
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    fn copy_public_key_from_certificate(&self) -> Result<SecKeyRef> {
        unsafe {
            // Create an X509 trust using the using the certificate
            let mut trust: SecTrustRef = ptr::null_mut();
            let policy: SecPolicyRef = SecPolicyCreateBasicX509();
            cvt(SecTrustCreateWithCertificates(
                self.as_concrete_TypeRef() as _,
                policy as _,
                &mut trust,
            ))?;

            // Get a public key reference for the certificate from the trust
            let mut result: SecTrustResultType = 0;
            cvt(SecTrustEvaluate(trust, &mut result))?;
            let public_key = SecTrustCopyPublicKey(trust);
            CFRelease(policy as _);
            CFRelease(trust as _);
            Ok(public_key)
        }
    }
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
fn get_asn1_header_bytes(pkt: CFStringRef, ksz: u32) -> &'static [u8] {
    unsafe {
        if CFStringCompare(pkt, kSecAttrKeyTypeRSA, 0) as i64 == 0 && ksz == 2048 {
            return &RSA_2048_ASN1_HEADER;
        }
        if CFStringCompare(pkt, kSecAttrKeyTypeRSA, 0) as i64 == 0 && ksz == 4096 {
            return &RSA_4096_ASN1_HEADER;
        }
        if CFStringCompare(pkt, kSecAttrKeyTypeECSECPrimeRandom, 0) as i64 == 0 && ksz == 256 {
            return &EC_DSA_SECP_256_R1_ASN1_HEADER;
        }
        if CFStringCompare(pkt, kSecAttrKeyTypeECSECPrimeRandom, 0) as i64 == 0 && ksz == 384 {
            return &EC_DSA_SECP_384_R1_ASN1_HEADER;
        }
    }
    &[]
}

extern "C" {
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn CFStringCompare(
        theString1: CFStringRef,
        theString2: CFStringRef,
        compareOptions: CFStringCompareFlags,
    ) -> CFComparisonResult;
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
const RSA_2048_ASN1_HEADER: [u8; 24] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
];

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
const RSA_4096_ASN1_HEADER: [u8; 24] = [
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00,
];

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
const EC_DSA_SECP_256_R1_ASN1_HEADER: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
const EC_DSA_SECP_384_R1_ASN1_HEADER: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

#[cfg(test)]
mod test {
    use test::certificate;

    #[test]
    fn subject_summary() {
        let cert = certificate();
        assert_eq!("foobar.com", cert.subject_summary());
    }
}
