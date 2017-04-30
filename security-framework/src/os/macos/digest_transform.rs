//! Digest Transform support

use core_foundation::base::{TCFType, CFIndex};
use core_foundation::data::CFData;
use core_foundation::error::CFError;
use core_foundation::string::CFString;
use core_foundation_sys::base::CFTypeRef;
use core_foundation_sys::data::CFDataRef;
use security_framework_sys::digest_transform::*;
use security_framework_sys::transform::*;
use std::ptr;

use os::macos::transform::SecTransform;

#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
/// A type of digest.
pub enum DigestType {
    HmacMd5,
    HmacSha1,
    HmacSha2,
    Md2,
    Md4,
    Md5,
    Sha1,
    Sha2,
}

impl DigestType {
    fn to_type(&self) -> CFTypeRef {
        unsafe {
            let s = match *self {
                DigestType::HmacMd5 => kSecDigestHMACMD5,
                DigestType::HmacSha1 => kSecDigestHMACSHA1,
                DigestType::HmacSha2 => kSecDigestHMACSHA2,
                DigestType::Md2 => kSecDigestMD2,
                DigestType::Md4 => kSecDigestMD4,
                DigestType::Md5 => kSecDigestMD5,
                DigestType::Sha1 => kSecDigestSHA1,
                DigestType::Sha2 => kSecDigestSHA2,
            };
            s as CFTypeRef
        }
    }
}

/// A builder for digest transform operations.
pub struct Builder {
    digest_type: Option<DigestType>,
    digest_length: Option<CFIndex>,
    hmac_key: Option<CFData>,
}

impl Default for Builder {
    fn default() -> Builder {
        Builder::new()
    }
}

impl Builder {
    /// Returns a new builder with default settings.
    pub fn new() -> Builder {
        Builder {
            digest_type: None,
            digest_length: None,
            hmac_key: None,
        }
    }

    /// Sets the type of digest to perform.
    ///
    /// If not set, an appropriate digest will be selected for you.
    pub fn type_(&mut self, digest_type: DigestType) -> &mut Builder {
        self.digest_type = Some(digest_type);
        self
    }

    /// Sets the output length of the digest.
    ///
    /// If not set, an appropriate length will be selected for you. Some digest
    /// types only support specific output lengths.
    pub fn length(&mut self, digest_length: CFIndex) -> &mut Builder {
        self.digest_length = Some(digest_length);
        self
    }

    /// Sets the key used for HMAC digests.
    ///
    /// Only applies to `HmacMd5`, `HmacSha1`, and `HmacSha2` digests.
    pub fn hmac_key(&mut self, hmac_key: CFData) -> &mut Builder {
        self.hmac_key = Some(hmac_key);
        self
    }

    /// Computes the digest of the data.
    pub fn execute(&self, data: &CFData) -> Result<CFData, CFError> {
        unsafe {
            let digest_type = match self.digest_type {
                Some(ref digest_type) => digest_type.to_type(),
                None => ptr::null(),
            };

            let digest_length = self.digest_length.unwrap_or(0);

            let mut error = ptr::null_mut();
            let transform = SecDigestTransformCreate(digest_type, digest_length, &mut error);
            if transform.is_null() {
                return Err(CFError::wrap_under_create_rule(error));
            }
            let mut transform = SecTransform::wrap_under_create_rule(transform);

            if let Some(ref hmac_key) = self.hmac_key {
                let key = CFString::wrap_under_get_rule(kSecDigestHMACKeyAttribute);
                try!(transform.set_attribute(&key, hmac_key));
            }

            let key = CFString::wrap_under_get_rule(kSecTransformInputAttributeName);
            try!(transform.set_attribute(&key, data));

            let result = try!(transform.execute());
            Ok(CFData::wrap_under_get_rule(result.as_CFTypeRef() as CFDataRef))
        }
    }
}

#[cfg(test)]
mod test {
    use core_foundation::data::CFData;
    use hex::ToHex;

    use super::*;

    #[test]
    fn md5() {
        let data = CFData::from_buffer("The quick brown fox jumps over the lazy dog".as_bytes());
        let hash = Builder::new()
                       .type_(DigestType::Md5)
                       .execute(&data)
                       .unwrap();
        assert_eq!(hash.bytes().to_hex(), "9e107d9d372bb6826bd81d3542a419d6");
    }

    #[test]
    fn hmac_sha1() {
        let data = CFData::from_buffer("The quick brown fox jumps over the lazy dog".as_bytes());
        let key = CFData::from_buffer("key".as_bytes());
        let hash = Builder::new()
                       .type_(DigestType::HmacSha1)
                       .hmac_key(key)
                       .execute(&data)
                       .unwrap();
        assert_eq!(hash.bytes().to_hex(),
                   "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    }
}
