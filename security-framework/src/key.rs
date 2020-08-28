//! Encryption key support

use core_foundation::base::TCFType;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::base::ToVoid;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::data::CFData;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::item::{kSecAttrKeySizeInBits, kSecAttrKeyType};
use security_framework_sys::key::SecKeyGetTypeID;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::key::{SecKeyCopyAttributes, SecKeyCopyExternalRepresentation};
use std::fmt;

declare_TCFType! {
    /// A type representing an encryption key.
    SecKey, SecKeyRef
}
impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);

unsafe impl Sync for SecKey {}
unsafe impl Send for SecKey {}

impl SecKey {
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCopyAttributes
    pub fn attributes(&self) -> CFDictionary {
        let pka = unsafe { SecKeyCopyAttributes(self.to_void() as _) };
        unsafe { CFDictionary::wrap_under_create_rule(pka) }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCopyExternalRepresentation
    pub fn external_representation(&self) -> Option<CFData> {
        let mut error: CFErrorRef = ::std::ptr::null_mut();
        let data = unsafe { SecKeyCopyExternalRepresentation(self.to_void() as _, &mut error) };
        if data == ::std::ptr::null() {
            return None;
        }
        Some(unsafe { CFData::wrap_under_create_rule(data) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCreateRandom
    ///
    /// Creates a random `SecKey`.
    pub fn random(
        key_type: KeyType,
        key_size: CFNumber,
        attributes: Option<CFDictionary>,
    ) -> Result<Self, CFError> {
        unsafe {
            let key_type = (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                key_type.to_str(),
            );
            let key_size = (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                key_size.to_str(),
            );
            let parameters = attributes
                .map(|p| {
                    let mut p = p.to_mutable();
                    (&mut p).add(key_type.0, key_type.1);
                    (&mut p).add(key_size.0, key_size.1);
                    p.to_immutable()
                })
                .unwrap_or(CFDictionary::from_CFType_pairs(&[key_type, key_size]));

            let mut err = ::std::ptr::null_mut();
            let key = SecKeyCreateRandom(parameters.as_concrete_TypeRef(), &mut err);
            if key.is_null() {
                Err(CFError::wrap_under_create_rule(err))
            } else {
                Ok(Self::wrap_under_create_rule(key))
            }
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCopyPublicKey
    ///
    /// Gets the public key associated with the given private key.
    fn public_key(&self) -> Option<Self> {
        let key = unsafe { SecKeyCopyPublicKey(self.to_void() as _) };
        if key == ::std::ptr::null() {
            None
        } else {
            Some(unsafe { Self::wrap_under_create_rule(key) })
        }
    }
}

// FIXME
impl fmt::Debug for SecKey {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}
