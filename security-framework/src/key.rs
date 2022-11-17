//! Encryption key support

use core_foundation::{
    base::TCFType, string::{CFStringRef, CFString},
    boolean::CFBoolean, dictionary::CFMutableDictionary, number::CFNumber,
};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::base::ToVoid;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::data::CFData;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::dictionary::CFDictionary;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::error::{CFError, CFErrorRef};

use security_framework_sys::base::SecKeyRef;
use security_framework_sys::item::{
    kSecAttrKeyType3DES, kSecAttrKeyTypeRSA, kSecAttrKeyTypeDSA, kSecAttrKeyTypeAES,
    kSecAttrKeyTypeDES, kSecAttrKeyTypeRC4, kSecAttrKeyTypeCAST, kSecAttrIsPermanent,
    kSecAttrLabel, kSecAttrKeyType, kSecAttrKeySizeInBits, kSecPrivateKeyAttrs,
};

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub use security_framework_sys::key::{Algorithm, SecKeyCreateRandomKey};
use security_framework_sys::key::SecKeyGetTypeID;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::key::{
    SecKeyCopyAttributes, SecKeyCopyExternalRepresentation, SecKeyCreateSignature,
};
use std::fmt;

/// Types of `SecKey`s.
#[derive(Debug, Copy, Clone)]
pub struct KeyType(CFStringRef);

#[allow(missing_docs)]
impl KeyType {
    #[inline(always)]
    pub fn rsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeRSA) }
    }

    #[inline(always)]
    pub fn dsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeDSA) }
    }

    #[inline(always)]
    pub fn aes() -> Self {
        unsafe { Self(kSecAttrKeyTypeAES) }
    }

    #[inline(always)]
    pub fn des() -> Self {
        unsafe { Self(kSecAttrKeyTypeDES) }
    }

    #[inline(always)]
    pub fn triple_des() -> Self {
        unsafe { Self(kSecAttrKeyType3DES) }
    }

    #[inline(always)]
    pub fn rc4() -> Self {
        unsafe { Self(kSecAttrKeyTypeRC4) }
    }

    #[inline(always)]
    pub fn cast() -> Self {
        unsafe { Self(kSecAttrKeyTypeCAST) }
    }

    #[cfg(feature = "OSX_10_9")]
    #[inline(always)]
    pub fn ec() -> Self {
        use security_framework_sys::item::kSecAttrKeyTypeEC;

        unsafe { Self(kSecAttrKeyTypeEC) }
    }

    pub(crate) fn to_str(self) -> CFString {
        unsafe { CFString::wrap_under_get_rule(self.0) }
    }
}

declare_TCFType! {
    /// A type representing an encryption key.
    SecKey, SecKeyRef
}
impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);

unsafe impl Sync for SecKey {}
unsafe impl Send for SecKey {}

impl SecKey {
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCreateRandomKey
    pub fn generate(key_type : KeyType, size_in_bits: u32, label: Option<&str>, store_in_keychain: bool) -> Result<Self, CFError> {
        
        let private_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent } as *const _,
            if store_in_keychain{CFBoolean::true_value()} else {CFBoolean::false_value()}.to_void(),
        )]);

        //  keep attributes alive until after SecKeyCreateRandomKey is called
        let key_type = key_type.to_str();
        let size_in_bits = CFNumber::from(size_in_bits as i32);
        let mut attribute_key_values = vec![
            (unsafe{ kSecAttrKeyType} as *const _, key_type.to_void()),
            (
                unsafe { kSecAttrKeySizeInBits } as *const _,
                size_in_bits.to_void(),
            ),
            (
                unsafe { kSecPrivateKeyAttrs } as *const _,
                private_attributes.to_void(),
            ),
        ];
        let label = label.map(CFString::new);
        if let Some(label) = &label {
            attribute_key_values.push((unsafe{ kSecAttrLabel} as *const _, label.to_void()));
        }

        let attributes = CFMutableDictionary::from_CFType_pairs(&attribute_key_values);

        let mut error: CFErrorRef = ::std::ptr::null_mut();
        let sec_key = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error)};
        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            Ok(unsafe { SecKey::wrap_under_create_rule(sec_key) })
        }
    }

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
        if data.is_null() {
            return None;
        }
        Some(unsafe { CFData::wrap_under_create_rule(data) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Creates the cryptographic signature for a block of data using a private
    /// key and specified algorithm.
    pub fn create_signature(
        &self,
        algorithm: Algorithm,
        input: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateSignature(
                self.as_concrete_TypeRef(),
                algorithm.into(),
                CFData::from_buffer(input.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        }
    }
}

// FIXME
impl fmt::Debug for SecKey {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}
