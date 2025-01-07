//! Encryption key support

use crate::cvt;
use core_foundation::{
    base::TCFType, string::{CFStringRef, CFString},
    dictionary::CFMutableDictionary,
};
use core_foundation::base::ToVoid;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use core_foundation::boolean::CFBoolean;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use core_foundation::data::CFData;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use core_foundation::dictionary::CFDictionary;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use core_foundation::number::CFNumber;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use core_foundation::error::{CFError, CFErrorRef};

use security_framework_sys::{
    item::{kSecAttrKeyTypeRSA, kSecValueRef},
    keychain_item::SecItemDelete,
    key::SecKeyCopyKeyExchangeResult
};
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use security_framework_sys::{item::{
    kSecAttrIsPermanent, kSecAttrLabel, kSecAttrKeyType,
    kSecAttrKeySizeInBits, kSecPrivateKeyAttrs, kSecAttrAccessControl
}};
#[cfg(any(feature = "OSX_10_13", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use security_framework_sys::item::kSecAttrSynchronizable;
#[cfg(target_os = "macos")]
use security_framework_sys::item::{
    kSecAttrKeyType3DES, kSecAttrKeyTypeDSA, kSecAttrKeyTypeAES,
    kSecAttrKeyTypeDES, kSecAttrKeyTypeRC4, kSecAttrKeyTypeCAST,
};

use security_framework_sys::base::SecKeyRef;
use security_framework_sys::key::SecKeyGetTypeID;

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub use security_framework_sys::key::Algorithm;

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use security_framework_sys::key::{
    SecKeyCopyAttributes, SecKeyCopyExternalRepresentation,
    SecKeyCreateSignature, SecKeyCreateRandomKey,
    SecKeyCopyPublicKey,
    SecKeyCreateDecryptedData, SecKeyCreateEncryptedData,
};
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use security_framework_sys::item::kSecAttrApplicationLabel;
use std::fmt;


use crate::base::Error;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use crate::item::Location;
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
use crate::access_control::SecAccessControl;
/// Types of `SecKey`s.
#[derive(Debug, Copy, Clone)]
pub struct KeyType(CFStringRef);

#[allow(missing_docs)]
impl KeyType {
    #[inline(always)]
    #[must_use]
    pub fn rsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeRSA) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn dsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeDSA) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn aes() -> Self {
        unsafe { Self(kSecAttrKeyTypeAES) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn des() -> Self {
        unsafe { Self(kSecAttrKeyTypeDES) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn triple_des() -> Self {
        unsafe { Self(kSecAttrKeyType3DES) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn rc4() -> Self {
        unsafe { Self(kSecAttrKeyTypeRC4) }
    }

    #[cfg(target_os = "macos")]
    #[inline(always)]
    #[must_use]
    pub fn cast() -> Self {
        unsafe { Self(kSecAttrKeyTypeCAST) }
    }

    #[inline(always)]
    #[must_use]
    pub fn ec() -> Self {
        use security_framework_sys::item::kSecAttrKeyTypeEC;

        unsafe { Self(kSecAttrKeyTypeEC) }
    }

    #[inline(always)]
    #[must_use]
    pub fn ec_sec_prime_random() -> Self {
        use security_framework_sys::item::kSecAttrKeyTypeECSECPrimeRandom;

        unsafe { Self(kSecAttrKeyTypeECSECPrimeRandom) }
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
    /// Translates to `SecKeyCreateRandomKey`
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    #[allow(deprecated)]
    #[doc(alias = "SecKeyCreateRandomKey")]
    pub fn new(options: &GenerateKeyOptions) -> Result<Self, CFError> {
        Self::generate(options.to_dictionary())
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCreateRandomKey`
    /// `GenerateKeyOptions` provides a helper to create an attribute `CFDictionary`.
    #[deprecated(note = "Use SecKey::new")]
    pub fn generate(attributes: CFDictionary) -> Result<Self, CFError> {
        let mut error: CFErrorRef = ::std::ptr::null_mut();
        let sec_key = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error) };
        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            Ok(unsafe { Self::wrap_under_create_rule(sec_key) })
        }
    }

    /// Returns the programmatic identifier for the key. For keys of class
    /// kSecAttrKeyClassPublic and kSecAttrKeyClassPrivate, the value is the
    /// hash of the public key.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    #[must_use]
    pub fn application_label(&self) -> Option<Vec<u8>> {
        self.attributes()
            .find(unsafe { kSecAttrApplicationLabel.to_void() })
            .map(|v| unsafe { CFData::wrap_under_get_rule(v.cast()) }.to_vec())
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCopyAttributes`
    // TODO: deprecate and remove. CFDictionary should not be exposed in public Rust APIs.
    #[must_use]
    pub fn attributes(&self) -> CFDictionary {
        let pka = unsafe { SecKeyCopyAttributes(self.to_void() as _) };
        unsafe { CFDictionary::wrap_under_create_rule(pka) }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCopyExternalRepresentation`
    // TODO: deprecate and remove. CFData should not be exposed in public Rust APIs.
    #[must_use]
    pub fn external_representation(&self) -> Option<CFData> {
        let mut error: CFErrorRef = ::std::ptr::null_mut();
        let data = unsafe { SecKeyCopyExternalRepresentation(self.to_void() as _, &mut error) };
        if data.is_null() {
            return None;
        }
        Some(unsafe { CFData::wrap_under_create_rule(data) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Translates to `SecKeyCopyPublicKey`
    #[must_use]
    pub fn public_key(&self) -> Option<Self> {
        let pub_seckey = unsafe { SecKeyCopyPublicKey(self.0.cast()) };
        if pub_seckey.is_null() {
            return None;
        }

        Some(unsafe { Self::wrap_under_create_rule(pub_seckey) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Encrypts a block of data using a public key and specified algorithm
    pub fn encrypt_data(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateEncryptedData(self.as_concrete_TypeRef(), algorithm.into(), CFData::from_buffer(input).as_concrete_TypeRef(), &mut error)
        };

        if error.is_null() {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        } else {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Decrypts a block of data using a private key and specified algorithm
    pub fn decrypt_data(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateDecryptedData(self.as_concrete_TypeRef(), algorithm.into(), CFData::from_buffer(input).as_concrete_TypeRef(), &mut error)
        };

        if error.is_null() {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        } else {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    /// Creates the cryptographic signature for a block of data using a private
    /// key and specified algorithm.
    pub fn create_signature(&self, algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateSignature(
                self.as_concrete_TypeRef(),
                algorithm.into(),
                CFData::from_buffer(input).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if error.is_null() {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        } else {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        }
    }

    /// Verifies the cryptographic signature for a block of data using a public
    /// key and specified algorithm.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn verify_signature(&self, algorithm: Algorithm, signed_data: &[u8], signature: &[u8]) -> Result<bool, CFError> {
        use security_framework_sys::key::SecKeyVerifySignature;
        let mut error: CFErrorRef = std::ptr::null_mut();

        let valid = unsafe {
            SecKeyVerifySignature(
                self.as_concrete_TypeRef(),
                algorithm.into(),
                CFData::from_buffer(signed_data).as_concrete_TypeRef(),
                CFData::from_buffer(signature).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            return Err(unsafe { CFError::wrap_under_create_rule(error) })?;
        }
        Ok(valid != 0)
    }

    /// Performs the Diffie-Hellman style of key exchange.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
    pub fn key_exchange(
        &self,
        algorithm: Algorithm,
        public_key: &Self,
        requested_size: usize,
        shared_info: Option<&[u8]>,
    ) -> Result<Vec<u8>, CFError> {
        use core_foundation::data::CFData;
        use security_framework_sys::item::{
            kSecKeyKeyExchangeParameterRequestedSize, kSecKeyKeyExchangeParameterSharedInfo,
        };

        unsafe {
            let mut params = vec![(
                CFString::wrap_under_get_rule(kSecKeyKeyExchangeParameterRequestedSize),
                CFNumber::from(requested_size as i64).into_CFType(),
            )];

            if let Some(shared_info) = shared_info {
                params.push((
                    CFString::wrap_under_get_rule(kSecKeyKeyExchangeParameterSharedInfo),
                    CFData::from_buffer(shared_info).as_CFType(),
                ));
            };

            let parameters = CFDictionary::from_CFType_pairs(&params);

            let mut error: CFErrorRef = std::ptr::null_mut();

            let output = SecKeyCopyKeyExchangeResult(
                self.as_concrete_TypeRef(),
                algorithm.into(),
                public_key.as_concrete_TypeRef(),
                parameters.as_concrete_TypeRef(),
                &mut error,
            );

            if error.is_null() {
                let output = CFData::wrap_under_create_rule(output);
                Ok(output.to_vec())
            } else {
                Err(CFError::wrap_under_create_rule(error))
            }
        }
    }

    /// Translates to `SecItemDelete`, passing in the `SecKeyRef`
    pub fn delete(&self) -> Result<(), Error> {
        let query = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecValueRef }.to_void(),
            self.to_void(),
        )]);

        cvt(unsafe { SecItemDelete(query.as_concrete_TypeRef()) })
    }
}

/// Where to generate the key.
#[derive(Debug)]
pub enum Token {
    /// Generate the key in software, compatible with all `KeyType`s.
    Software,
    /// Generate the key in the Secure Enclave such that the private key is not
    /// extractable. Only compatible with `KeyType::ec()`.
    SecureEnclave,
}

/// Helper for creating `CFDictionary` attributes for `SecKey::generate`
/// Recommended reading:
/// <https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains>
#[derive(Debug, Default)]
#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
pub struct GenerateKeyOptions {
    /// kSecAttrKeyType
    #[deprecated(note = "use set_key_type()")]
    pub key_type: Option<KeyType>,
    /// kSecAttrKeySizeInBits
    #[deprecated(note = "use set_size_in_bits()")]
    pub size_in_bits: Option<u32>,
    /// kSecAttrLabel
    #[deprecated(note = "use set_label()")]
    pub label: Option<String>,
    /// kSecAttrTokenID
    #[deprecated(note = "use set_token()")]
    pub token: Option<Token>,
    /// Which keychain to store the key in, if any.
    #[deprecated(note = "use set_location()")]
    pub location: Option<Location>,
    /// Access control
    #[deprecated(note = "use set_access_control()")]
    pub access_control: Option<SecAccessControl>,
    /// kSecAttrSynchronizable
    #[cfg(all(feature = "sync-keychain", any(target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
    pub synchronizable: Option<bool>,
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
#[allow(deprecated)]
impl GenerateKeyOptions {
    /// Set `key_type`
    pub fn set_key_type(&mut self, key_type: KeyType) -> &mut Self {
        self.key_type = Some(key_type);
        self
    }

    /// Set `size_in_bits`
    pub fn set_size_in_bits(&mut self, size_in_bits: u32) -> &mut Self {
        self.size_in_bits = Some(size_in_bits);
        self
    }

    /// Set `label`
    pub fn set_label(&mut self, label: impl Into<String>) -> &mut Self {
        self.label = Some(label.into());
        self
    }

    /// Set `token`
    pub fn set_token(&mut self, token: Token) -> &mut Self {
        self.token = Some(token);
        self
    }

    /// Set `location`
    pub fn set_location(&mut self, location: Location) -> &mut Self {
        self.location = Some(location);
        self
    }

    /// Set `access_control`
    pub fn set_access_control(&mut self, access_control: SecAccessControl) -> &mut Self {
        self.access_control = Some(access_control);
        self
    }

    /// Set `synchronizable`
    #[cfg(all(feature = "sync-keychain", any(target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
    pub fn set_synchronizable(&mut self, synchronizable: bool) -> &mut Self {
        self.synchronizable = Some(synchronizable);
        self
    }

    /// Collect options into a `CFDictioanry`
    // CFDictionary should not be exposed in public Rust APIs.
    #[deprecated(note = "Pass the options to SecKey::new")]
    pub fn to_dictionary(&self) -> CFDictionary {
        #[cfg(target_os = "macos")]
        use security_framework_sys::item::kSecUseKeychain;
        use security_framework_sys::item::{
            kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecPublicKeyAttrs,
        };

        let is_permanent = CFBoolean::from(self.location.is_some());
        let mut private_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            is_permanent.to_void(),
        )]);
        if let Some(access_control) = &self.access_control {
            private_attributes.set(unsafe { kSecAttrAccessControl }.to_void(), access_control.to_void());
        }

        let public_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            is_permanent.to_void(),
        )]);

        let key_type = self.key_type.unwrap_or_else(KeyType::rsa).to_str();

        let size_in_bits = self.size_in_bits.unwrap_or(match () {
            #[cfg(target_os = "macos")]
            _ if key_type == KeyType::aes().to_str() => 256,
            _ if key_type == KeyType::rsa().to_str() => 2048,
            _ if key_type == KeyType::ec().to_str() => 256,
            _ if key_type == KeyType::ec_sec_prime_random().to_str() => 256,
            _ => 256,
        });
        let size_in_bits = CFNumber::from(size_in_bits as i32);

        let mut attribute_key_values = vec![
            (unsafe { kSecAttrKeyType }.to_void(), key_type.to_void()),
            (unsafe { kSecAttrKeySizeInBits }.to_void(), size_in_bits.to_void()),
        ];
        #[cfg(target_os = "macos")]
        if key_type != KeyType::aes().to_str() {
                attribute_key_values.push((unsafe { kSecPublicKeyAttrs }.to_void(), public_attributes.to_void()));
                attribute_key_values.push((unsafe { kSecPrivateKeyAttrs }.to_void(), private_attributes.to_void()));
        }

        let label = self.label.as_deref().map(CFString::new);
        if let Some(label) = &label {
            attribute_key_values.push((unsafe { kSecAttrLabel }.to_void(), label.to_void()));
        }

        #[cfg(target_os = "macos")]
        match &self.location {
            #[cfg(feature = "OSX_10_15")]
            Some(Location::DataProtectionKeychain) => {
                use security_framework_sys::item::kSecUseDataProtectionKeychain;
                attribute_key_values.push((
                    unsafe { kSecUseDataProtectionKeychain }.to_void(),
                    CFBoolean::true_value().to_void(),
                ));
            }
            Some(Location::FileKeychain(keychain)) => {
                attribute_key_values.push((
                    unsafe { kSecUseKeychain }.to_void(),
                    keychain.as_concrete_TypeRef().to_void(),
                ));
            }
            _ => {}
        }

        match self.token.as_ref().unwrap_or(&Token::Software) {
            Token::Software => {},
            Token::SecureEnclave => {
                attribute_key_values.push((
                    unsafe { kSecAttrTokenID }.to_void(),
                    unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
                ));
            }
        }

        #[cfg(all(feature = "sync-keychain", any(target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
        if let Some(ref synchronizable) = self.synchronizable {
            attribute_key_values.push((
                 unsafe { kSecAttrSynchronizable }.to_void(),
                (if *synchronizable {
                    CFBoolean::true_value()
                } else {
                    CFBoolean::false_value()
                })
                .to_void(),
            ));
        }

        CFMutableDictionary::from_CFType_pairs(&attribute_key_values).to_immutable()
    }
}

impl fmt::Debug for SecKey {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SecKey").finish_non_exhaustive()
    }
}
