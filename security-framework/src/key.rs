//! Encryption key support

use core_foundation::{
    base::TCFType, string::{CFStringRef, CFString},
    boolean::CFBoolean, dictionary::CFMutableDictionary, number::CFNumber,
};
use core_foundation::base::ToVoid;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::data::CFData;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::dictionary::CFDictionary;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::error::{CFError, CFErrorRef};

use security_framework_sys::{item::{
    kSecAttrKeyTypeRSA, kSecAttrIsPermanent, kSecAttrLabel, kSecAttrKeyType,
    kSecAttrKeySizeInBits, kSecPrivateKeyAttrs, kSecValueRef,
}, keychain_item::SecItemDelete};
#[cfg(target_os="macos")]
use security_framework_sys::item::{
    kSecAttrKeyType3DES, kSecAttrKeyTypeDSA, kSecAttrKeyTypeAES,
    kSecAttrKeyTypeDES, kSecAttrKeyTypeRC4, kSecAttrKeyTypeCAST,
};

use security_framework_sys::key::SecKeyGetTypeID;
use security_framework_sys::base::SecKeyRef;

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::key::{
    SecKeyCopyAttributes, SecKeyCopyExternalRepresentation,
    SecKeyCreateSignature, Algorithm, SecKeyCreateRandomKey,
    SecKeyCopyPublicKey,
};
use std::fmt;

use crate::base::Error;

/// Types of `SecKey`s.
#[derive(Debug, Copy, Clone)]
pub struct KeyType(CFStringRef);

#[allow(missing_docs)]
impl KeyType {
    #[inline(always)]
    pub fn rsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeRSA) }
    }

    #[cfg(target_os="macos")]
    #[inline(always)]
    pub fn dsa() -> Self {
        unsafe { Self(kSecAttrKeyTypeDSA) }
    }

    #[cfg(target_os="macos")]
    #[inline(always)]
    pub fn aes() -> Self {
        unsafe { Self(kSecAttrKeyTypeAES) }
    }

    #[cfg(target_os="macos")]
    #[inline(always)]
    pub fn des() -> Self {
        unsafe { Self(kSecAttrKeyTypeDES) }
    }

    #[cfg(target_os="macos")]
    #[inline(always)]
    pub fn triple_des() -> Self {
        unsafe { Self(kSecAttrKeyType3DES) }
    }

    #[cfg(target_os="macos")]
    #[inline(always)]
    pub fn rc4() -> Self {
        unsafe { Self(kSecAttrKeyTypeRC4) }
    }

    #[cfg(target_os="macos")]
    #[inline(always)]
    pub fn cast() -> Self {
        unsafe { Self(kSecAttrKeyTypeCAST) }
    }

    #[cfg(any(feature = "OSX_10_9", target_os="ios"))]
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

/// Whether to store the key in a keychain. 
pub enum StoreInKeychain {
    /// Don't store the key.
    None, 
    /// Store in the default keychain. On iOS, there is only one keychain. On
    /// macOS, defaults to the Login keychain.
    Default, 
    #[cfg(target_os="macos")]
    /// Store the key in a specific keychain.
    Keychain(crate::os::macos::keychain::SecKeychain),
}

/// Options related to key storage. Recommended reading:
/// https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
pub struct Persistence {
    /// Where to generate the key.
    pub token: Token,
    /// Where to store the key.
    pub location: Location
}

/// Which, if any, keychain to store the key in.
pub enum Location {
    /// Don't store the key.
    None,
    /// Store the key in the newer DataProtectionKeychain. This is the only
    /// keychain on iOS. On macOS, this is the newer and more consistent
    /// keychain implementation. Keys stored in the Secure Enclave _must_ use
    /// this keychain.
    /// 
    /// This keychain requires the calling binary to be codesigned with
    /// entitlements for the KeychainAccessGroups it is supposed to
    /// access.
    #[cfg(any(feature = "OSX_10_15", target_os="ios"))]
    DataProtectionKeychain,
    /// Store the key in the default file-based keychain. On
    /// macOS, defaults to the Login keychain.
    #[cfg(target_os="macos")]
    DefaultFileKeychain,
    /// Store the key in a specific file-based keychain.
    #[cfg(target_os="macos")]
    FileKeychain(crate::os::macos::keychain::SecKeychain)
}

/// Where to generate the key.
pub enum Token {
    /// Generate the key in software, compatible with all `KeyType`s.
    Software, 
    /// Generate the key in the Secure Enclave such that the private key is not
    /// extractable. Only compatible with `KeyType::ec()`.
    SecureEnclave,
}

impl SecKey {
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCreateRandomKey
    pub fn generate(key_type : KeyType, size_in_bits: u32, label: Option<&str>, persistence: Persistence) -> Result<Self, CFError> {
        use security_framework_sys::item::{kSecUseKeychain, kSecUseDataProtectionKeychain, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecPublicKeyAttrs};
        let private_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            match persistence.location {
                Location::None => CFBoolean::false_value(),
                _ => CFBoolean::true_value(),
            }.to_void()
        )]);

        let public_attributes = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrIsPermanent }.to_void(),
            match persistence.location {
                Location::None => CFBoolean::false_value(),
                _ => CFBoolean::true_value(),
            }.to_void()
        )]);

        //  Keep attributes alive until after SecKeyCreateRandomKey is called
        let key_type = key_type.to_str();
        let size_in_bits = CFNumber::from(size_in_bits as i32);
        let mut attribute_key_values = vec![
            (unsafe{ kSecAttrKeyType}.to_void(), key_type.to_void()),
            (
                unsafe { kSecAttrKeySizeInBits }.to_void(),
                size_in_bits.to_void(),
            ),
            (
                unsafe { kSecPrivateKeyAttrs }.to_void(),
                private_attributes.to_void(),
            ),
            (
                unsafe { kSecPublicKeyAttrs }.to_void(),
                public_attributes.to_void(),
            ),
        ];
        let label = label.map(CFString::new);
        if let Some(label) = &label {
            attribute_key_values.push((unsafe{ kSecAttrLabel}.to_void(), label.to_void()));
        }

        #[cfg(target_os="macos")]
        match &persistence.location {
            #[cfg(feature = "OSX_10_15")]
            Location::DataProtectionKeychain =>{
                attribute_key_values.push(( unsafe{ kSecUseDataProtectionKeychain }.to_void(), CFBoolean::true_value().to_void()));
            }
            Location::FileKeychain(keychain) => {
                attribute_key_values.push(( unsafe{ kSecUseKeychain }.to_void(), keychain.as_concrete_TypeRef().to_void()));
            }
            _ => {}
        }

        match persistence.token {
            Token::Software => {},
            Token::SecureEnclave => {
                attribute_key_values.push(( unsafe{ kSecAttrTokenID }.to_void(), unsafe {kSecAttrTokenIDSecureEnclave}.to_void()));
            }
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
    /// Translates to SecKeyCopyPublicKey
    pub fn public_key(&self) -> Result<Option<Self>, CFError> {
        let mut error: CFErrorRef = ::std::ptr::null_mut();

        let pub_seckey = unsafe {SecKeyCopyPublicKey(self.0 as *mut _, &mut error)};
        if !error.is_null() {
            return Err(unsafe { CFError::wrap_under_create_rule(error) })
        }
        if pub_seckey.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { SecKey::wrap_under_create_rule(pub_seckey)}))
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

    /// Verifies the cryptographic signature for a block of data using a public
    /// key and specified algorithm.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn verify_signature(
        &self,
        algorithm: Algorithm,
        signed_data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<bool, CFError> {
        use security_framework_sys::key::SecKeyVerifySignature;
        let mut error: CFErrorRef = std::ptr::null_mut();

        let valid = unsafe { SecKeyVerifySignature(
            self.as_concrete_TypeRef(),
            algorithm.into(),
            CFData::from_buffer(signed_data.as_ref()).as_concrete_TypeRef(),
            CFData::from_buffer(signature.as_ref()).as_concrete_TypeRef(),
            &mut error,
        )};

        if !error.is_null() {
            return Err(unsafe { CFError::wrap_under_create_rule(error) })?;
        }
        return Ok(valid != 0)
    }

    /// Translates to SecItemDelete, passing in the SecKeyRef
    pub fn delete(&self) -> Result<(), Error> {
        let query = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecValueRef }.to_void(),
            self.to_void(),
        )]);

        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status != 0 {
            return Err(status.into())
        }
        Ok(())
    }
}

// FIXME
impl fmt::Debug for SecKey {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}
