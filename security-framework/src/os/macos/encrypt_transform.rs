//! Encryption and Decryption transform support.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::data::CFDataRef;
use security_framework_sys::encrypt_transform::*;
use security_framework_sys::transform::*;
use std::ptr;

use os::macos::digest_transform::DigestType;
use os::macos::transform::SecTransform;
use key::SecKey;

#[derive(Debug, Copy, Clone)]
pub enum Padding {
    None,
    Pkcs1,
    Pkcs5,
    Pkcs7,
    #[cfg(feature = "OSX_10_8")]
    Oaep,
}

impl Padding {
    fn to_str(&self) -> CFString {
        let raw = match *self {
            Padding::None => kSecPaddingNoneKey,
            Padding::Pkcs1 => kSecPaddingPKCS1Key,
            Padding::Pkcs5 => kSecPaddingPKCS5Key,
            Padding::Pkcs7 => kSecPaddingPKCS7Key,
            #[cfg(feature = "OSX_10_8")]
            Padding::Oaep => kSecPaddingOAEPKey,
        };
        unsafe { CFString::wrap_under_get_rule(raw) }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Mode {
    None,
    Ecb,
    Cbc,
    Cfb,
    Ofb,
}

impl Mode {
    fn to_str(&self) -> CFString {
        let raw = match *self {
            Mode::None => kSecModeNoneKey,
            Mode::Ecb => kSecModeECBKey,
            Mode::Cbc => kSecModeCBCKey,
            Mode::Cfb => kSecModeCFBKey,
            Mode::Ofb => kSecModeOFBKey,
        };
        unsafe { CFString::wrap_under_get_rule(raw) }
    }
}

#[derive(Default)]
pub struct Builder {
    padding: Option<Padding>,
    mode: Option<Mode>,
    iv: Option<CFData>,
    #[cfg(feature = "OSX_10_8")]
    oaep_message_length: Option<CFNumber>,
    #[cfg(feature = "OSX_10_8")]
    oaep_encoding_parameters: Option<CFData>,
    #[cfg(feature = "OSX_10_8")]
    oaep_mgf1_digest_algorithm: Option<DigestType>,
}

impl Builder {
    pub fn new() -> Builder {
        Builder::default()
    }

    pub fn padding(&mut self, padding: Padding) -> &mut Builder {
        self.padding = Some(padding);
        self
    }

    pub fn mode(&mut self, mode: Mode) -> &mut Builder {
        self.mode = Some(mode);
        self
    }

    pub fn iv(&mut self, iv: CFData) -> &mut Builder {
        self.iv = Some(iv);
        self
    }

    #[cfg(feature = "OSX_10_8")]
    pub fn oaep_message_length(&mut self, oaep_message_length: CFNumber) -> &mut Builder {
        self.oaep_message_length = Some(oaep_message_length);
        self
    }

    #[cfg(feature = "OSX_10_8")]
    pub fn oaep_encoding_parameters(&mut self, oaep_encoding_parameters: CFData) -> &mut Builder {
        self.oaep_encoding_parameters = Some(oaep_encoding_parameters);
        self
    }

    #[cfg(feature = "OSX_10_8")]
    pub fn oaep_mgf1_digest_algorithm(&mut self,
                                      oaep_mgf1_digest_algorithm: DigestType)
                                      -> &mut Builder {
        self.oaep_mgf1_digest_algorithm = Some(oaep_mgf1_digest_algorithm);
        self
    }

    pub fn encrypt(&self, key: &SecKey, data: &CFData) -> Result<CFData, CFError> {
        unsafe {
            let mut error = ptr::null_mut();
            let transform = SecEncryptTransformCreate(key.as_concrete_TypeRef(), &mut error);
            if transform.is_null() {
                return Err(CFError::wrap_under_create_rule(error));
            }
            let transform = SecTransform::wrap_under_create_rule(transform);

            self.finish(transform, data)
        }
    }

    fn finish(&self, mut transform: SecTransform, data: &CFData) -> Result<CFData, CFError> {
        unsafe {
            if let Some(ref padding) = self.padding {
                let key = CFString::wrap_under_get_rule(kSecPaddingKey);
                try!(transform.set_attribute(&key, &padding.to_str()));
            }

            if let Some(ref mode) = self.mode {
                let key = CFString::wrap_under_get_rule(kSecEncryptionMode);
                try!(transform.set_attribute(&key, &mode.to_str()));
            }

            if let Some(ref iv) = self.iv {
                let key = CFString::wrap_under_get_rule(kSecIVKey);
                try!(transform.set_attribute(&key, iv));
            }

            try!(self.finish_oaep(&mut transform));

            let key = CFString::wrap_under_get_rule(kSecTransformInputAttributeName);
            try!(transform.set_attribute(&key, data));

            let result = try!(transform.execute());
            Ok(CFData::wrap_under_get_rule(result.as_CFTypeRef() as CFDataRef))
        }
    }

    #[cfg(feature = "OSX_10_8")]
    fn finish_oaep(&self, transform: &mut SecTransform) -> Result<(), CFError> {
        unsafe {
            if let Some(ref oaep_message_length) = self.oaep_message_length {
                let key = CFString::wrap_under_get_rule(kSecOAEPMessageLengthAttributeName);
                try!(transform.set_attribute(&key, oaep_message_length));
            }

            if let Some(ref oeap_encoding_parameters) = self.oaep_encoding_parameters {
                let key = CFString::wrap_under_get_rule(kSecOAEPEncodingParametersAttributeName);
                try!(transform.set_attribute(&key, oaep_encoding_parameters));
            }

            if let Some(ref oaep_mgf1_digest_algorithm) = self.oaep_mgf1_digest_algorithm {
                let key = CFString::wrap_under_get_rule(kSecOAEPMGF1DigestAlgorithmAttributeName);
                try!(transform.set_attribute(&key, oaep_mgf1_digest_algorithm));
            }

            Ok(())
        }
    }

    #[cfg(not(feature = "OSX_10_8"))]
    fn finish_oaep(&self, _: &mut SecTransform) -> Result<(), CFError> {
        Ok(())
    }
}
