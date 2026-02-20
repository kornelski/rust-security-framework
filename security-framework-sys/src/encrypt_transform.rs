use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;

use crate::base::SecKeyRef;
use crate::transform::SecTransformRef;

extern "C" {
    pub static kSecEncryptionMode: CFStringRef;
    pub static kSecEncryptKey: CFStringRef;
    pub static kSecIVKey: CFStringRef;
    pub static kSecModeCBCKey: CFStringRef;
    pub static kSecModeCFBKey: CFStringRef;
    pub static kSecModeECBKey: CFStringRef;
    pub static kSecModeNoneKey: CFStringRef;
    pub static kSecModeOFBKey: CFStringRef;
    pub static kSecPaddingKey: CFStringRef;
    pub static kSecPaddingNoneKey: CFStringRef;
    pub static kSecPaddingOAEPKey: CFStringRef;
    pub static kSecPaddingPKCS1Key: CFStringRef;
    pub static kSecPaddingPKCS5Key: CFStringRef;
    pub static kSecPaddingPKCS7Key: CFStringRef;

    #[deprecated(note = "Deprecated by Apple. SecTransform is no longer supported")]
    pub fn SecDecryptTransformCreate(keyRef: SecKeyRef, error: *mut CFErrorRef) -> SecTransformRef;
    // this symbol is apparently missing in 10.13.3?
    // pub fn SecDecryptTransformGetTypeID() -> CFTypeID;
    #[deprecated(note = "Deprecated by Apple. SecTransform is no longer supported")]
    pub fn SecEncryptTransformCreate(keyRef: SecKeyRef, error: *mut CFErrorRef) -> SecTransformRef;
// this symbol is apparently missing in 10.13.3?
// pub fn SecEncryptTransformGetTypeID() -> CFTypeID;
}
