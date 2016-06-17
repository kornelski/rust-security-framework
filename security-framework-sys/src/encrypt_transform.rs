use core_foundation_sys::base::CFTypeID;
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;

use transform::SecTransformRef;
use base::SecKeyRef;

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
    #[cfg(feature = "OSX_10_8")]
    pub static kSecPaddingOAEPKey: CFStringRef;
    pub static kSecPaddingPKCS1Key: CFStringRef;
    pub static kSecPaddingPKCS5Key: CFStringRef;
    pub static kSecPaddingPKCS7Key: CFStringRef;

    pub fn SecDecryptTransformCreate(keyRef: SecKeyRef, error: *mut CFErrorRef) -> SecTransformRef;
    pub fn SecDecryptTransformGetTypeID() -> CFTypeID;
    pub fn SecEncryptTransformCreate(keyRef: SecKeyRef, error: *mut CFErrorRef) -> SecTransformRef;
    pub fn SecEncryptTransformGetTypeID() -> CFTypeID;
}
