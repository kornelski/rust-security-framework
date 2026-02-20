use core_foundation_sys::base::{Boolean, CFTypeID, CFTypeRef};
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;

pub type SecTransformRef = CFTypeRef;

extern "C" {
    pub static kSecTransformInputAttributeName: CFStringRef;

    #[deprecated(note = "Deprecated by Apple. SecTransform is no longer supported")]
    pub fn SecTransformGetTypeID() -> CFTypeID;

    #[deprecated(note = "Deprecated by Apple. SecTransform is no longer supported")]
    pub fn SecTransformSetAttribute(
        transformRef: SecTransformRef,
        key: CFStringRef,
        value: CFTypeRef,
        error: *mut CFErrorRef,
    ) -> Boolean;

    #[deprecated(note = "Deprecated by Apple. SecTransform is no longer supported")]
    pub fn SecTransformExecute(
        transformRef: SecTransformRef,
        errorRef: *mut CFErrorRef,
    ) -> CFTypeRef;
}
