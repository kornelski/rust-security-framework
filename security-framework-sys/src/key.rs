use core_foundation_sys::base::CFTypeID;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use core_foundation_sys::data::CFDataRef;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use core_foundation_sys::dictionary::CFDictionaryRef;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use core_foundation_sys::error::CFErrorRef;

use base::SecKeyRef;

extern "C" {
    pub fn SecKeyGetTypeID() -> CFTypeID;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SecKeyCreateFromData(parameters: CFDictionaryRef,
                                keyData: CFDataRef,
                                error: *mut CFErrorRef)
                                -> SecKeyRef;
}
