use core_foundation_sys::base::{OSStatus, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

extern "C" {
    pub static kSecClass: CFStringRef;
    pub static kSecClassInternetPassword: CFStringRef;
    pub static kSecClassGenericPassword: CFStringRef;
    pub static kSecClassCertificate: CFStringRef;
    pub static kSecClassKey: CFStringRef;
    pub static kSecClassIdentity: CFStringRef;

    pub static kSecMatchLimit: CFStringRef;

    pub static kSecReturnData: CFStringRef;
    pub static kSecReturnAttributes: CFStringRef;
    pub static kSecReturnRef: CFStringRef;
    pub static kSecReturnPersistentRef: CFStringRef;

    pub static kSecMatchSearchList: CFStringRef;

    pub static kSecAttrKeyType: CFStringRef;
    pub static kSecAttrLabel: CFStringRef;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeRSA: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeDSA: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeAES: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeDES: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyType3DES: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeRC4: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeRC2: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecAttrKeyTypeCAST: CFStringRef;
    #[cfg(feature = "OSX_10_9")]
    pub static kSecAttrKeyTypeEC: CFStringRef;

    pub fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
}
