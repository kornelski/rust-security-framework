use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{OSStatus, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

use base::{SecKeychainRef, SecAccessRef};

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub type SecExternalFormat = u32;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub type SecExternalItemType = u32;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub type SecItemImportExportFlags = u32;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub type SecKeyImportExportFlags = u32;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const kSecKeyImportOnlyOne: SecKeyImportExportFlags = 1;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const kSecKeySecurePassphrase: SecKeyImportExportFlags = 2;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const kSecKeyNoAccessControl: SecKeyImportExportFlags = 4;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION: u32 = 0;

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub struct SecItemImportExportKeyParameters {
    pub version: u32,
    pub flags: SecKeyImportExportFlags,
    pub passphrase: CFTypeRef,
    pub alert_title: CFStringRef,
    pub alert_prompt: CFStringRef,
    pub access_ref: SecAccessRef,
    pub key_usage: CFArrayRef,
    pub key_attributes: CFArrayRef,
}

extern "C" {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn SecItemImport(importedData: CFDataRef,
                         fileNameOrExtension: CFStringRef,
                         inputFormat: *mut SecExternalFormat,
                         itemType: *mut SecExternalItemType,
                         flags: SecItemImportExportFlags,
                         keyParams: *const SecItemImportExportKeyParameters,
                         importKeychain: SecKeychainRef,
                         outItems: *mut CFArrayRef)
                         -> OSStatus;

    pub static kSecImportExportPassphrase: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecImportExportKeychain: CFStringRef;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub static kSecImportExportAccess: CFStringRef;

    pub static kSecImportItemLabel: CFStringRef;
    pub static kSecImportItemKeyID: CFStringRef;
    pub static kSecImportItemTrust: CFStringRef;
    pub static kSecImportItemCertChain: CFStringRef;
    pub static kSecImportItemIdentity: CFStringRef;

    pub fn SecPKCS12Import(pkcs12_data: CFDataRef,
                           options: CFDictionaryRef,
                           items: *mut CFArrayRef)
                           -> OSStatus;
}
