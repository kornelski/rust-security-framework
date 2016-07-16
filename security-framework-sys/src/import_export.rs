use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{OSStatus, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

use base::{SecKeychainRef, SecAccessRef};

#[cfg(target_os = "macos")]
pub type SecExternalFormat = u32;
#[cfg(target_os = "macos")]
pub type SecExternalItemType = u32;
#[cfg(target_os = "macos")]
pub type SecItemImportExportFlags = u32;
#[cfg(target_os = "macos")]
pub type SecKeyImportExportFlags = u32;

#[cfg(target_os = "macos")]
pub const kSecKeyImportOnlyOne: SecKeyImportExportFlags = 1;
#[cfg(target_os = "macos")]
pub const kSecKeySecurePassphrase: SecKeyImportExportFlags = 2;
#[cfg(target_os = "macos")]
pub const kSecKeyNoAccessControl: SecKeyImportExportFlags = 4;

#[cfg(target_os = "macos")]
pub const SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION: u32 = 0;

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
    pub static kSecImportExportKeychain: CFStringRef;
    #[cfg(target_os = "macos")]
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
