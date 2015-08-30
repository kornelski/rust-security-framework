use core_foundation_sys::array::CFArrayRef;
use core_foundation_sys::base::{OSStatus, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::string::CFStringRef;

use base::{SecKeychainRef, SecAccessRef};

pub type SecExternalFormat = u32;
pub type SecExternalItemType = u32;
pub type SecItemImportExportFlags = u32;
pub type SecKeyImportExportFlags = u32;

pub const SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION: u32 = 0;

#[repr(C)]
#[derive(Copy, Clone)]
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

extern {
    pub fn SecItemImport(importedData: CFDataRef, fileNameOrExtension: CFStringRef,
                         inputFormat: *mut SecExternalFormat, itemType: *mut SecExternalItemType,
                         flags: SecItemImportExportFlags,
                         keyParams: *const SecItemImportExportKeyParameters,
                         importKeychain: SecKeychainRef,
                         outItems: *mut CFArrayRef) -> OSStatus;
}
