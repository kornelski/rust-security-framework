//! Security Framework type import/export support.

use security_framework_sys::import_export::*;
use core_foundation::string::CFString;
use core_foundation::base::{TCFType, CFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::array::CFArray;
use std::ptr;

#[cfg(target_os = "macos")]
use access::SecAccess;
#[cfg(target_os = "macos")]
use keychain::SecKeychain;
use trust::SecTrust;
use certificate::SecCertificate;
use identity::SecIdentity;
use base::Result;
use cvt;

/// Information about an imported identity.
pub struct ImportedIdentity {
    /// The label of the identity.
    pub label: String,
    /// The ID of the identity. Typically the SHA-1 hash of the public key.
    pub key_id: Vec<u8>,
    /// A `SecTrust` object set up to validate this identity.
    pub trust: SecTrust,
    /// A certificate chain validating this identity.
    pub cert_chain: Vec<SecCertificate>,
    /// The identity itself.
    pub identity: SecIdentity,
    _p: (),
}

/// A builder type to import an identity from PKCS#12 formatted data.
#[derive(Default)]
pub struct Pkcs12ImportOptions {
    passphrase: Option<CFString>,
    #[cfg(target_os = "macos")]
    keychain: Option<SecKeychain>,
    #[cfg(target_os = "macos")]
    access: Option<SecAccess>,
}

#[cfg(target_os = "macos")]
impl ::Pkcs12ImportOptionsInternals for Pkcs12ImportOptions {
    fn keychain(&mut self, keychain: SecKeychain) -> &mut Self {
        self.keychain = Some(keychain);
        self
    }

    fn access(&mut self, access: SecAccess) -> &mut Self {
        self.access = Some(access);
        self
    }
}

impl Pkcs12ImportOptions {
    /// Creates a new builder with default options.
    pub fn new() -> Pkcs12ImportOptions {
        Self::default()
    }

    /// Specifies the passphrase to be used to decrypt the data.
    ///
    /// This must be specified, as unencrypted PKCS#12 data is not supported.
    pub fn passphrase(&mut self, passphrase: &str) -> &mut Self {
        self.passphrase = Some(CFString::new(passphrase));
        self
    }

    /// Deprecated
    ///
    /// Replaced by `os::macos::import_export::Pkcs12ImportOptionsExt::keychain`.
    #[cfg(target_os = "macos")]
    pub fn keychain(&mut self, keychain: SecKeychain) -> &mut Self {
        self.keychain = Some(keychain);
        self
    }

    /// Deprecated
    ///
    /// Replaced by `os::macos::import_export::Pkcs12ImportOptionsExt::access`.
    #[cfg(target_os = "macos")]
    pub fn access(&mut self, access: SecAccess) -> &mut Self {
        self.access = Some(access);
        self
    }

    /// Imports identities from PKCS#12 encoded data.
    pub fn import(&self, pkcs12_data: &[u8]) -> Result<Vec<ImportedIdentity>> {
        unsafe {
            let pkcs12_data = CFData::from_buffer(pkcs12_data);

            let mut options = vec![];

            if let Some(ref passphrase) = self.passphrase {
                options.push((CFString::wrap_under_get_rule(kSecImportExportPassphrase),
                              passphrase.as_CFType()));
            }

            self.import_setup(&mut options);

            let options = CFDictionary::from_CFType_pairs(&options);

            let mut raw_items = ptr::null();
            try!(cvt(SecPKCS12Import(pkcs12_data.as_concrete_TypeRef(),
                                     options.as_concrete_TypeRef(),
                                     &mut raw_items)));
            let raw_items = CFArray::wrap_under_create_rule(raw_items);

            let mut items = vec![];

            for raw_item in &raw_items {
                let raw_item = CFDictionary::wrap_under_get_rule(raw_item as *mut _);
                let label = raw_item.get(kSecImportItemLabel as *const _);
                let label = CFString::wrap_under_get_rule(label as *const _).to_string();
                let key_id = raw_item.get(kSecImportItemKeyID as *const _);
                let key_id = CFData::wrap_under_get_rule(key_id as *const _).to_owned();
                let trust = raw_item.get(kSecImportItemTrust as *const _);
                let trust = SecTrust::wrap_under_get_rule(trust as usize as *mut _);
                let cert_chain = raw_item.get(kSecImportItemCertChain as *const _);
                let cert_chain = CFArray::wrap_under_get_rule(cert_chain as *const _);
                let cert_chain = cert_chain.iter()
                                           .map(|c| {
                                               SecCertificate::wrap_under_get_rule(c as *mut _)
                                           })
                                           .collect();
                let identity = raw_item.get(kSecImportItemIdentity as *const _);
                let identity = SecIdentity::wrap_under_get_rule(identity as usize as *mut _);

                items.push(ImportedIdentity {
                    label: label,
                    key_id: key_id,
                    trust: trust,
                    cert_chain: cert_chain,
                    identity: identity,
                    _p: (),
                });
            }

            Ok(items)
        }
    }

    #[cfg(target_os = "macos")]
    fn import_setup(&self, options: &mut Vec<(CFString, CFType)>) {
        unsafe {
            if let Some(ref keychain) = self.keychain {
                options.push((CFString::wrap_under_get_rule(kSecImportExportKeychain),
                              keychain.as_CFType()));
            }

            if let Some(ref access) = self.access {
                options.push((CFString::wrap_under_get_rule(kSecImportExportAccess),
                              access.as_CFType()));
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn import_setup(&self, _: &mut Vec<(CFString, CFType)>) {}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn missing_passphrase() {
        let data = include_bytes!("../test/server.p12");
        assert!(Pkcs12ImportOptions::new().import(data).is_err());
    }
}
