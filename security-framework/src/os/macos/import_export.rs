use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::import_export::*;
use std::ptr;
use std::str::FromStr;

use ErrorNew;
use base::{Error, Result};
use certificate::SecCertificate;
use identity::SecIdentity;
use key::SecKey;
use keychain::SecKeychain;

#[derive(Default)]
pub struct ImportOptions<'a> {
    filename: Option<CFString>,
    passphrase: Option<CFType>,
    secure_passphrase: bool,
    no_access_control: bool,
    alert_title: Option<CFString>,
    alert_prompt: Option<CFString>,
    items: Option<&'a mut SecItems>,
    keychain: Option<SecKeychain>,
}

impl<'a> ImportOptions<'a> {
    pub fn new() -> ImportOptions<'a> {
        ImportOptions::default()
    }

    pub fn filename(&mut self, filename: &str) -> &mut ImportOptions<'a> {
        self.filename = Some(CFString::from_str(filename).unwrap());
        self
    }

    pub fn passphrase(&mut self, passphrase: &str) -> &mut ImportOptions<'a> {
        self.passphrase = Some(CFString::from_str(passphrase).unwrap().as_CFType());
        self
    }

    pub fn passphrase_bytes(&mut self, passphrase: &[u8]) -> &mut ImportOptions<'a> {
        self.passphrase = Some(CFData::from_buffer(passphrase).as_CFType());
        self
    }

    pub fn secure_passphrase(&mut self, secure_passphrase: bool) -> &mut ImportOptions<'a> {
        self.secure_passphrase = secure_passphrase;
        self
    }

    pub fn no_access_control(&mut self, no_access_control: bool) -> &mut ImportOptions<'a> {
        self.no_access_control = no_access_control;
        self
    }

    pub fn alert_title(&mut self, alert_title: &str) -> &mut ImportOptions<'a> {
        self.alert_title = Some(CFString::from_str(alert_title).unwrap());
        self
    }

    pub fn alert_prompt(&mut self, alert_prompt: &str) -> &mut ImportOptions<'a> {
        self.alert_prompt = Some(CFString::from_str(alert_prompt).unwrap());
        self
    }

    pub fn items(&mut self, items: &'a mut SecItems) -> &mut ImportOptions<'a> {
        self.items = Some(items);
        self
    }

    pub fn keychain(&mut self, keychain: &SecKeychain) -> &mut ImportOptions<'a> {
        self.keychain = Some(keychain.clone());
        self
    }

    pub fn import(&mut self, data: &[u8]) -> Result<()> {
        let data = CFData::from_buffer(data);
        let data = data.as_concrete_TypeRef();

        let filename = match self.filename {
            Some(ref filename) => filename.as_concrete_TypeRef(),
            None => ptr::null(),
        };

        let mut key_params = SecItemImportExportKeyParameters {
            version: SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
            flags: 0,
            passphrase: ptr::null(),
            alert_title: ptr::null(),
            alert_prompt: ptr::null(),
            access_ref: ptr::null_mut(),
            key_usage: ptr::null_mut(),
            key_attributes: ptr::null(),
        };

        if let Some(ref passphrase) = self.passphrase {
            key_params.passphrase = passphrase.as_CFTypeRef();
        }

        if self.secure_passphrase {
            key_params.flags |= kSecKeySecurePassphrase;
        }

        if self.no_access_control {
            key_params.flags |= kSecKeyNoAccessControl;
        }

        if let Some(ref alert_title) = self.alert_title {
            key_params.alert_title = alert_title.as_concrete_TypeRef();
        }

        if let Some(ref alert_prompt) = self.alert_prompt {
            key_params.alert_prompt = alert_prompt.as_concrete_TypeRef();
        }

        let keychain = match self.keychain {
            Some(ref keychain) => keychain.as_concrete_TypeRef(),
            None => ptr::null_mut(),
        };

        let mut raw_items = ptr::null();
        let items_ref = match self.items {
            Some(_) => &mut raw_items as *mut _,
            None => ptr::null_mut(),
        };

        unsafe {
            let ret = SecItemImport(data,
                                    filename,
                                    ptr::null_mut(),
                                    ptr::null_mut(),
                                    0,
                                    &mut key_params,
                                    keychain,
                                    items_ref);
            if ret != errSecSuccess {
                return Err(Error::new(ret));
            }

            if let Some(ref mut items) = self.items {
                let raw_items = CFArray::wrap_under_create_rule(raw_items);
                for item in raw_items.iter() {
                    let type_id = CFType::wrap_under_get_rule(item as *mut _).type_of();
                    if type_id == SecCertificate::type_id() {
                        items.certificates.push(SecCertificate::wrap_under_get_rule(item as *mut _));
                    } else if type_id == SecIdentity::type_id() {
                        items.identities.push(SecIdentity::wrap_under_get_rule(item as *mut _));
                    } else if type_id == SecKey::type_id() {
                        items.keys.push(SecKey::wrap_under_get_rule(item as *mut _));
                    } else {
                        panic!("Got bad type from SecItemImport: {}", type_id);
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct SecItems {
    pub certificates: Vec<SecCertificate>,
    pub identities: Vec<SecIdentity>,
    pub keys: Vec<SecKey>,
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;

    use super::*;
    use os::macos::keychain;

    #[test]
    fn certificate() {
        let data = include_bytes!("../../../test/server.der");
        let mut items = SecItems::default();
        ImportOptions::new()
            .filename("server.der")
            .items(&mut items)
            .import(data)
            .unwrap();
        assert_eq!(1, items.certificates.len());
        assert_eq!(0, items.identities.len());
        assert_eq!(0, items.keys.len());
    }

    #[test]
    fn key() {
        let data = include_bytes!("../../../test/server.key");
        let mut items = SecItems::default();
        ImportOptions::new()
            .filename("server.key")
            .items(&mut items)
            .import(data)
            .unwrap();
        assert_eq!(0, items.certificates.len());
        assert_eq!(0, items.identities.len());
        assert_eq!(1, items.keys.len());
    }

    #[test]
    fn identity() {
        let dir = TempDir::new("identity").unwrap();
        let keychain = keychain::CreateOptions::new()
            .password("password")
            .create(dir.path().join("identity.keychain"))
            .unwrap();

        let data = include_bytes!("../../../test/server.p12");
        let mut items = SecItems::default();
        ImportOptions::new()
            .filename("server.p12")
            .passphrase("password123")
            .items(&mut items)
            .keychain(&keychain)
            .import(data)
            .unwrap();
        assert_eq!(1, items.identities.len());
        assert_eq!(0, items.certificates.len());
        assert_eq!(0, items.keys.len());
    }

    #[test]
    #[ignore] // since it requires manual intervention
    fn secure_passphrase_identity() {
        let dir = TempDir::new("identity").unwrap();
        let keychain = keychain::CreateOptions::new()
            .password("password")
            .create(dir.path().join("identity.keychain"))
            .unwrap();

        let data = include_bytes!("../../../test/server.p12");
        let mut items = SecItems::default();
        ImportOptions::new()
            .filename("server.p12")
            .secure_passphrase(true)
            .alert_title("alert title")
            .alert_prompt("alert prompt")
            .items(&mut items)
            .keychain(&keychain)
            .import(data)
            .unwrap();
        assert_eq!(1, items.identities.len());
        assert_eq!(0, items.certificates.len());
        assert_eq!(0, items.keys.len());
    }
}
