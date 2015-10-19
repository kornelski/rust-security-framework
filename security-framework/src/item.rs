use core_foundation::array::CFArray;
use core_foundation::boolean::CFBoolean;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework_sys::item::*;
use std::ptr;

use cvt;
use base::Result;
use certificate::SecCertificate;
use identity::SecIdentity;
use key::SecKey;
use keychain::SecKeychain;

#[derive(Debug, Copy, Clone)]
pub enum ItemClass {
    GenericPassword,
    InternetPassword,
    Certificate,
    Key,
    Identity,
}

impl ItemClass {
    fn to_value(&self) -> CFType {
        let raw = match *self {
            ItemClass::GenericPassword => kSecClassGenericPassword,
            ItemClass::InternetPassword => kSecClassInternetPassword,
            ItemClass::Certificate => kSecClassCertificate,
            ItemClass::Key => kSecClassKey,
            ItemClass::Identity => kSecClassIdentity,
        };
        unsafe {
            CFType::wrap_under_get_rule(raw as *const _)
        }
    }
}

#[derive(Default)]
pub struct ItemSearchOptions {
    keychains: Option<CFArray>,
    class: Option<ItemClass>,
    load_refs: bool,
}

impl ItemSearchOptions {
    pub fn new() -> ItemSearchOptions {
        ItemSearchOptions::default()
    }

    pub fn class(&mut self, class: ItemClass) -> &mut ItemSearchOptions {
        self.class = Some(class);
        self
    }

    pub fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut ItemSearchOptions {
        self.keychains = Some(CFArray::from_CFTypes(keychains));
        self
    }

    pub fn load_refs(&mut self, load_refs: bool) -> &mut ItemSearchOptions {
        self.load_refs = load_refs;
        self
    }

    pub fn search(&self) -> Result<SearchResults> {
        unsafe {
            let mut params = vec![];

            if let Some(ref keychains) = self.keychains {
                params.push((CFString::wrap_under_get_rule(kSecMatchSearchList),
                             keychains.as_CFType()));
            }

            if let Some(class) = self.class {
                params.push((CFString::wrap_under_get_rule(kSecClass), class.to_value()));
            }

            if self.load_refs {
                params.push((CFString::wrap_under_get_rule(kSecReturnRef),
                             CFBoolean::true_value().as_CFType()));
            }

            let params = CFDictionary::from_CFType_pairs(&params);

            let mut ret = ptr::null();
            try!(cvt(SecItemCopyMatching(params.as_concrete_TypeRef(), &mut ret)));
            let type_id = CFType::wrap_under_get_rule(ret).type_of();

            let mut results = SearchResults {
                certificates: vec![],
                keys: vec![],
                identities: vec![],
            };

            if type_id == SecCertificate::type_id() {
                results.certificates.push(SecCertificate::wrap_under_get_rule(ret as *mut _));
            } else if type_id == SecKey::type_id() {
                results.keys.push(SecKey::wrap_under_get_rule(ret as *mut _));
            } else if type_id == SecIdentity::type_id() {
                results.identities.push(SecIdentity::wrap_under_get_rule(ret as *mut _));
            } else {
                panic!("Got bad type from SecItemCopyMatching: {}", type_id);
            }

            Ok(results)
        }
    }
}

#[derive(Debug)]
pub struct SearchResults {
    pub certificates: Vec<SecCertificate>,
    pub keys: Vec<SecKey>,
    pub identities: Vec<SecIdentity>,
}

#[cfg(test)]
mod test {
    use super::*;
    use keychain::SecKeychain;

    #[test]
    fn find_nothing() {
        assert!(ItemSearchOptions::new().search().is_err());
    }

    #[test]
    fn find_certificate() {
        // the path has to be absolute for some reason
        let keychain = p!(SecKeychain::open(concat!(env!("PWD"), "/test/server.keychain")));

        let results = p!(ItemSearchOptions::new()
                     .keychains(&[keychain])
                     .class(ItemClass::Certificate)
                     .search());
        assert_eq!(1, results.certificates.len());
        assert_eq!("foobar.com", p!(results.certificates[0].common_name()).to_string());
        assert!(results.keys.is_empty());
        assert!(results.identities.is_empty());
    }
}
