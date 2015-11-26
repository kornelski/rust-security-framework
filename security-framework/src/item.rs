use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFTypeRef, CFGetTypeID, CFRelease};
use security_framework_sys::item::*;
use std::fmt;
use std::ptr;

use base::Result;
use certificate::SecCertificate;
use cvt;
use identity::SecIdentity;
use key::SecKey;
use keychain::SecKeychain;
use keychain_item::SecKeychainItem;

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
        unsafe { CFType::wrap_under_get_rule(raw as *const _) }
    }
}

#[derive(Default)]
pub struct ItemSearchOptions {
    keychains: Option<CFArray>,
    class: Option<ItemClass>,
    load_refs: bool,
    limit: Option<i64>,
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

    pub fn limit(&mut self, limit: i64) -> &mut ItemSearchOptions {
        self.limit = Some(limit);
        self
    }

    pub fn search(&self) -> Result<Vec<SearchResult>> {
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

            if let Some(limit) = self.limit {
                params.push((CFString::wrap_under_get_rule(kSecMatchLimit),
                             CFNumber::from_i64(limit).as_CFType()));
            }

            let params = CFDictionary::from_CFType_pairs(&params);

            let mut ret = ptr::null();
            try!(cvt(SecItemCopyMatching(params.as_concrete_TypeRef(), &mut ret)));
            let type_id = CFGetTypeID(ret);

            let mut items = vec![];

            if type_id == CFArray::type_id() {
                let array = CFArray::wrap_under_create_rule(ret as *mut _);
                for item in &array {
                    items.push(get_item(item as *const _));
                }
            } else {
                items.push(get_item(ret));
                // This is a bit janky, but get_item uses wrap_under_get_rule
                // which bumps the refcount but we want create semantics
                CFRelease(ret);
            }

            Ok(items)
        }
    }
}

unsafe fn get_item(item: CFTypeRef) -> SearchResult {
    let type_id = CFGetTypeID(item);

    let reference = if type_id == SecCertificate::type_id() {
        Reference::Certificate(SecCertificate::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecKey::type_id() {
        Reference::Key(SecKey::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecIdentity::type_id() {
        Reference::Identity(SecIdentity::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecKeychainItem::type_id() {
        Reference::KeychainItem(SecKeychainItem::wrap_under_get_rule(item as *mut _))
    } else {
        panic!("Got bad type from SecItemCopyMatching: {}", type_id);
    };

    SearchResult {
        reference: Some(reference),
        _p: (),
    }
}

#[derive(Debug)]
pub enum Reference {
    Identity(SecIdentity),
    Certificate(SecCertificate),
    Key(SecKey),
    KeychainItem(SecKeychainItem),
}

pub struct SearchResult {
    pub reference: Option<Reference>,
    _p: (),
}

impl fmt::Debug for SearchResult {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SearchResult")
           .field("reference", &self.reference)
           .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn find_nothing() {
        assert!(ItemSearchOptions::new().search().is_err());
    }

    #[test]
    fn limit_two() {
        let results = ItemSearchOptions::new()
                        .class(ItemClass::Certificate)
                        .limit(2)
                        .search()
                        .unwrap();
        assert_eq!(results.len(), 2);
    }
}
