//! Support to search for items in a keychain.

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
#[cfg(target_os = "macos")]
use keychain::SecKeychain;

/// Specifies the type of items to search for.
#[derive(Debug, Copy, Clone)]
pub enum ItemClass {
    /// Look for `SecKeychainItem`s corresponding to generic passwords.
    GenericPassword,
    /// Look for `SecKeychainItem`s corresponding to internet passwords.
    InternetPassword,
    /// Look for `SecCertificate`s.
    Certificate,
    /// Look for `SecKey`s.
    Key,
    /// Look for `SecIdentity`s.
    Identity,
}

impl ItemClass {
    fn to_value(&self) -> CFType {
        unsafe {
            let raw = match *self {
                ItemClass::GenericPassword => kSecClassGenericPassword,
                ItemClass::InternetPassword => kSecClassInternetPassword,
                ItemClass::Certificate => kSecClassCertificate,
                ItemClass::Key => kSecClassKey,
                ItemClass::Identity => kSecClassIdentity,
            };
            CFType::wrap_under_get_rule(raw as *const _)
        }
    }
}

/// A builder type to search for items in keychains.
#[derive(Default)]
pub struct ItemSearchOptions {
    keychains: Option<CFArray>,
    class: Option<ItemClass>,
    load_refs: bool,
    limit: Option<i64>,
    label: Option<CFString>,
}

#[cfg(target_os = "macos")]
impl ::ItemSearchOptionsInternals for ItemSearchOptions {
    fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut ItemSearchOptions {
        self.keychains = Some(CFArray::from_CFTypes(keychains));
        self
    }
}

impl ItemSearchOptions {
    /// Creates a new builder with default options.
    pub fn new() -> ItemSearchOptions {
        ItemSearchOptions::default()
    }

    /// Search only for items of the specified class.
    pub fn class(&mut self, class: ItemClass) -> &mut ItemSearchOptions {
        self.class = Some(class);
        self
    }

    /// Deprecated.
    ///
    /// Replaced by `os::macos::item::ItemSearchOptionsExt::keychains`.
    #[cfg(target_os = "macos")]
    pub fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut ItemSearchOptions {
        self.keychains = Some(CFArray::from_CFTypes(keychains));
        self
    }

    /// Load Security Framework objects (`SecCertificate`, `SecKey`, etc) for
    /// the results.
    pub fn load_refs(&mut self, load_refs: bool) -> &mut ItemSearchOptions {
        self.load_refs = load_refs;
        self
    }

    /// Limit the number of search results.
    ///
    /// If this is not called, the default limit is 1.
    pub fn limit(&mut self, limit: i64) -> &mut ItemSearchOptions {
        self.limit = Some(limit);
        self
    }

    /// Search for an item with the given label.
    pub fn label(&mut self, label: &str) -> &mut ItemSearchOptions {
        self.label = Some(CFString::new(label));
        self
    }

    /// Search for objects.
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

            if let Some(ref label) = self.label {
                params.push((CFString::wrap_under_get_rule(kSecAttrLabel),
                             label.as_CFType()));
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

#[cfg(target_os = "macos")]
unsafe fn get_item(item: CFTypeRef) -> SearchResult {
    use os::macos::keychain_item::SecKeychainItem;

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

#[cfg(not(target_os = "macos"))]
unsafe fn get_item(item: CFTypeRef) -> SearchResult {
    let type_id = CFGetTypeID(item);

    let reference = if type_id == SecCertificate::type_id() {
        Reference::Certificate(SecCertificate::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecKey::type_id() {
        Reference::Key(SecKey::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecIdentity::type_id() {
        Reference::Identity(SecIdentity::wrap_under_get_rule(item as *mut _))
    } else {
        panic!("Got bad type from SecItemCopyMatching: {}", type_id);
    };

    SearchResult {
        reference: Some(reference),
        _p: (),
    }
}

/// An enum including all objects which can be found by `ItemSearchOptions`.
#[derive(Debug)]
pub enum Reference {
    /// A `SecIdentity`.
    Identity(SecIdentity),
    /// A `SecCertificate`.
    Certificate(SecCertificate),
    /// A `SecKey`.
    Key(SecKey),
    /// A `SecKeychainItem`.
    ///
    /// Only defined on OSX
    #[cfg(target_os = "macos")]
    KeychainItem(::os::macos::keychain_item::SecKeychainItem),
}

/// An individual search result.
pub struct SearchResult {
    /// A reference to the Security Framework object, if asked for.
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
