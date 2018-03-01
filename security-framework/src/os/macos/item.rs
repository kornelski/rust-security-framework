//! OSX specific functionality for items.

use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::item::*;

use item::ItemSearchOptions;
use os::macos::keychain::SecKeychain;
use ItemSearchOptionsInternals;

/// Types of `SecKey`s.
#[derive(Debug, Copy, Clone)]
pub struct KeyType(CFStringRef);

#[allow(missing_docs)]
impl KeyType {
    pub fn rsa() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeRSA) }
    }

    pub fn dsa() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeDES) }
    }

    pub fn aes() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeAES) }
    }

    pub fn des() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeDES) }
    }

    pub fn triple_des() -> KeyType {
        unsafe { KeyType(kSecAttrKeyType3DES) }
    }

    pub fn rc4() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeRC4) }
    }

    pub fn cast() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeCAST) }
    }

    #[cfg(feature = "OSX_10_9")]
    pub fn ec() -> KeyType {
        unsafe { KeyType(kSecAttrKeyTypeEC) }
    }

    pub(crate) fn to_str(&self) -> CFString {
        unsafe { CFString::wrap_under_get_rule(self.0) }
    }
}

/// An extension trait adding OSX specific functionality to `ItemSearchOptions`.
pub trait ItemSearchOptionsExt {
    /// Search within the specified keychains.
    ///
    /// If this is not called, the default keychain will be searched.
    fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut Self;
}

impl ItemSearchOptionsExt for ItemSearchOptions {
    fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut ItemSearchOptions {
        ItemSearchOptionsInternals::keychains(self, keychains)
    }
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;

    use item::*;
    use os::macos::certificate::SecCertificateExt;
    use os::macos::test::keychain;

    #[test]
    fn find_certificate() {
        let dir = p!(TempDir::new("find_certificate"));
        let keychain = keychain(dir.path());
        let results = p!(ItemSearchOptions::new()
            .keychains(&[keychain])
            .class(ItemClass::certificate())
            .search());
        assert_eq!(1, results.len());
        let certificate = match results[0] {
            SearchResult::Ref(Reference::Certificate(ref cert)) => cert,
            _ => panic!("expected certificate"),
        };
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }
}
