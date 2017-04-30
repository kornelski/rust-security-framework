//! OSX specific functionality for items.

use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::item::*;

use ItemSearchOptionsInternals;
use keychain::SecKeychain;
use os::macos::PrivKeyType;
use item::ItemSearchOptions;

/// Types of `SecKey`s.
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone)]
pub enum KeyType {
    Rsa,
    Dsa,
    Aes,
    Des,
    TripleDes,
    Rc4,
    Cast,
    #[cfg(feature = "OSX_10_9")]
    Ec,
}

impl PrivKeyType for KeyType {
    fn to_str(&self) -> CFString {
        unsafe {
            let raw = match *self {
                KeyType::Rsa => kSecAttrKeyTypeRSA,
                KeyType::Dsa => kSecAttrKeyTypeDSA,
                KeyType::Aes => kSecAttrKeyTypeAES,
                KeyType::Des => kSecAttrKeyTypeDES,
                KeyType::TripleDes => kSecAttrKeyType3DES,
                KeyType::Rc4 => kSecAttrKeyTypeRC4,
                KeyType::Cast => kSecAttrKeyTypeCAST,
                #[cfg(feature = "OSX_10_9")]
                KeyType::Ec => kSecAttrKeyTypeEC,
            };
            CFString::wrap_under_get_rule(raw)
        }
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
                             .class(ItemClass::Certificate)
                             .search());
        assert_eq!(1, results.len());
        let certificate = match results[0].reference {
            Some(Reference::Certificate(ref cert)) => cert,
            _ => panic!("expected certificate"),
        };
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }
}
