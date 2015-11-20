#[cfg(test)]
mod test {
    use keychain::SecKeychain;
    use item::*;
    use os::macos::certificate::SecCertificateExt;
    use os::macos::keychain::SecKeychainExt;

    #[test]
    fn find_certificate() {
        // the path has to be absolute for some reason
        let keychain = p!(SecKeychain::open(concat!(env!("PWD"), "/test/server.keychain")));

        let results = p!(ItemSearchOptions::new()
                             .keychains(&[keychain])
                             .class(ItemClass::Certificate)
                             .search());
        assert_eq!(1, results.certificates.len());
        assert_eq!("foobar.com",
                   p!(results.certificates[0].common_name()).to_string());
        assert!(results.keys.is_empty());
        assert!(results.identities.is_empty());
    }
}
