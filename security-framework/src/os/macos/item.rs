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
        assert_eq!(1, results.certificates.len());
        assert_eq!("foobar.com",
                   p!(results.certificates[0].common_name()).to_string());
        assert!(results.keys.is_empty());
        assert!(results.identities.is_empty());
    }
}
