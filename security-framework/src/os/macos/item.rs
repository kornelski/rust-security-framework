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
