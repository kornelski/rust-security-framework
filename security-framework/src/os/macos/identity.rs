#[cfg(test)]
mod test {
    use tempdir::TempDir;

    use os::macos::test::identity;
    use os::macos::certificate::SecCertificateExt;

    #[test]
    fn certificate() {
        let dir = p!(TempDir::new("certificate"));
        let identity = identity(dir.path());
        let certificate = p!(identity.certificate());
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }

    #[test]
    fn private_key() {
        let dir = p!(TempDir::new("private_key"));
        let identity = identity(dir.path());
        p!(identity.private_key());
    }
}
