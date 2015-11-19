#[cfg(test)]
mod test {
    use os::macos::test::identity;
    use os::macos::certificate::SecCertificateExt;

    #[test]
    fn certificate() {
        let identity = identity();
        let certificate = p!(identity.certificate());
        assert_eq!("foobar.com", p!(certificate.common_name()).to_string());
    }

    #[test]
    fn private_key() {
        let identity = identity();
        p!(identity.private_key());
    }
}
