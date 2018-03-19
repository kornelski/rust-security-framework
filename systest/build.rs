extern crate ctest;

fn main() {
    let mut test = ctest::TestGenerator::new();

    #[cfg(feature = "OSX_10_8")]
    test.cfg("feature", Some("OSX_10_8"));
    #[cfg(feature = "OSX_10_9")]
    test.cfg("feature", Some("OSX_10_9"));
    #[cfg(feature = "OSX_10_10")]
    test.cfg("feature", Some("OSX_10_10"));
    #[cfg(feature = "OSX_10_11")]
    test.cfg("feature", Some("OSX_10_11"));
    #[cfg(feature = "OSX_10_12")]
    test.cfg("feature", Some("OSX_10_12"));

    test.header("Security/SecAccess.h")
        .header("Security/SecBase.h")
        .header("Security/SecCertificate.h")
        .header("Security/CipherSuite.h")
        .header("Security/SecDigestTransform.h")
        .header("Security/SecEncryptTransform.h")
        .header("Security/SecIdentity.h")
        .header("Security/SecImportExport.h")
        .header("Security/SecItem.h")
        .header("Security/SecKey.h")
        .header("Security/SecKeychainItem.h")
        .header("Security/SecPolicy.h")
        .header("Security/SecRandom.h")
        .header("Security/SecureTransport.h")
        .header("Security/SecTransform.h")
        .header("Security/SecTrust.h")
        .flag("-Wno-deprecated-declarations")
        .type_name(|name, _| name.to_string())
        .skip_signededness(|s| s.ends_with("Ref") || s.ends_with("Func"))
        .generate("../security-framework-sys/src/lib.rs", "all.rs");
}
