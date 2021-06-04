use std::env;

fn main() {
    let mut test = ctest::TestGenerator::new();

    #[cfg(feature = "OSX_10_9")]
    test.cfg("feature", Some("OSX_10_9"));
    #[cfg(feature = "OSX_10_10")]
    test.cfg("feature", Some("OSX_10_10"));
    #[cfg(feature = "OSX_10_11")]
    test.cfg("feature", Some("OSX_10_11"));
    #[cfg(feature = "OSX_10_12")]
    test.cfg("feature", Some("OSX_10_12"));

    if env::var("TARGET").unwrap().contains("darwin") {
        test.header("Security/SecAccess.h")
            .header("Security/SecDigestTransform.h")
            .header("Security/SecEncryptTransform.h")
            .header("Security/SecKeychain.h")
            .header("Security/SecKeychainItem.h")
            .header("Security/SecCertificateOIDs.h")
            .header("Security/SecTransform.h")
            .header("Security/SecTrustSettings.h")
            .header("Security/Authorization.h")
            .header("Security/AuthorizationDB.h")
            .header("Security/CodeSigning.h");
    }

    test.header("Security/SecBase.h")
        .header("Security/SecCertificate.h")
        .header("Security/CipherSuite.h")
        .header("Security/SecIdentity.h")
        .header("Security/SecImportExport.h")
        .header("Security/SecItem.h")
        .header("Security/SecKey.h")
        .header("Security/SecPolicy.h")
        .header("Security/SecRandom.h")
        .header("Security/SecureTransport.h")
        .header("Security/SecTrust.h")
        .flag("-Wno-deprecated-declarations")
        .type_name(|name, _, _| name.to_string())
        .skip_signededness(|s| s.ends_with("Ref") || s.ends_with("Func"))
        .skip_fn(|s| s == "SecRandomCopyBytes") // varies between macOS versions
        .generate("../security-framework-sys/src/lib.rs", "all.rs");
}
