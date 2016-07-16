//! Keychain support

use security_framework_sys::base::SecKeychainRef;
use security_framework_sys::keychain::*;

make_wrapper! {
    /// A type representing a keychain.
    struct SecKeychain, SecKeychainRef, SecKeychainGetTypeID
}
