//! Security Policies support.
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::base::{errSecParam, SecPolicyRef};
use security_framework_sys::policy::*;

use std::mem;
use std::fmt;

use ErrorNew;
use base::{Error, Result};

make_wrapper! {
    /// A type representing a certificate validation policy.
    struct SecPolicy, SecPolicyRef, SecPolicyGetTypeID
}

unsafe impl Sync for SecPolicy {}
unsafe impl Send for SecPolicy {}

impl fmt::Debug for SecPolicy {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("SecPolicy")
           .finish()
    }
}

impl SecPolicy {
    /// Creates a `SecPolicy` suitable for validating certificates for SSL.
    pub fn for_ssl(server: bool, hostname: &str) -> Result<SecPolicy> {
        let hostname_cf = CFString::new(hostname);
        unsafe {
            let policy = SecPolicyCreateSSL(server as u8, hostname_cf.as_concrete_TypeRef());
            if policy.is_null() {
                Err(Error::new(errSecParam))
            } else {
                Ok(SecPolicy::wrap_under_create_rule(policy))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use ::policy::SecPolicy;

    #[test]
    fn for_ssl() {
        let policy = SecPolicy::for_ssl(true, "certifi.org");
        assert_eq!(policy.is_ok(), true);
    }
}
