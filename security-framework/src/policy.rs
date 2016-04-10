//! Security Policies support.
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::base::{errSecParam, SecPolicyRef};
use security_framework_sys::policy::*;

use std::mem;
use std::fmt;

use ErrorNew;
use base::{Error, Result};
use secure_transport::ProtocolSide;

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
    pub fn for_ssl(protocol_side: ProtocolSide, hostname: &str) -> Result<SecPolicy> {
        let hostname_cf = CFString::new(hostname);
        let client_side = match protocol_side {
            ProtocolSide::Server => 0,
            ProtocolSide::Client => 1,
        };
        unsafe {
            let policy = SecPolicyCreateSSL(client_side as u8, hostname_cf.as_concrete_TypeRef());
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
    use policy::SecPolicy;
    use secure_transport::ProtocolSide;

    #[test]
    fn for_ssl() {
        let policy = SecPolicy::for_ssl(ProtocolSide::Client, "certifi.org");
        assert_eq!(policy.is_ok(), true);
    }
}
