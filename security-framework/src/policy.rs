//! Security Policies support.
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::base::{errSecParam, SecPolicyRef};
use security_framework_sys::policy::*;
use std::fmt;
use std::ptr;

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
    /// Deprecated
    #[deprecated(since = "0.1.12", note = "use SecPolicy::create_ssl")]
    pub fn for_ssl(protocol_side: ProtocolSide, hostname: &str) -> Result<SecPolicy> {
        let hostname_cf = CFString::new(hostname);
        let client_side = match protocol_side {
            ProtocolSide::Server => 0,
            ProtocolSide::Client => 1,
        };
        unsafe {
            let policy = SecPolicyCreateSSL(client_side as u8, hostname_cf.as_concrete_TypeRef());
            if policy.is_null() {
                Err(Error::from_code(errSecParam))
            } else {
                Ok(SecPolicy::wrap_under_create_rule(policy))
            }
        }
    }

    /// Creates a `SecPolicy` for evaluating SSL certificate chains.
    ///
    /// The side which you are evaluating should be provided (i.e. pass `ProtocolSide::Server` if
    /// you are a client looking to validate a server's certificate chain).
    pub fn create_ssl(protocol_side: ProtocolSide, hostname: Option<&str>) -> SecPolicy {
        let hostname = hostname.map(CFString::new);
        let hostname = hostname.as_ref().map(|s| s.as_concrete_TypeRef()).unwrap_or(ptr::null_mut());
        let server = match protocol_side {
            ProtocolSide::Server => 1,
            ProtocolSide::Client => 0,
        };
        unsafe {
            let policy = SecPolicyCreateSSL(server, hostname);
            SecPolicy::wrap_under_create_rule(policy)
        }
    }
}

#[cfg(test)]
mod test {
    use policy::SecPolicy;
    use secure_transport::ProtocolSide;

    #[test]
    fn create_ssl() {
        SecPolicy::create_ssl(ProtocolSide::Server, Some("certifi.org"));
    }
}
