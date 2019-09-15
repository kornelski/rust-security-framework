//! Querying trust settings.

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation::number::CFNumber;
use core_foundation::base::{TCFType, CFIndex};

use security_framework_sys::trust_settings::*;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::base::errSecNoTrustSettings;

use std::ptr;
use std::convert::TryFrom;

use base::Result;
use base::Error;
use certificate::SecCertificate;

/// Which set of trust settings to query
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Domain {
    /// Per-user trust settings
    User,
    /// Locally administered, system-wide trust settings
    Admin,
    /// System trust settings
    System
}

impl Into<SecTrustSettingsDomain> for Domain {
    fn into(self) -> SecTrustSettingsDomain {
        match self {
            Domain::User => kSecTrustSettingsDomainUser,
            Domain::Admin => kSecTrustSettingsDomainAdmin,
            Domain::System => kSecTrustSettingsDomainSystem,
        }
    }
}

/// Trust settings for a specific certificate in a specific domain
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TrustSettingsForCertificate {
    /// Not used
    Invalid,

    /// This is a root certificate and is trusted, either explicitly or
    /// implicitly.
    TrustRoot,

    /// This is a non-root certificate but is explicitly trusted.
    TrustAsRoot,

    /// Cert is explicitly distrusted.
    Deny,

    /// Neither trusted nor distrusted.
    Unspecified
}

impl TrustSettingsForCertificate {
    fn new(value: i64) -> TrustSettingsForCertificate {
        match u32::try_from(value).ok() {
            Some(kSecTrustSettingsResultTrustRoot) => TrustSettingsForCertificate::TrustRoot,
            Some(kSecTrustSettingsResultTrustAsRoot) => TrustSettingsForCertificate::TrustAsRoot,
            Some(kSecTrustSettingsResultDeny) => TrustSettingsForCertificate::Deny,
            Some(kSecTrustSettingsResultUnspecified) => TrustSettingsForCertificate::Unspecified,
            Some(_) | None => TrustSettingsForCertificate::Invalid,
        }
    }
}

/// Allows access to the certificates and their trust settings in a given domain.
pub struct TrustSettings {
    domain: Domain,
}

impl TrustSettings {
    /// Create a new TrustSettings for the given domain.
    ///
    /// You can call `iter()` to discover the certificates with settings in this domain.
    ///
    /// Then you can call `tls_trust_settings_for_certificate()` with a given certificate
    /// to learn what the aggregate trust setting for that certificate within this domain.
    pub fn new(domain: Domain) -> TrustSettings {
        TrustSettings { domain }
    }

    /// Create an iterator over the certificates with settings in this domain.
    /// This produces an empty iterator if there are no such certificates.
    pub fn iter(&self) -> Result<TrustSettingsIter> {
        let array = unsafe {
            let mut array_ptr: CFArrayRef = ptr::null_mut();

            // SecTrustSettingsCopyCertificates returns errSecNoTrustSettings
            // if no items have trust settings in the given domain.  We map
            // that to an empty TrustSettings iterator.
            match SecTrustSettingsCopyCertificates(self.domain.into(), &mut array_ptr) {
                errSecNoTrustSettings => {
                    Ok(CFArray::from_CFTypes(&[]))
                },
                errSecSuccess => {
                    Ok(CFArray::<SecCertificate>::wrap_under_create_rule(array_ptr))
                },
                err => Err(Error::from_code(err)),
            }?
        };

        Ok(TrustSettingsIter {
            index: 0,
            array,
        })
    }

    /// Returns the aggregate trust setting for the given certificate.
    ///
    /// This tells you whether the certificate should be trusted as a TLS
    /// root certificate.
    pub fn tls_trust_settings_for_certificate(&self, cert: &SecCertificate)
        -> Result<TrustSettingsForCertificate> {
        let trust_settings = unsafe {
            let mut array_ptr: CFArrayRef = ptr::null_mut();
            let cert_ptr = cert.as_CFTypeRef() as *mut _;
            match SecTrustSettingsCopyTrustSettings(cert_ptr, self.domain.into(), &mut array_ptr) {
                errSecNoTrustSettings => {
                    Ok(CFArray::from_CFTypes(&[]))
                },
                errSecSuccess => {
                    Ok(CFArray::<CFDictionary>::wrap_under_create_rule(array_ptr))
                },
                err => Err(Error::from_code(err)),
            }?
        };

        for settings in trust_settings.iter() {
            // Reject settings for non-SSL policies
            let is_not_ssl_policy = {
                let policy_name_key = CFString::from_static_string("kSecTrustSettingsPolicyName");
                let ssl_policy_name = CFString::from_static_string("sslServer");

                let maybe_name: Option<CFString> = settings.find(policy_name_key.as_CFTypeRef() as *const _)
                    .map(|name| unsafe { CFString::wrap_under_get_rule(*name as *const _) });

                match maybe_name {
                    Some(ref name) if name != &ssl_policy_name => true,
                    _ => false
                }
            };

            if is_not_ssl_policy { continue; }

            // Evaluate "effective trust settings" for this usage constraint.
            let maybe_trust_result = {
                let settings_result_key = CFString::from_static_string("kSecTrustSettingsResult");
                settings.find(settings_result_key.as_CFTypeRef() as *const _)
                    .map(|num| unsafe { CFNumber::wrap_under_get_rule(*num as *const _) })
                    .and_then(|num| num.to_i64())
            };

            // "Note that an empty Trust Settings array means "always trust this cert,
            //  with a resulting kSecTrustSettingsResult of kSecTrustSettingsResultTrustRoot"."
            let trust_result = TrustSettingsForCertificate::new(maybe_trust_result
                .unwrap_or(kSecTrustSettingsResultTrustRoot as i64));

            match trust_result {
                TrustSettingsForCertificate::Unspecified => { continue; },
                TrustSettingsForCertificate::Invalid => { continue; },
                _ => return Ok(trust_result),
            }
        }

        // There were no more specific settings, and trust is the default.
        Ok(TrustSettingsForCertificate::TrustRoot)
    }
}

/// Iterator over certificates.
pub struct TrustSettingsIter {
    array: CFArray<SecCertificate>,
    index: CFIndex,
}

impl Iterator for TrustSettingsIter {
    type Item = SecCertificate;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.array.len() {
            None
        } else {
            let cert = self.array.get(self.index)
                .unwrap();
            self.index += 1;
            Some(cert.clone())
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = (self.array.len() as usize)
            .saturating_sub(self.index as usize);
        (left, Some(left))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn list_for_domain(domain: Domain) {
        println!("--- domain: {:?}", domain);
        let ts = TrustSettings::new(domain);
        let iterator = ts.iter()
            .unwrap();

        for (i, cert) in iterator.enumerate() {
            println!("cert({:?}) = {:?}", i, cert);
            println!("  settings = {:?}", ts.tls_trust_settings_for_certificate(&cert));
        }
        println!("---");
    }

    #[test]
    fn list_for_user() {
        list_for_domain(Domain::User);
    }

    #[test]
    fn list_for_system() {
        list_for_domain(Domain::System);
    }

    #[test]
    fn list_for_admin() {
        list_for_domain(Domain::Admin);
    }

    #[test]
    fn test_system_certs_are_present() {
        let system = TrustSettings::new(Domain::System)
            .iter()
            .unwrap()
            .count();

        // 168 at the time of writing
        assert!(system > 100);
    }

    #[test]
    fn test_isrg_root_exists() {
        let ts = TrustSettings::new(Domain::System);
        assert!(ts
            .iter()
            .unwrap()
            .any(|cert| cert.subject_summary() == "ISRG Root X1" &&
                 ts.tls_trust_settings_for_certificate(&cert).unwrap() ==
                 TrustSettingsForCertificate::TrustRoot));
    }
    }
}
