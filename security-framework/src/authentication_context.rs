//! A local authentication context that keychain operations can share.

use core_foundation::base::{CFType, TCFType};
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use std::fmt;
use std::time::Duration;

/// An `LAContext` that lets one user authentication serve several keychain operations.
///
/// Clones share the same context, including across threads. Configure it with [`AuthenticationContext::builder`],
/// since it cannot change once built.
#[derive(Clone)]
pub struct AuthenticationContext(pub(crate) CFType);

// SAFETY: this crate only retains, releases and passes the `LAContext` to `SecItem*` once it is built, never calling
// its methods, which relies on LocalAuthentication synchronizing its own state when one context serves concurrent
// keychain calls.
unsafe impl Send for AuthenticationContext {}
// SAFETY: as for `Send`, since a shared reference offers no mutator.
unsafe impl Sync for AuthenticationContext {}

impl AuthenticationContext {
    /// Creates a context with the default settings that has not authenticated yet.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Starts configuring a context.
    #[must_use]
    pub fn builder() -> AuthenticationContextBuilder {
        // SAFETY: `+[LAContext new]` has no preconditions.
        // madsmtm/objc2#864 marks this safe, so the `unsafe` can go once it is released.
        AuthenticationContextBuilder(unsafe { LAContext::new() })
    }
}

impl Default for AuthenticationContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AuthenticationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationContext").finish_non_exhaustive()
    }
}

/// Configures an [`AuthenticationContext`] before it can be shared.
pub struct AuthenticationContextBuilder(Retained<LAContext>);

impl AuthenticationContextBuilder {
    /// Sets the text the authentication prompt shows, which replaces the deprecated `kSecUseOperationPrompt`.
    #[must_use]
    pub fn localized_reason(self, reason: &str) -> Self {
        // SAFETY: the setter has no preconditions, and the builder is the only owner of the context.
        // madsmtm/objc2#864 marks this safe, so the `unsafe` can go once it is released.
        unsafe { self.0.setLocalizedReason(&NSString::from_str(reason)) };
        self
    }

    /// Sets whether keychain calls may prompt the user, failing with `errSecInteractionNotAllowed` when they may not.
    #[must_use]
    pub fn interaction_allowed(self, allowed: bool) -> Self {
        // SAFETY: the setter has no preconditions, and the builder is the only owner of the context.
        // madsmtm/objc2#864 marks this safe, so the `unsafe` can go once it is released.
        unsafe { self.0.setInteractionNotAllowed(!allowed) };
        self
    }

    /// Accepts a Touch ID device unlock this recent in place of a prompt, capped by LocalAuthentication at five minutes.
    #[must_use]
    pub fn touch_id_reuse_duration(self, duration: Duration) -> Self {
        // SAFETY: the setter has no preconditions, and the builder is the only owner of the context.
        // madsmtm/objc2#864 marks this safe, so the `unsafe` can go once it is released.
        unsafe { self.0.setTouchIDAuthenticationAllowableReuseDuration(duration.as_secs_f64()) };
        self
    }

    /// Finishes configuration.
    #[must_use]
    pub fn build(self) -> AuthenticationContext {
        // SAFETY: `into_raw` hands over the builder's retain, which the create rule adopts, and `CFRelease` accepts
        // Objective-C objects.
        AuthenticationContext(unsafe { CFType::wrap_under_create_rule(Retained::into_raw(self.0).cast()) })
    }
}

impl fmt::Debug for AuthenticationContextBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationContextBuilder").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn builder_applies_settings() {
        let context = AuthenticationContext::builder()
            .localized_reason("unlock the vault")
            .interaction_allowed(false)
            .touch_id_reuse_duration(Duration::from_secs(10))
            .build();
        // SAFETY: the `CFType` wraps the `LAContext` created by `build`.
        let la_context = unsafe { &*context.0.as_CFTypeRef().cast::<LAContext>() };
        // SAFETY: the getters have no preconditions.
        unsafe {
            assert_eq!(la_context.localizedReason().to_string(), "unlock the vault");
            assert!(la_context.interactionNotAllowed());
            assert_eq!(la_context.touchIDAuthenticationAllowableReuseDuration(), 10.0);
        }
    }
}
