//! OS specific extensions.

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos;
