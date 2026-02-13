#![allow(bad_style)]
#![allow(unused)]
#![allow(clippy::all)]
#![allow(deprecated)]
#![allow(deref_nullptr)]
#![allow(invalid_value)] // mem::uninitialized has to stay
#![allow(clippy::all)]
#![allow(function_casts_as_integer)]
#![allow(deprecated)]

use core_foundation_sys::base::{CFOptionFlags, OSStatus};
use core_foundation_sys::string::CFStringRef;
use std::os::raw::*;

#[cfg(target_os = "macos")]
use security_framework_sys::access::*;
use security_framework_sys::access_control::*;
#[cfg(target_os = "macos")]
use security_framework_sys::authorization::*;
use security_framework_sys::base::*;
use security_framework_sys::certificate::*;
#[cfg(target_os = "macos")]
use security_framework_sys::certificate_oids::*;
use security_framework_sys::cipher_suite::*;
#[cfg(target_os = "macos")]
use security_framework_sys::cms::*;
#[cfg(target_os = "macos")]
use security_framework_sys::code_signing::*;
#[cfg(target_os = "macos")]
use security_framework_sys::digest_transform::*;
#[cfg(target_os = "macos")]
use security_framework_sys::encrypt_transform::*;
use security_framework_sys::identity::*;
use security_framework_sys::import_export::*;
use security_framework_sys::item::*;
use security_framework_sys::key::*;
use security_framework_sys::keychain::*;
use security_framework_sys::keychain_item::*;
use security_framework_sys::policy::*;
use security_framework_sys::random::*;
use security_framework_sys::secure_transport::*;
#[cfg(target_os = "macos")]
use security_framework_sys::transform::*;
use security_framework_sys::trust::*;
#[cfg(target_os = "macos")]
use security_framework_sys::trust_settings::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
