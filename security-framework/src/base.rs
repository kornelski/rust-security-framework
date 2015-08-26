use core_foundation_sys::base::OSStatus;
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework_sys::base::SecCopyErrorMessageString;
use std::error;
use std::fmt;
use std::ptr;
use std::result;

use ErrorNew;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(OSStatus);

impl ErrorNew for Error {
    fn new(status: OSStatus) -> Error {
        Error(status)
    }
}

impl Error {
    pub fn message(&self) -> Option<String> {
        unsafe {
            let s = SecCopyErrorMessageString(self.0, ptr::null_mut());
            if s.is_null() {
                None
            } else {
                let s = CFString::wrap_under_create_rule(s);
                Some(s.to_string())
            }
        }
    }

    pub fn code(&self) -> OSStatus {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if let Some(message) = self.message() {
            write!(fmt, "{}", message)
        } else {
            write!(fmt, "error code {}", self.code())
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Secure Transport error"
    }
}
