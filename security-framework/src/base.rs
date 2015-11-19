use core_foundation_sys::base::OSStatus;
use std::error;
use std::fmt;
use std::result;

use ErrorNew;

pub type Result<T> = result::Result<T, Error>;

pub struct Error(OSStatus);

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.0);
        if let Some(message) = self.message() {
            builder.field("message", &message);
        }
        builder.finish()
    }
}

impl ErrorNew for Error {
    fn new(status: OSStatus) -> Error {
        Error(status)
    }
}

impl Error {
    #[cfg(target_os = "macos")]
    pub fn message(&self) -> Option<String> {
        use security_framework_sys::base::SecCopyErrorMessageString;
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;
        use std::ptr;

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

    #[cfg(target_os = "ios")]
    pub fn message(&self) -> Option<String> {
        None
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
