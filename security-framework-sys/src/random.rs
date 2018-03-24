use libc::{c_void, size_t, c_int};

pub enum __SecRandom {}
pub type SecRandomRef = *const __SecRandom;

extern "C" {
    pub static kSecRandomDefault: SecRandomRef;

    pub fn SecRandomCopyBytes(rnd: SecRandomRef, count: size_t, bytes: *mut c_void) -> c_int;
}
