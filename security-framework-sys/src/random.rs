use libc::{c_void, size_t, c_int};

#[repr(C)]
pub struct __SecRandom(c_void);
pub type SecRandomRef = *const __SecRandom;

extern "C" {
    pub static kSecRandomDefault: SecRandomRef;

    pub fn SecRandomCopyBytes(rnd: SecRandomRef, count: size_t, bytes: *mut u8) -> c_int;
}
