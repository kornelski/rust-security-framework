#![allow(bad_style)]
#![allow(unused_imports)]
#![allow(dead_code)]

use core_foundation_sys::base::*;
use security_framework_sys::base::*;
pub use security_framework_sys::secure_transport::*;

use std::mem;
use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT, Ordering};
use libc;

unsafe fn get<'a, T>(ptr: &'a AtomicUsize, name: &str) -> Option<&'a T> {
    assert_eq!(mem::size_of::<T>(), mem::size_of_val(ptr));
    match ptr.load(Ordering::SeqCst) {
        0 => {}
        1 => return None,
        _ => return Some(&*(ptr as *const _ as *const T)),
    }

    let lib = "Security.framework/Versions/A/Security\0";
    let lib = libc::dlopen(lib.as_ptr() as *const _, libc::RTLD_LAZY);
    let mut ret = 1;
    if !lib.is_null() {
        let sym = libc::dlsym(lib, name.as_ptr() as *const _);
        if !sym.is_null() {
            ret = sym as usize;
        }
    }
    match ptr.compare_exchange(0, ret, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(1) |
        Err(1) => None,
        Ok(_) |
        Err(_) => Some(&*(ptr as *const _ as *const T)),
    }
}

macro_rules! compat {
    ($(fn $name:ident($($arg:ident: $t:ty),*) -> $ret:ty {
        $($code:tt)*
    })*) => {$(
        pub unsafe extern fn $name($($arg:$t),*) -> $ret {
            static PTR: AtomicUsize = ATOMIC_USIZE_INIT;
            type T = unsafe extern fn($($t),*) -> $ret;
            match get::<T>(&PTR, concat!(stringify!($name), "\0")) {
                Some(f) => f($($arg),*),
                None => { $($code)* }
            }
        }
    )*}
}

#[cfg(not(feature = "OSX_10_8"))]
compat! {
    fn SSLSetProtocolVersionMin(context: SSLContextRef,
                                minVersion: SSLProtocol) -> OSStatus {
        errSecIO
    }
}
