use core_foundation_sys::base::CFTypeID;

extern "C" {
    pub fn SecKeychainItemGetTypeID() -> CFTypeID;
}
