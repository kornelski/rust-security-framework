use core_foundation_sys::base::CFTypeID;

extern "C" {
    #[deprecated(note = "Deprecated by Apple. SecKeychain is deprecated")]
    pub fn SecAccessGetTypeID() -> CFTypeID;
}
