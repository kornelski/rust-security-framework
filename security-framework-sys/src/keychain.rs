use core_foundation_sys::base::{Boolean, OSStatus, CFTypeID, CFTypeRef};
use libc::{c_char, c_uint, c_void};

use base::{SecAccessRef, SecKeychainRef, SecKeychainItemRef};

pub const SEC_KEYCHAIN_SETTINGS_VERS1: c_uint = 1;

#[repr(C)]
pub struct SecKeychainSettings {
    pub version: c_uint,
    pub lockOnSleep: Boolean,
    pub useLockInterval: Boolean,
    pub lockInterval: c_uint,
}

// Little endian 4-char literal
macro_rules! char_lit_le {
    ($e:expr) => {
        ($e[0] as u32) + (($e[1] as u32) << 8) + (($e[2] as u32) << 16) + (($e[3] as u32) << 24)
    };
}

// Big endian 4-char literal
macro_rules! char_lit_be {
    ($e:expr) => {
        ($e[3] as u32) + (($e[2] as u32) << 8) + (($e[1] as u32) << 16) + (($e[0] as u32) << 24)
    };
}

#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SecProtocolType {
    FTP = char_lit_le!(b"ftp "),
    FTPAccount = char_lit_le!(b"ftpa"),
    HTTP = char_lit_le!(b"http"),
    IRC = char_lit_le!(b"irc "),
    NNTP = char_lit_le!(b"nntp"),
    POP3 = char_lit_le!(b"pop3"),
    SMTP = char_lit_le!(b"smtp"),
    SOCKS = char_lit_le!(b"sox "),
    IMAP = char_lit_le!(b"imap"),
    LDAP = char_lit_le!(b"ldap"),
    AppleTalk = char_lit_le!(b"atlk"),
    AFP = char_lit_le!(b"afp "),
    Telnet = char_lit_le!(b"teln"),
    SSH = char_lit_le!(b"ssh "),
    FTPS = char_lit_le!(b"ftps"),
    HTTPS = char_lit_le!(b"htps"),
    HTTPProxy = char_lit_le!(b"htpx"),
    HTTPSProxy = char_lit_le!(b"htsx"),
    FTPProxy = char_lit_le!(b"ftpx"),
    CIFS = char_lit_le!(b"cifs"),
    SMB = char_lit_le!(b"smb "),
    RTSP = char_lit_le!(b"rtsp"),
    RTSPProxy = char_lit_le!(b"rtsx"),
    DAAP = char_lit_le!(b"daap"),
    EPPC = char_lit_le!(b"eppc"),
    IPP = char_lit_le!(b"ipp "),
    NNTPS = char_lit_le!(b"ntps"),
    LDAPS = char_lit_le!(b"ldps"),
    TelnetS = char_lit_le!(b"tels"),
    IMAPS = char_lit_le!(b"imps"),
    IRCS = char_lit_le!(b"ircs"),
    POP3S = char_lit_le!(b"pops"),
    CVSpserver = char_lit_le!(b"cvsp"),
    SVN = char_lit_le!(b"svn "),
    Any = 0,
}

#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SecAuthenticationType {
    // [sic] Apple has got two related enums each with a different endianness!
    NTLM = char_lit_be!(b"ntlm"),
    MSN = char_lit_be!(b"msna"),
    DPA = char_lit_be!(b"dpaa"),
    RPA = char_lit_be!(b"rpaa"),
    HTTPBasic = char_lit_be!(b"http"),
    HTTPDigest = char_lit_be!(b"httd"),
    HTMLForm = char_lit_be!(b"form"),
    Default = char_lit_be!(b"dflt"),
    Any = 0,
}

extern "C" {
    pub fn SecKeychainGetTypeID() -> CFTypeID;
    pub fn SecKeychainCopyDefault(keychain: *mut SecKeychainRef) -> OSStatus;
    pub fn SecKeychainCreate(
        pathName: *const c_char,
        passwordLength: c_uint,
                             password: *const c_void,
                             promptUser: Boolean,
                             initialAccess: SecAccessRef,
        keychain: *mut SecKeychainRef,
    ) -> OSStatus;
    pub fn SecKeychainOpen(pathName: *const c_char, keychain: *mut SecKeychainRef) -> OSStatus;
    pub fn SecKeychainUnlock(
        keychain: SecKeychainRef,
        passwordLength: c_uint,
                             password: *const c_void,
                             usePassword: Boolean)
                             -> OSStatus;
    #[cfg(target_os = "macos")]
    pub fn SecKeychainFindGenericPassword(keychainOrArray: CFTypeRef,
                                          serviceNameLength: u32,
                                          serviceName: *const c_char,
                                          accountNameLength: u32,
                                          accountName: *const c_char,
                                          passwordLength: *mut u32,
                                          passwordData: *mut *mut c_void,
                                          itemRef: *mut SecKeychainItemRef)
                                          -> OSStatus;

    #[cfg(target_os = "macos")]
    pub fn SecKeychainFindInternetPassword(
        keychainOrArray: CFTypeRef,
        serverNameLength: u32,
        serverName: *const c_char,
        securityDomainLength: u32,
        securityDomain: *const c_char,
        accountNameLength: u32,
        accountName: *const c_char,
        pathLength: u32,
        path: *const c_char,
        port: u16,
        protocol: SecProtocolType,
        authenticationType: SecAuthenticationType,
        passwordLength: *mut u32,
        passwordData: *mut *mut c_void,
        itemRef: *mut SecKeychainItemRef,
    ) -> OSStatus;

    #[cfg(target_os = "macos")]
    pub fn SecKeychainAddGenericPassword(keychain: SecKeychainRef,
                                         serviceNameLength: u32,
                                         serviceName: *const c_char,
                                         accountNameLength: u32,
                                         accountName: *const c_char,
                                         passwordLength: u32,
                                         passwordData: *const c_void,
                                         itemRef: *mut SecKeychainItemRef)
                                         -> OSStatus;

    #[cfg(target_os = "macos")]
    pub fn SecKeychainAddInternetPassword(
        keychain: SecKeychainRef,
        serverNameLength: u32,
        serverName: *const c_char,
        securityDomainLength: u32,
        securityDomain: *const c_char,
        accountNameLength: u32,
        accountName: *const c_char,
        pathLength: u32,
        path: *const c_char,
        port: u16,
        protocol: SecProtocolType,
        authenticationType: SecAuthenticationType,
        passwordLength: u32,
        passwordData: *const c_void,
        itemRef: *mut SecKeychainItemRef,
    ) -> OSStatus;

    pub fn SecKeychainSetSettings(
        keychain: SecKeychainRef,
        newSettings: *const SecKeychainSettings,
    ) -> OSStatus;
}
