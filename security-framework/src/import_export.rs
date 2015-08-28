use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use security_framework_sys::base::{errSecIO, errSecSuccess};
use security_framework_sys::import_export::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::ptr;
use std::str::FromStr;

use ErrorNew;
use base::{Error, Result};
use certificate::SecCertificate;
use identity::SecIdentity;
use key::SecKey;

pub struct SecItems {
    pub certificates: Vec<SecCertificate>,
    pub identities: Vec<SecIdentity>,
    pub keys: Vec<SecKey>,
}

pub fn import_items_from_file<P: AsRef<Path>>(path: P) -> Result<SecItems> {
    let path = path.as_ref();

    let mut data = vec![];
    // FIXME
    if let Err(_) = File::open(path).map(|mut f| f.read_to_end(&mut data)) {
        return Err(Error::new(errSecIO));
    }
    let data = CFData::from_buffer(&data);

    let filename = path.file_name().unwrap();
    let filename = CFString::from_str(&filename.to_string_lossy()).unwrap();

    let items = unsafe {
        let mut raw_items = ptr::null();
        let ret = SecItemImport(data.as_concrete_TypeRef(), filename.as_concrete_TypeRef(),
                                ptr::null_mut(), ptr::null_mut(), 0, ptr::null(), ptr::null_mut(),
                                &mut raw_items);
        if ret != errSecSuccess {
            return Err(Error::new(ret));
        }

        let mut items = SecItems {
            certificates: vec![],
            identities: vec![],
            keys: vec![],
        };

        let raw_items = CFArray::wrap_under_create_rule(raw_items);
        for item in raw_items.iter() {
            let type_id = CFType::wrap_under_get_rule(item as *mut _).type_of();
            if type_id == SecCertificate::type_id() {
                items.certificates.push(SecCertificate::wrap_under_get_rule(item as *mut _));
            } else if type_id == SecIdentity::type_id() {
                items.identities.push(SecIdentity::wrap_under_get_rule(item as *mut _));
            } else if type_id == SecKey::type_id() {
                items.keys.push(SecKey::wrap_under_get_rule(item as *mut _));
            } else {
                panic!("Got bad type from SecItemImport: {}", type_id);
            }
        }

        items
    };

    Ok(items)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn certificate() {
        let items = import_items_from_file("test/server.crt").unwrap();
        assert_eq!(1, items.certificates.len());
        assert_eq!(0, items.identities.len());
        assert_eq!(0, items.keys.len());
    }

    #[test]
    fn key() {
        let items = import_items_from_file("test/server.key").unwrap();
        assert_eq!(0, items.certificates.len());
        assert_eq!(0, items.identities.len());
        assert_eq!(1, items.keys.len());
    }
}
