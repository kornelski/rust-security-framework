pub mod certificate;
pub mod import_export;
mod identity;
mod item;
pub mod secure_transport;
pub mod keychain;

#[cfg(test)]
pub mod test {
    use item::{ItemSearchOptions, ItemClass};
    use os::macos::import_export::{SecItems, ImportOptions};
    use os::macos::keychain::SecKeychainExt;
    use identity::SecIdentity;
    use certificate::SecCertificate;
    use keychain::SecKeychain;

    pub fn identity() -> SecIdentity {
        let mut items = p!(ItemSearchOptions::new()
            .class(ItemClass::Identity)
            .keychains(&[keychain()])
            .search());
        items.identities.pop().unwrap()
    }

    pub fn certificate() -> SecCertificate {
        let certificate = include_bytes!("../../../test/server.crt");
        let mut items = SecItems::default();
        p!(ImportOptions::new()
           .filename("server.crt")
           .items(&mut items)
           .import(certificate));
        items.certificates.pop().unwrap()
    }

    pub fn keychain() -> SecKeychain {
        // the path has to be absolute for some reason
        let mut keychain = p!(SecKeychain::open(concat!(env!("PWD"), "/test/server.keychain")));
        p!(keychain.unlock(Some("password123")));
        keychain
    }
}
