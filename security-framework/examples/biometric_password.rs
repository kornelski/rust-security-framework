//! Store and retrieve a password with biometric authentication
//!
//! This example demonstrates storing a password that requires Touch ID or Face ID
//! to access, equivalent to the Swift code in unpass-mac/Unpass/ContentView.swift

use security_framework::access_control::ProtectionMode;
use security_framework::passwords::{set_generic_password_options, get_generic_password_options};
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

fn main() {
    let service = "com.example.biometric-test";
    let account = "testuser";
    let password = b"secret123";

    // Store password with biometric protection
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.set_access_control(
        ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly,
        AccessControlOptions::BIOMETRY_ANY
    );

    match set_generic_password_options(password, options) {
        Ok(()) => {
            println!("Password stored with biometric protection for {account}@{service}");
            println!("Protection: AccessibleWhenUnlockedThisDeviceOnly + BIOMETRY_ANY");
        }
        Err(err) => {
            eprintln!("Could not store password: {err:?}");
            return;
        }
    }

    // Retrieve the password with authentication context
    #[cfg(feature = "OSX_10_13")]
    {
        println!("Attempting to retrieve password...");
        println!("Note: In a real app, you would create an LAContext from LocalAuthentication framework");

        // For demonstration, we'll show what the code would look like:
        // let la_context = create_la_context(); // This would come from LocalAuthentication
        // let la_context_ptr = la_context as *mut std::os::raw::c_void;

        let retrieve_options = PasswordOptions::new_generic_password(service, account);
        // retrieve_options.set_authentication_context(la_context_ptr);

        // Since we don't have a real LAContext, this will fail with authentication required
        match get_generic_password_options(retrieve_options) {
            Ok(retrieved) => {
                println!("Retrieved password: {:?}", std::str::from_utf8(&retrieved));
                println!("Password matches: {}", retrieved == password);
            }
            Err(err) => {
                println!("Expected error without authentication context: {err:?}");
                println!("This demonstrates that biometric protection is working!");
            }
        }
    }
}
