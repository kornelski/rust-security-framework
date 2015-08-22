extern crate libc;

pub mod secure_transport;

pub type Boolean = u8;
pub type OSStatus = i32;
pub const ioErr: OSStatus = -36;
