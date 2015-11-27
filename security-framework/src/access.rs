//! Access control functionality.

use security_framework_sys::base::SecAccessRef;
use security_framework_sys::access::SecAccessGetTypeID;
use std::mem;

make_wrapper!(SecAccess, SecAccessRef, SecAccessGetTypeID);
