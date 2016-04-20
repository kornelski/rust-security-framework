use core_foundation_sys::error::CFErrorRef;

use base::SecKeyRef;
use transform::SecTransformRef;

extern "C" {
	pub fn SecSignTransformCreate(key: SecKeyRef, error: *mut CFErrorRef) -> SecTransformRef;
}
