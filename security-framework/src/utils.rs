use std::collections::HashMap;

use core_foundation::{base::{CFCopyDescription, CFGetTypeID, TCFType}, data::CFData, date::CFDate, dictionary::CFDictionary, string::CFString};

pub fn simplify_dict(dict: &CFDictionary) -> HashMap<String, String> {
    unsafe {
        let mut retmap = HashMap::new();
        let (keys, values) = dict.get_keys_and_values();
        for (k, v) in keys.iter().zip(values.iter()) {
            let keycfstr = CFString::wrap_under_get_rule((*k).cast());
            let val: String = match CFGetTypeID(*v) {
                cfstring if cfstring == CFString::type_id() => {
                    format!("{}", CFString::wrap_under_get_rule((*v).cast()))
                },
                cfdata if cfdata == CFData::type_id() => {
                    let buf = CFData::wrap_under_get_rule((*v).cast());
                    let mut vec = Vec::new();
                    vec.extend_from_slice(buf.bytes());
                    format!("{}", String::from_utf8_lossy(&vec))
                }
                cfdate if cfdate == CFDate::type_id() => format!(
                    "{}",
                    CFString::wrap_under_create_rule(CFCopyDescription(*v))
                ),
                _ => String::from("unknown"),
            };
            retmap.insert(format!("{keycfstr}"), val);
        }
        retmap
    }
}