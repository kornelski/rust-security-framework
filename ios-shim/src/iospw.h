/// Header material that XCode can use to create a bridging header
///
/// In order to call the external C ABI from Swift, XCode creates a
/// "bridging header" in which it does memory reference analysis of
/// the C API entires.  The default analysis is that input-only objects
/// remain memory managed, but in-out objects are unmanaged.
///
/// In this API, there is one call - `RustShimCopyGenericPassword` - that
/// retains an output CFData object and passes ownership to the caller.
/// Although it's named correctly per CF conventions to let the compiler
/// infer that the output is retained, that's not always reliably done,
/// so in this header the CF_RETURNS_RETAINED annotation is used to force
/// the correct interpretation.  This allows Swift (and other ARC-based)
/// callers to do automated memory management.
#ifndef RUST_SECURITY_FRAMEWORK_IOSPW_H
#define RUST_SECURITY_FRAMEWORK_IOSPW_H

#include <CoreFoundation/CoreFoundation.h>

extern OSStatus RustShimSetGenericPassword(CFStringRef service, CFStringRef account, CFDataRef password);
extern OSStatus RustShimCopyGenericPassword(CFStringRef service, CFStringRef account, CF_RETURNS_RETAINED CFDataRef *password);
extern OSStatus RustShimDeleteGenericPassword(CFStringRef service, CFStringRef account);

#endif //RUST_SECURITY_FRAMEWORK_IOSPW_H
