//
// Created by Daniel Brotsky on 12/18/21.
//

#ifndef RUST_SECURITY_FRAMEWORK_IOSPW_H
#define RUST_SECURITY_FRAMEWORK_IOSPW_H

#include <CoreFoundation/CoreFoundation.h>

extern OSStatus SecSetGenericPassword(CFStringRef service, CFStringRef account, CFDataRef password);
extern OSStatus SecCopyGenericPassword(CFStringRef service, CFStringRef account, CFDataRef *password);
extern OSStatus SecDeleteGenericPassword(CFStringRef service, CFStringRef account);

#endif //RUST_SECURITY_FRAMEWORK_IOSPW_H
