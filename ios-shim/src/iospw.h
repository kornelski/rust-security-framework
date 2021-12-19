//
// Created by Daniel Brotsky on 12/18/21.
//

#ifndef RUST_SECURITY_FRAMEWORK_IOSPW_H
#define RUST_SECURITY_FRAMEWORK_IOSPW_H

#include <stdint.h>

extern int32_t set_generic_password(const char *service, const char *user, const uint8_t *pw, uint64_t pw_len);
extern int32_t get_generic_password(const char *service, const char *user, uint8_t *buffer, uint64_t buf_len, uint64_t *pw_len);
extern int32_t delete_generic_password(const char *service, const char *user);

#endif //RUST_SECURITY_FRAMEWORK_IOSPW_H
