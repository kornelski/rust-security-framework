#pragma once
#include <Security/SecureTransport.h>

#ifdef __cplusplus
extern "C" {
#endif

// ALPN
typedef void
(*SSLALPNFunc)             (SSLContextRef          ctx,
                            void                    *info,		/* info pointer provided by SSLSetALPNFunc */
                            const void			    *alpnData,
                            size_t                  alpnDataLength);

void
SSLSetALPNFunc              (SSLContextRef      context,
                             SSLALPNFunc         alpnFunc,
                             void               *info)
    __OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0);


OSStatus
SSLSetALPNData				(SSLContextRef      context,
                             const void *data,
                             size_t length)
    __OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0);

const void *
SSLGetALPNData				(SSLContextRef      context,
                             size_t				*length)
    __OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0);

// end of ALPN

#ifdef __cplusplus
}
#endif
