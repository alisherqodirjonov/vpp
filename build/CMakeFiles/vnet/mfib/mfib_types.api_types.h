#ifndef included_mfib_types_api_types_h
#define included_mfib_types_api_types_h
#define VL_API_MFIB_TYPES_API_VERSION_MAJOR 1
#define VL_API_MFIB_TYPES_API_VERSION_MINOR 0
#define VL_API_MFIB_TYPES_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/fib/fib_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    MFIB_API_ENTRY_FLAG_NONE = 0,
    MFIB_API_ENTRY_FLAG_SIGNAL = 1,
    MFIB_API_ENTRY_FLAG_DROP = 2,
    MFIB_API_ENTRY_FLAG_CONNECTED = 4,
    MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF = 8,
} vl_api_mfib_entry_flags_t;
typedef enum {
    MFIB_API_ITF_FLAG_NONE = 0,
    MFIB_API_ITF_FLAG_NEGATE_SIGNAL = 1,
    MFIB_API_ITF_FLAG_ACCEPT = 2,
    MFIB_API_ITF_FLAG_FORWARD = 4,
    MFIB_API_ITF_FLAG_SIGNAL_PRESENT = 8,
    MFIB_API_ITF_FLAG_DONT_PRESERVE = 16,
} vl_api_mfib_itf_flags_t;
typedef struct __attribute__ ((packed)) _vl_api_mfib_path {
    vl_api_mfib_itf_flags_t itf_flags;
    vl_api_fib_path_t path;
} vl_api_mfib_path_t;
#define VL_API_MFIB_PATH_IS_CONSTANT_SIZE (1)


#endif
