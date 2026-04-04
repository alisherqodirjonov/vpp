#ifndef included_fib_api_types_h
#define included_fib_api_types_h
#define VL_API_FIB_API_VERSION_MAJOR 1
#define VL_API_FIB_API_VERSION_MINOR 0
#define VL_API_FIB_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/fib/fib_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_fib_source {
    u8 priority;
    u8 id;
    u8 name[64];
} vl_api_fib_source_t;
#define VL_API_FIB_SOURCE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_fib_source_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_fib_source_t src;
} vl_api_fib_source_add_t;
#define VL_API_FIB_SOURCE_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_fib_source_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 id;
} vl_api_fib_source_add_reply_t;
#define VL_API_FIB_SOURCE_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_fib_source_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_fib_source_dump_t;
#define VL_API_FIB_SOURCE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_fib_source_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_fib_source_t src;
} vl_api_fib_source_details_t;
#define VL_API_FIB_SOURCE_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_FIB_SOURCE_ADD_CRC "fib_source_add_b3ac2aec"
#define VL_API_FIB_SOURCE_ADD_REPLY_CRC "fib_source_add_reply_604fd6f1"
#define VL_API_FIB_SOURCE_DUMP_CRC "fib_source_dump_51077d14"
#define VL_API_FIB_SOURCE_DETAILS_CRC "fib_source_details_8668acdb"

#endif
