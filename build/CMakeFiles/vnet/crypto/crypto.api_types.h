#ifndef included_crypto_api_types_h
#define included_crypto_api_types_h
#define VL_API_CRYPTO_API_VERSION_MAJOR 1
#define VL_API_CRYPTO_API_VERSION_MINOR 0
#define VL_API_CRYPTO_API_VERSION_PATCH 1
/* Imported API files */
typedef enum __attribute__((packed)) {
    CRYPTO_ASYNC_DISPATCH_POLLING = 0,
    CRYPTO_ASYNC_DISPATCH_INTERRUPT = 1,
} vl_api_crypto_dispatch_mode_t;
STATIC_ASSERT(sizeof(vl_api_crypto_dispatch_mode_t) == sizeof(u8), "size of API enum crypto_dispatch_mode is wrong");
typedef enum __attribute__((packed)) {
    CRYPTO_API_OP_SIMPLE = 0,
    CRYPTO_API_OP_CHAINED = 1,
    CRYPTO_API_OP_BOTH = 2,
} vl_api_crypto_op_class_type_t;
STATIC_ASSERT(sizeof(vl_api_crypto_op_class_type_t) == sizeof(u8), "size of API enum crypto_op_class_type is wrong");
typedef struct __attribute__ ((packed)) _vl_api_crypto_set_async_dispatch {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_crypto_dispatch_mode_t mode;
} vl_api_crypto_set_async_dispatch_t;
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_crypto_set_async_dispatch_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_crypto_set_async_dispatch_reply_t;
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_crypto_set_async_dispatch_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_crypto_dispatch_mode_t mode;
    bool adaptive;
} vl_api_crypto_set_async_dispatch_v2_t;
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_crypto_set_async_dispatch_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_crypto_set_async_dispatch_v2_reply_t;
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_crypto_set_handler {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 alg_name[32];
    u8 engine[16];
    vl_api_crypto_op_class_type_t oct;
    u8 is_async;
} vl_api_crypto_set_handler_t;
#define VL_API_CRYPTO_SET_HANDLER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_crypto_set_handler_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_crypto_set_handler_reply_t;
#define VL_API_CRYPTO_SET_HANDLER_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_CRC "crypto_set_async_dispatch_5ca4adc0"
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_REPLY_CRC "crypto_set_async_dispatch_reply_e8d4e804"
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_CRC "crypto_set_async_dispatch_v2_667d2d54"
#define VL_API_CRYPTO_SET_ASYNC_DISPATCH_V2_REPLY_CRC "crypto_set_async_dispatch_v2_reply_e8d4e804"
#define VL_API_CRYPTO_SET_HANDLER_CRC "crypto_set_handler_ce9ad00d"
#define VL_API_CRYPTO_SET_HANDLER_REPLY_CRC "crypto_set_handler_reply_e8d4e804"

#endif
