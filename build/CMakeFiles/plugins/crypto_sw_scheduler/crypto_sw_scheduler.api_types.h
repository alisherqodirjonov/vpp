#ifndef included_crypto_sw_scheduler_api_types_h
#define included_crypto_sw_scheduler_api_types_h
#define VL_API_CRYPTO_SW_SCHEDULER_API_VERSION_MAJOR 1
#define VL_API_CRYPTO_SW_SCHEDULER_API_VERSION_MINOR 1
#define VL_API_CRYPTO_SW_SCHEDULER_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_crypto_sw_scheduler_set_worker {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 worker_index;
    bool crypto_enable;
} vl_api_crypto_sw_scheduler_set_worker_t;
#define VL_API_CRYPTO_SW_SCHEDULER_SET_WORKER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_crypto_sw_scheduler_set_worker_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_crypto_sw_scheduler_set_worker_reply_t;
#define VL_API_CRYPTO_SW_SCHEDULER_SET_WORKER_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_CRYPTO_SW_SCHEDULER_SET_WORKER_CRC "crypto_sw_scheduler_set_worker_b4274502"
#define VL_API_CRYPTO_SW_SCHEDULER_SET_WORKER_REPLY_CRC "crypto_sw_scheduler_set_worker_reply_e8d4e804"

#endif
