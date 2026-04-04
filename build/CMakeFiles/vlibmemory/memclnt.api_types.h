#ifndef included_memclnt_api_types_h
#define included_memclnt_api_types_h
#define VL_API_MEMCLNT_API_VERSION_MAJOR 2
#define VL_API_MEMCLNT_API_VERSION_MINOR 1
#define VL_API_MEMCLNT_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_module_version {
    u32 major;
    u32 minor;
    u32 patch;
    u8 name[64];
} vl_api_module_version_t;
#define VL_API_MODULE_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_message_table_entry {
    u16 index;
    u8 name[64];
} vl_api_message_table_entry_t;
#define VL_API_MESSAGE_TABLE_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_create {
    u16 _vl_msg_id;
    u32 context;
    i32 ctx_quota;
    u64 input_queue;
    u8 name[64];
    u32 api_versions[8];
} vl_api_memclnt_create_t;
#define VL_API_MEMCLNT_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 response;
    u64 handle;
    u32 index;
    u64 message_table;
} vl_api_memclnt_create_reply_t;
#define VL_API_MEMCLNT_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_delete {
    u16 _vl_msg_id;
    u32 index;
    u64 handle;
    bool do_cleanup;
} vl_api_memclnt_delete_t;
#define VL_API_MEMCLNT_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_delete_reply {
    u16 _vl_msg_id;
    i32 response;
    u64 handle;
} vl_api_memclnt_delete_reply_t;
#define VL_API_MEMCLNT_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_rx_thread_exit {
    u16 _vl_msg_id;
    u8 dummy;
} vl_api_rx_thread_exit_t;
#define VL_API_RX_THREAD_EXIT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_rx_thread_suspend {
    u16 _vl_msg_id;
    u8 dummy;
} vl_api_memclnt_rx_thread_suspend_t;
#define VL_API_MEMCLNT_RX_THREAD_SUSPEND_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_read_timeout {
    u16 _vl_msg_id;
    u8 dummy;
} vl_api_memclnt_read_timeout_t;
#define VL_API_MEMCLNT_READ_TIMEOUT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_rpc_call {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u64 function;
    u8 multicast;
    u8 need_barrier_sync;
    u8 send_reply;
    u32 data_len;
    u8 data[0];
} vl_api_rpc_call_t;
#define VL_API_RPC_CALL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_rpc_call_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_rpc_call_reply_t;
#define VL_API_RPC_CALL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_get_first_msg_id {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 name[64];
} vl_api_get_first_msg_id_t;
#define VL_API_GET_FIRST_MSG_ID_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_get_first_msg_id_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u16 first_msg_id;
} vl_api_get_first_msg_id_reply_t;
#define VL_API_GET_FIRST_MSG_ID_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_api_versions {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_api_versions_t;
#define VL_API_API_VERSIONS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_api_versions_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_module_version_t api_versions[0];
} vl_api_api_versions_reply_t;
#define VL_API_API_VERSIONS_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_trace_plugin_msg_ids {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 plugin_name[128];
    u16 first_msg_id;
    u16 last_msg_id;
} vl_api_trace_plugin_msg_ids_t;
#define VL_API_TRACE_PLUGIN_MSG_IDS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sockclnt_create {
    u16 _vl_msg_id;
    u32 context;
    u8 name[64];
} vl_api_sockclnt_create_t;
#define VL_API_SOCKCLNT_CREATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sockclnt_create_reply {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    i32 response;
    u32 index;
    u16 count;
    vl_api_message_table_entry_t message_table[0];
} vl_api_sockclnt_create_reply_t;
#define VL_API_SOCKCLNT_CREATE_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_sockclnt_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 index;
} vl_api_sockclnt_delete_t;
#define VL_API_SOCKCLNT_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sockclnt_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 response;
} vl_api_sockclnt_delete_reply_t;
#define VL_API_SOCKCLNT_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sock_init_shm {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 requested_size;
    u8 nitems;
    u64 configs[0];
} vl_api_sock_init_shm_t;
#define VL_API_SOCK_INIT_SHM_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_sock_init_shm_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sock_init_shm_reply_t;
#define VL_API_SOCK_INIT_SHM_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_keepalive {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_memclnt_keepalive_t;
#define VL_API_MEMCLNT_KEEPALIVE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_keepalive_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_memclnt_keepalive_reply_t;
#define VL_API_MEMCLNT_KEEPALIVE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_control_ping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_control_ping_t;
#define VL_API_CONTROL_PING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_control_ping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 client_index;
    u32 vpe_pid;
} vl_api_control_ping_reply_t;
#define VL_API_CONTROL_PING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_create_v2 {
    u16 _vl_msg_id;
    u32 context;
    i32 ctx_quota;
    u64 input_queue;
    u8 name[64];
    u32 api_versions[8];
    bool keepalive;
} vl_api_memclnt_create_v2_t;
#define VL_API_MEMCLNT_CREATE_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_memclnt_create_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 response;
    u64 handle;
    u32 index;
    u64 message_table;
} vl_api_memclnt_create_v2_reply_t;
#define VL_API_MEMCLNT_CREATE_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_get_api_json {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_get_api_json_t;
#define VL_API_GET_API_JSON_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_get_api_json_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_string_t json;
} vl_api_get_api_json_reply_t;
#define VL_API_GET_API_JSON_REPLY_IS_CONSTANT_SIZE (0)

#define VL_API_MEMCLNT_CREATE_CRC "memclnt_create_9c5e1c2f"
#define VL_API_MEMCLNT_CREATE_REPLY_CRC "memclnt_create_reply_42ec4560"
#define VL_API_MEMCLNT_DELETE_CRC "memclnt_delete_7e1c04e3"
#define VL_API_MEMCLNT_DELETE_REPLY_CRC "memclnt_delete_reply_3d3b6312"
#define VL_API_RX_THREAD_EXIT_CRC "rx_thread_exit_c3a3a452"
#define VL_API_MEMCLNT_RX_THREAD_SUSPEND_CRC "memclnt_rx_thread_suspend_c3a3a452"
#define VL_API_MEMCLNT_READ_TIMEOUT_CRC "memclnt_read_timeout_c3a3a452"
#define VL_API_RPC_CALL_CRC "rpc_call_7e8a2c95"
#define VL_API_RPC_CALL_REPLY_CRC "rpc_call_reply_e8d4e804"
#define VL_API_GET_FIRST_MSG_ID_CRC "get_first_msg_id_ebf79a66"
#define VL_API_GET_FIRST_MSG_ID_REPLY_CRC "get_first_msg_id_reply_7d337472"
#define VL_API_API_VERSIONS_CRC "api_versions_51077d14"
#define VL_API_API_VERSIONS_REPLY_CRC "api_versions_reply_5f0d99d6"
#define VL_API_TRACE_PLUGIN_MSG_IDS_CRC "trace_plugin_msg_ids_f476d3ce"
#define VL_API_SOCKCLNT_CREATE_CRC "sockclnt_create_455fb9c4"
#define VL_API_SOCKCLNT_CREATE_REPLY_CRC "sockclnt_create_reply_35166268"
#define VL_API_SOCKCLNT_DELETE_CRC "sockclnt_delete_8ac76db6"
#define VL_API_SOCKCLNT_DELETE_REPLY_CRC "sockclnt_delete_reply_8f38b1ee"
#define VL_API_SOCK_INIT_SHM_CRC "sock_init_shm_51646d92"
#define VL_API_SOCK_INIT_SHM_REPLY_CRC "sock_init_shm_reply_e8d4e804"
#define VL_API_MEMCLNT_KEEPALIVE_CRC "memclnt_keepalive_51077d14"
#define VL_API_MEMCLNT_KEEPALIVE_REPLY_CRC "memclnt_keepalive_reply_e8d4e804"
#define VL_API_CONTROL_PING_CRC "control_ping_51077d14"
#define VL_API_CONTROL_PING_REPLY_CRC "control_ping_reply_f6b0b8ca"
#define VL_API_MEMCLNT_CREATE_V2_CRC "memclnt_create_v2_c4bd4882"
#define VL_API_MEMCLNT_CREATE_V2_REPLY_CRC "memclnt_create_v2_reply_42ec4560"
#define VL_API_GET_API_JSON_CRC "get_api_json_51077d14"
#define VL_API_GET_API_JSON_REPLY_CRC "get_api_json_reply_ea715b59"

#endif
