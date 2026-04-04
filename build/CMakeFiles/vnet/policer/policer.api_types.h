#ifndef included_policer_api_types_h
#define included_policer_api_types_h
#define VL_API_POLICER_API_VERSION_MAJOR 3
#define VL_API_POLICER_API_VERSION_MINOR 0
#define VL_API_POLICER_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/policer/policer_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_policer_bind {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 name[64];
    u32 worker_index;
    bool bind_enable;
} vl_api_policer_bind_t;
#define VL_API_POLICER_BIND_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_bind_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_bind_reply_t;
#define VL_API_POLICER_BIND_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_bind_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
    u32 worker_index;
    bool bind_enable;
} vl_api_policer_bind_v2_t;
#define VL_API_POLICER_BIND_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_bind_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_bind_v2_reply_t;
#define VL_API_POLICER_BIND_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_input {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 name[64];
    vl_api_interface_index_t sw_if_index;
    bool apply;
} vl_api_policer_input_t;
#define VL_API_POLICER_INPUT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_input_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_input_reply_t;
#define VL_API_POLICER_INPUT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_input_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
    vl_api_interface_index_t sw_if_index;
    bool apply;
} vl_api_policer_input_v2_t;
#define VL_API_POLICER_INPUT_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_input_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_input_v2_reply_t;
#define VL_API_POLICER_INPUT_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_output {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 name[64];
    vl_api_interface_index_t sw_if_index;
    bool apply;
} vl_api_policer_output_t;
#define VL_API_POLICER_OUTPUT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_output_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_output_reply_t;
#define VL_API_POLICER_OUTPUT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_output_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
    vl_api_interface_index_t sw_if_index;
    bool apply;
} vl_api_policer_output_v2_t;
#define VL_API_POLICER_OUTPUT_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_output_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_output_v2_reply_t;
#define VL_API_POLICER_OUTPUT_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 name[64];
    u32 cir;
    u32 eir;
    u64 cb;
    u64 eb;
    vl_api_sse2_qos_rate_type_t rate_type;
    vl_api_sse2_qos_round_type_t round_type;
    vl_api_sse2_qos_policer_type_t type;
    bool color_aware;
    vl_api_sse2_qos_action_t conform_action;
    vl_api_sse2_qos_action_t exceed_action;
    vl_api_sse2_qos_action_t violate_action;
} vl_api_policer_add_del_t;
#define VL_API_POLICER_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 name[64];
    vl_api_policer_config_t infos;
} vl_api_policer_add_t;
#define VL_API_POLICER_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
} vl_api_policer_del_t;
#define VL_API_POLICER_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_del_reply_t;
#define VL_API_POLICER_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
    vl_api_policer_config_t infos;
} vl_api_policer_update_t;
#define VL_API_POLICER_UPDATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_update_reply_t;
#define VL_API_POLICER_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_reset {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
} vl_api_policer_reset_t;
#define VL_API_POLICER_RESET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_reset_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_reset_reply_t;
#define VL_API_POLICER_RESET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 policer_index;
} vl_api_policer_add_del_reply_t;
#define VL_API_POLICER_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 policer_index;
} vl_api_policer_add_reply_t;
#define VL_API_POLICER_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool match_name_valid;
    u8 match_name[64];
} vl_api_policer_dump_t;
#define VL_API_POLICER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_dump_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 policer_index;
} vl_api_policer_dump_v2_t;
#define VL_API_POLICER_DUMP_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_details {
    u16 _vl_msg_id;
    u32 context;
    u8 name[64];
    u32 cir;
    u32 eir;
    u64 cb;
    u64 eb;
    vl_api_sse2_qos_rate_type_t rate_type;
    vl_api_sse2_qos_round_type_t round_type;
    vl_api_sse2_qos_policer_type_t type;
    vl_api_sse2_qos_action_t conform_action;
    vl_api_sse2_qos_action_t exceed_action;
    vl_api_sse2_qos_action_t violate_action;
    bool single_rate;
    bool color_aware;
    u32 scale;
    u32 cir_tokens_per_period;
    u32 pir_tokens_per_period;
    u32 current_limit;
    u32 current_bucket;
    u32 extended_limit;
    u32 extended_bucket;
    u64 last_update_time;
} vl_api_policer_details_t;
#define VL_API_POLICER_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_POLICER_BIND_CRC "policer_bind_dcf516f9"
#define VL_API_POLICER_BIND_REPLY_CRC "policer_bind_reply_e8d4e804"
#define VL_API_POLICER_BIND_V2_CRC "policer_bind_v2_f87bd3c0"
#define VL_API_POLICER_BIND_V2_REPLY_CRC "policer_bind_v2_reply_e8d4e804"
#define VL_API_POLICER_INPUT_CRC "policer_input_233f0ef5"
#define VL_API_POLICER_INPUT_REPLY_CRC "policer_input_reply_e8d4e804"
#define VL_API_POLICER_INPUT_V2_CRC "policer_input_v2_8388eb84"
#define VL_API_POLICER_INPUT_V2_REPLY_CRC "policer_input_v2_reply_e8d4e804"
#define VL_API_POLICER_OUTPUT_CRC "policer_output_233f0ef5"
#define VL_API_POLICER_OUTPUT_REPLY_CRC "policer_output_reply_e8d4e804"
#define VL_API_POLICER_OUTPUT_V2_CRC "policer_output_v2_8388eb84"
#define VL_API_POLICER_OUTPUT_V2_REPLY_CRC "policer_output_v2_reply_e8d4e804"
#define VL_API_POLICER_ADD_DEL_CRC "policer_add_del_2b31dd38"
#define VL_API_POLICER_ADD_CRC "policer_add_4d949e35"
#define VL_API_POLICER_DEL_CRC "policer_del_7ff7912e"
#define VL_API_POLICER_DEL_REPLY_CRC "policer_del_reply_e8d4e804"
#define VL_API_POLICER_UPDATE_CRC "policer_update_fd039ef0"
#define VL_API_POLICER_UPDATE_REPLY_CRC "policer_update_reply_e8d4e804"
#define VL_API_POLICER_RESET_CRC "policer_reset_7ff7912e"
#define VL_API_POLICER_RESET_REPLY_CRC "policer_reset_reply_e8d4e804"
#define VL_API_POLICER_ADD_DEL_REPLY_CRC "policer_add_del_reply_a177cef2"
#define VL_API_POLICER_ADD_REPLY_CRC "policer_add_reply_a177cef2"
#define VL_API_POLICER_DUMP_CRC "policer_dump_35f1ae0f"
#define VL_API_POLICER_DUMP_V2_CRC "policer_dump_v2_7ff7912e"
#define VL_API_POLICER_DETAILS_CRC "policer_details_72d0e248"

#endif
