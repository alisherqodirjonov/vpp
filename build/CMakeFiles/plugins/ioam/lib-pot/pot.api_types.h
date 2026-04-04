#ifndef included_pot_api_types_h
#define included_pot_api_types_h
#define VL_API_POT_API_VERSION_MAJOR 1
#define VL_API_POT_API_VERSION_MINOR 0
#define VL_API_POT_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_pot_profile_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 id;
    u8 validator;
    u64 secret_key;
    u64 secret_share;
    u64 prime;
    u8 max_bits;
    u64 lpc;
    u64 polynomial_public;
    vl_api_string_t list_name;
} vl_api_pot_profile_add_t;
#define VL_API_POT_PROFILE_ADD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pot_profile_add_reply_t;
#define VL_API_POT_PROFILE_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_activate {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 id;
    vl_api_string_t list_name;
} vl_api_pot_profile_activate_t;
#define VL_API_POT_PROFILE_ACTIVATE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_activate_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pot_profile_activate_reply_t;
#define VL_API_POT_PROFILE_ACTIVATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_string_t list_name;
} vl_api_pot_profile_del_t;
#define VL_API_POT_PROFILE_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pot_profile_del_reply_t;
#define VL_API_POT_PROFILE_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_show_config_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 id;
} vl_api_pot_profile_show_config_dump_t;
#define VL_API_POT_PROFILE_SHOW_CONFIG_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pot_profile_show_config_details {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 id;
    u8 validator;
    u64 secret_key;
    u64 secret_share;
    u64 prime;
    u64 bit_mask;
    u64 lpc;
    u64 polynomial_public;
} vl_api_pot_profile_show_config_details_t;
#define VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_POT_PROFILE_ADD_CRC "pot_profile_add_ad5da3a3"
#define VL_API_POT_PROFILE_ADD_REPLY_CRC "pot_profile_add_reply_e8d4e804"
#define VL_API_POT_PROFILE_ACTIVATE_CRC "pot_profile_activate_0770af98"
#define VL_API_POT_PROFILE_ACTIVATE_REPLY_CRC "pot_profile_activate_reply_e8d4e804"
#define VL_API_POT_PROFILE_DEL_CRC "pot_profile_del_cd63f53b"
#define VL_API_POT_PROFILE_DEL_REPLY_CRC "pot_profile_del_reply_e8d4e804"
#define VL_API_POT_PROFILE_SHOW_CONFIG_DUMP_CRC "pot_profile_show_config_dump_005b7d59"
#define VL_API_POT_PROFILE_SHOW_CONFIG_DETAILS_CRC "pot_profile_show_config_details_b7ce0618"

#endif
