#ifndef included_ip_session_redirect_api_types_h
#define included_ip_session_redirect_api_types_h
#define VL_API_IP_SESSION_REDIRECT_API_VERSION_MAJOR 0
#define VL_API_IP_SESSION_REDIRECT_API_VERSION_MINOR 3
#define VL_API_IP_SESSION_REDIRECT_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/fib/fib_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_index;
    u8 match_len;
    u8 match[80];
    u32 opaque_index;
    bool is_punt;
    u8 n_paths;
    vl_api_fib_path_t paths[0];
} vl_api_ip_session_redirect_add_t;
#define VL_API_IP_SESSION_REDIRECT_ADD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip_session_redirect_add_reply_t;
#define VL_API_IP_SESSION_REDIRECT_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_add_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_index;
    u32 opaque_index;
    vl_api_fib_path_nh_proto_t proto;
    bool is_punt;
    u8 match_len;
    u8 match[80];
    u8 n_paths;
    vl_api_fib_path_t paths[0];
} vl_api_ip_session_redirect_add_v2_t;
#define VL_API_IP_SESSION_REDIRECT_ADD_V2_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_add_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip_session_redirect_add_v2_reply_t;
#define VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_index;
    u8 match_len;
    u8 match[0];
} vl_api_ip_session_redirect_del_t;
#define VL_API_IP_SESSION_REDIRECT_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip_session_redirect_del_reply_t;
#define VL_API_IP_SESSION_REDIRECT_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_index;
} vl_api_ip_session_redirect_dump_t;
#define VL_API_IP_SESSION_REDIRECT_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip_session_redirect_details {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_index;
    u32 opaque_index;
    bool is_punt;
    bool is_ip6;
    u32 match_length;
    u8 match[80];
    u8 n_paths;
    vl_api_fib_path_t paths[0];
} vl_api_ip_session_redirect_details_t;
#define VL_API_IP_SESSION_REDIRECT_DETAILS_IS_CONSTANT_SIZE (0)

#define VL_API_IP_SESSION_REDIRECT_ADD_CRC "ip_session_redirect_add_2f78ffda"
#define VL_API_IP_SESSION_REDIRECT_ADD_REPLY_CRC "ip_session_redirect_add_reply_e8d4e804"
#define VL_API_IP_SESSION_REDIRECT_ADD_V2_CRC "ip_session_redirect_add_v2_0765f51f"
#define VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY_CRC "ip_session_redirect_add_v2_reply_e8d4e804"
#define VL_API_IP_SESSION_REDIRECT_DEL_CRC "ip_session_redirect_del_fb643388"
#define VL_API_IP_SESSION_REDIRECT_DEL_REPLY_CRC "ip_session_redirect_del_reply_e8d4e804"
#define VL_API_IP_SESSION_REDIRECT_DUMP_CRC "ip_session_redirect_dump_33554253"
#define VL_API_IP_SESSION_REDIRECT_DETAILS_CRC "ip_session_redirect_details_4487a233"

#endif
