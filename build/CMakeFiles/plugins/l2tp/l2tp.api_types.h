#ifndef included_l2tp_api_types_h
#define included_l2tp_api_types_h
#define VL_API_L2TP_API_VERSION_MAJOR 2
#define VL_API_L2TP_API_VERSION_MINOR 0
#define VL_API_L2TP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum __attribute__((packed)) {
    L2T_LOOKUP_KEY_API_SRC_ADDR = 0,
    L2T_LOOKUP_KEY_API_DST_ADDR = 1,
    L2T_LOOKUP_KEY_API_SESSION_ID = 2,
} vl_api_l2t_lookup_key_t;
STATIC_ASSERT(sizeof(vl_api_l2t_lookup_key_t) == sizeof(u8), "size of API enum l2t_lookup_key is wrong");
typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_create_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t client_address;
    vl_api_address_t our_address;
    u32 local_session_id;
    u32 remote_session_id;
    u64 local_cookie;
    u64 remote_cookie;
    bool l2_sublayer_present;
    u32 encap_vrf_id;
} vl_api_l2tpv3_create_tunnel_t;
#define VL_API_L2TPV3_CREATE_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_create_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_l2tpv3_create_tunnel_reply_t;
#define VL_API_L2TPV3_CREATE_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_set_tunnel_cookies {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u64 new_local_cookie;
    u64 new_remote_cookie;
} vl_api_l2tpv3_set_tunnel_cookies_t;
#define VL_API_L2TPV3_SET_TUNNEL_COOKIES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_set_tunnel_cookies_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_l2tpv3_set_tunnel_cookies_reply_t;
#define VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_if_l2tpv3_tunnel_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 interface_name[64];
    vl_api_address_t client_address;
    vl_api_address_t our_address;
    u32 local_session_id;
    u32 remote_session_id;
    u64 local_cookie[2];
    u64 remote_cookie;
    bool l2_sublayer_present;
} vl_api_sw_if_l2tpv3_tunnel_details_t;
#define VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_if_l2tpv3_tunnel_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sw_if_l2tpv3_tunnel_dump_t;
#define VL_API_SW_IF_L2TPV3_TUNNEL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_interface_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable_disable;
    vl_api_interface_index_t sw_if_index;
} vl_api_l2tpv3_interface_enable_disable_t;
#define VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_interface_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_l2tpv3_interface_enable_disable_reply_t;
#define VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_set_lookup_key {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_l2t_lookup_key_t key;
} vl_api_l2tpv3_set_lookup_key_t;
#define VL_API_L2TPV3_SET_LOOKUP_KEY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_l2tpv3_set_lookup_key_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_l2tpv3_set_lookup_key_reply_t;
#define VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_L2TPV3_CREATE_TUNNEL_CRC "l2tpv3_create_tunnel_15bed0c2"
#define VL_API_L2TPV3_CREATE_TUNNEL_REPLY_CRC "l2tpv3_create_tunnel_reply_5383d31f"
#define VL_API_L2TPV3_SET_TUNNEL_COOKIES_CRC "l2tpv3_set_tunnel_cookies_b3f4faf7"
#define VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY_CRC "l2tpv3_set_tunnel_cookies_reply_e8d4e804"
#define VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS_CRC "sw_if_l2tpv3_tunnel_details_50b88993"
#define VL_API_SW_IF_L2TPV3_TUNNEL_DUMP_CRC "sw_if_l2tpv3_tunnel_dump_51077d14"
#define VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_CRC "l2tpv3_interface_enable_disable_3865946c"
#define VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY_CRC "l2tpv3_interface_enable_disable_reply_e8d4e804"
#define VL_API_L2TPV3_SET_LOOKUP_KEY_CRC "l2tpv3_set_lookup_key_c9892c86"
#define VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY_CRC "l2tpv3_set_lookup_key_reply_e8d4e804"

#endif
