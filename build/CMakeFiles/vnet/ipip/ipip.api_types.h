#ifndef included_ipip_api_types_h
#define included_ipip_api_types_h
#define VL_API_IPIP_API_VERSION_MAJOR 2
#define VL_API_IPIP_API_VERSION_MINOR 0
#define VL_API_IPIP_API_VERSION_PATCH 2
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/tunnel/tunnel_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_ipip_tunnel {
    u32 instance;
    vl_api_address_t src;
    vl_api_address_t dst;
    vl_api_interface_index_t sw_if_index;
    u32 table_id;
    vl_api_tunnel_encap_decap_flags_t flags;
    vl_api_tunnel_mode_t mode;
    vl_api_ip_dscp_t dscp;
} vl_api_ipip_tunnel_t;
#define VL_API_IPIP_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_add_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ipip_tunnel_t tunnel;
} vl_api_ipip_add_tunnel_t;
#define VL_API_IPIP_ADD_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_add_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipip_add_tunnel_reply_t;
#define VL_API_IPIP_ADD_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_del_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipip_del_tunnel_t;
#define VL_API_IPIP_DEL_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_del_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipip_del_tunnel_reply_t;
#define VL_API_IPIP_DEL_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_6rd_add_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 ip6_table_id;
    u32 ip4_table_id;
    vl_api_ip6_prefix_t ip6_prefix;
    vl_api_ip4_prefix_t ip4_prefix;
    vl_api_ip4_address_t ip4_src;
    bool security_check;
    u8 tc_tos;
} vl_api_ipip_6rd_add_tunnel_t;
#define VL_API_IPIP_6RD_ADD_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_6rd_add_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipip_6rd_add_tunnel_reply_t;
#define VL_API_IPIP_6RD_ADD_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_6rd_del_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipip_6rd_del_tunnel_t;
#define VL_API_IPIP_6RD_DEL_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_6rd_del_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ipip_6rd_del_tunnel_reply_t;
#define VL_API_IPIP_6RD_DEL_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_tunnel_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_ipip_tunnel_dump_t;
#define VL_API_IPIP_TUNNEL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipip_tunnel_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ipip_tunnel_t tunnel;
} vl_api_ipip_tunnel_details_t;
#define VL_API_IPIP_TUNNEL_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_IPIP_ADD_TUNNEL_CRC "ipip_add_tunnel_2ac399f5"
#define VL_API_IPIP_ADD_TUNNEL_REPLY_CRC "ipip_add_tunnel_reply_5383d31f"
#define VL_API_IPIP_DEL_TUNNEL_CRC "ipip_del_tunnel_f9e6675e"
#define VL_API_IPIP_DEL_TUNNEL_REPLY_CRC "ipip_del_tunnel_reply_e8d4e804"
#define VL_API_IPIP_6RD_ADD_TUNNEL_CRC "ipip_6rd_add_tunnel_b9ec1863"
#define VL_API_IPIP_6RD_ADD_TUNNEL_REPLY_CRC "ipip_6rd_add_tunnel_reply_5383d31f"
#define VL_API_IPIP_6RD_DEL_TUNNEL_CRC "ipip_6rd_del_tunnel_f9e6675e"
#define VL_API_IPIP_6RD_DEL_TUNNEL_REPLY_CRC "ipip_6rd_del_tunnel_reply_e8d4e804"
#define VL_API_IPIP_TUNNEL_DUMP_CRC "ipip_tunnel_dump_f9e6675e"
#define VL_API_IPIP_TUNNEL_DETAILS_CRC "ipip_tunnel_details_d31cb34e"

#endif
