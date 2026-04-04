#ifndef included_geneve_api_types_h
#define included_geneve_api_types_h
#define VL_API_GENEVE_API_VERSION_MAJOR 2
#define VL_API_GENEVE_API_VERSION_MINOR 1
#define VL_API_GENEVE_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_geneve_add_del_tunnel {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t local_address;
    vl_api_address_t remote_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    u32 decap_next_index;
    u32 vni;
} vl_api_geneve_add_del_tunnel_t;
#define VL_API_GENEVE_ADD_DEL_TUNNEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_geneve_add_del_tunnel_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_geneve_add_del_tunnel_reply_t;
#define VL_API_GENEVE_ADD_DEL_TUNNEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_geneve_add_del_tunnel2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t local_address;
    vl_api_address_t remote_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    u32 decap_next_index;
    u32 vni;
    bool l3_mode;
} vl_api_geneve_add_del_tunnel2_t;
#define VL_API_GENEVE_ADD_DEL_TUNNEL2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_geneve_add_del_tunnel2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
} vl_api_geneve_add_del_tunnel2_reply_t;
#define VL_API_GENEVE_ADD_DEL_TUNNEL2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_geneve_tunnel_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_geneve_tunnel_dump_t;
#define VL_API_GENEVE_TUNNEL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_geneve_tunnel_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t src_address;
    vl_api_address_t dst_address;
    vl_api_interface_index_t mcast_sw_if_index;
    u32 encap_vrf_id;
    u32 decap_next_index;
    u32 vni;
} vl_api_geneve_tunnel_details_t;
#define VL_API_GENEVE_TUNNEL_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_geneve_bypass {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool is_ipv6;
    bool enable;
} vl_api_sw_interface_set_geneve_bypass_t;
#define VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_geneve_bypass_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_set_geneve_bypass_reply_t;
#define VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_GENEVE_ADD_DEL_TUNNEL_CRC "geneve_add_del_tunnel_99445831"
#define VL_API_GENEVE_ADD_DEL_TUNNEL_REPLY_CRC "geneve_add_del_tunnel_reply_5383d31f"
#define VL_API_GENEVE_ADD_DEL_TUNNEL2_CRC "geneve_add_del_tunnel2_8c2a9999"
#define VL_API_GENEVE_ADD_DEL_TUNNEL2_REPLY_CRC "geneve_add_del_tunnel2_reply_5383d31f"
#define VL_API_GENEVE_TUNNEL_DUMP_CRC "geneve_tunnel_dump_f9e6675e"
#define VL_API_GENEVE_TUNNEL_DETAILS_CRC "geneve_tunnel_details_6b16eb24"
#define VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_CRC "sw_interface_set_geneve_bypass_65247409"
#define VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY_CRC "sw_interface_set_geneve_bypass_reply_e8d4e804"

#endif
