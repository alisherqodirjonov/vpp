#ifndef included_mpls_api_types_h
#define included_mpls_api_types_h
#define VL_API_MPLS_API_VERSION_MAJOR 1
#define VL_API_MPLS_API_VERSION_MINOR 1
#define VL_API_MPLS_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/fib/fib_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_mpls_tunnel {
    vl_api_interface_index_t mt_sw_if_index;
    u32 mt_tunnel_index;
    bool mt_l2_only;
    bool mt_is_multicast;
    u8 mt_tag[64];
    u8 mt_n_paths;
    vl_api_fib_path_t mt_paths[0];
} vl_api_mpls_tunnel_t;
#define VL_API_MPLS_TUNNEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mpls_table {
    u32 mt_table_id;
    u8 mt_name[64];
} vl_api_mpls_table_t;
#define VL_API_MPLS_TABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_route {
    u32 mr_table_id;
    u32 mr_label;
    u8 mr_eos;
    u8 mr_eos_proto;
    bool mr_is_multicast;
    u8 mr_n_paths;
    vl_api_fib_path_t mr_paths[0];
} vl_api_mpls_route_t;
#define VL_API_MPLS_ROUTE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mpls_ip_bind_unbind {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 mb_mpls_table_id;
    u32 mb_label;
    u32 mb_ip_table_id;
    bool mb_is_bind;
    vl_api_prefix_t mb_prefix;
} vl_api_mpls_ip_bind_unbind_t;
#define VL_API_MPLS_IP_BIND_UNBIND_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_ip_bind_unbind_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_mpls_ip_bind_unbind_reply_t;
#define VL_API_MPLS_IP_BIND_UNBIND_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_tunnel_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool mt_is_add;
    vl_api_mpls_tunnel_t mt_tunnel;
} vl_api_mpls_tunnel_add_del_t;
#define VL_API_MPLS_TUNNEL_ADD_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mpls_tunnel_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
    u32 tunnel_index;
} vl_api_mpls_tunnel_add_del_reply_t;
#define VL_API_MPLS_TUNNEL_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_tunnel_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_mpls_tunnel_dump_t;
#define VL_API_MPLS_TUNNEL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_tunnel_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_mpls_tunnel_t mt_tunnel;
} vl_api_mpls_tunnel_details_t;
#define VL_API_MPLS_TUNNEL_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mpls_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_mpls_interface_dump_t;
#define VL_API_MPLS_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_mpls_interface_details_t;
#define VL_API_MPLS_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_table_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool mt_is_add;
    vl_api_mpls_table_t mt_table;
} vl_api_mpls_table_add_del_t;
#define VL_API_MPLS_TABLE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_table_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_mpls_table_add_del_reply_t;
#define VL_API_MPLS_TABLE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_table_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_mpls_table_dump_t;
#define VL_API_MPLS_TABLE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_table_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_mpls_table_t mt_table;
} vl_api_mpls_table_details_t;
#define VL_API_MPLS_TABLE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_route_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool mr_is_add;
    bool mr_is_multipath;
    vl_api_mpls_route_t mr_route;
} vl_api_mpls_route_add_del_t;
#define VL_API_MPLS_ROUTE_ADD_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_mpls_route_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 stats_index;
} vl_api_mpls_route_add_del_reply_t;
#define VL_API_MPLS_ROUTE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_route_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_mpls_table_t table;
} vl_api_mpls_route_dump_t;
#define VL_API_MPLS_ROUTE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mpls_route_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_mpls_route_t mr_route;
} vl_api_mpls_route_details_t;
#define VL_API_MPLS_ROUTE_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_mpls_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enable;
} vl_api_sw_interface_set_mpls_enable_t;
#define VL_API_SW_INTERFACE_SET_MPLS_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sw_interface_set_mpls_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sw_interface_set_mpls_enable_reply_t;
#define VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_MPLS_IP_BIND_UNBIND_CRC "mpls_ip_bind_unbind_c7533b32"
#define VL_API_MPLS_IP_BIND_UNBIND_REPLY_CRC "mpls_ip_bind_unbind_reply_e8d4e804"
#define VL_API_MPLS_TUNNEL_ADD_DEL_CRC "mpls_tunnel_add_del_44350ac1"
#define VL_API_MPLS_TUNNEL_ADD_DEL_REPLY_CRC "mpls_tunnel_add_del_reply_afb01472"
#define VL_API_MPLS_TUNNEL_DUMP_CRC "mpls_tunnel_dump_f9e6675e"
#define VL_API_MPLS_TUNNEL_DETAILS_CRC "mpls_tunnel_details_57118ae3"
#define VL_API_MPLS_INTERFACE_DUMP_CRC "mpls_interface_dump_f9e6675e"
#define VL_API_MPLS_INTERFACE_DETAILS_CRC "mpls_interface_details_0b45011c"
#define VL_API_MPLS_TABLE_ADD_DEL_CRC "mpls_table_add_del_57817512"
#define VL_API_MPLS_TABLE_ADD_DEL_REPLY_CRC "mpls_table_add_del_reply_e8d4e804"
#define VL_API_MPLS_TABLE_DUMP_CRC "mpls_table_dump_51077d14"
#define VL_API_MPLS_TABLE_DETAILS_CRC "mpls_table_details_f03ecdc8"
#define VL_API_MPLS_ROUTE_ADD_DEL_CRC "mpls_route_add_del_8e1d1e07"
#define VL_API_MPLS_ROUTE_ADD_DEL_REPLY_CRC "mpls_route_add_del_reply_1992deab"
#define VL_API_MPLS_ROUTE_DUMP_CRC "mpls_route_dump_935fdefa"
#define VL_API_MPLS_ROUTE_DETAILS_CRC "mpls_route_details_9b5043dc"
#define VL_API_SW_INTERFACE_SET_MPLS_ENABLE_CRC "sw_interface_set_mpls_enable_ae6cfcfb"
#define VL_API_SW_INTERFACE_SET_MPLS_ENABLE_REPLY_CRC "sw_interface_set_mpls_enable_reply_e8d4e804"

#endif
