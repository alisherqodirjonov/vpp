#ifndef included_nat64_api_types_h
#define included_nat64_api_types_h
#define VL_API_NAT64_API_VERSION_MAJOR 1
#define VL_API_NAT64_API_VERSION_MINOR 0
#define VL_API_NAT64_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
#include <nat/lib/nat_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_nat64_plugin_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bib_buckets;
    u32 bib_memory_size;
    u32 st_buckets;
    u32 st_memory_size;
    bool enable;
} vl_api_nat64_plugin_enable_disable_t;
#define VL_API_NAT64_PLUGIN_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_plugin_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_plugin_enable_disable_reply_t;
#define VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_set_timeouts {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 udp;
    u32 tcp_established;
    u32 tcp_transitory;
    u32 icmp;
} vl_api_nat64_set_timeouts_t;
#define VL_API_NAT64_SET_TIMEOUTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_set_timeouts_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_set_timeouts_reply_t;
#define VL_API_NAT64_SET_TIMEOUTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_get_timeouts {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat64_get_timeouts_t;
#define VL_API_NAT64_GET_TIMEOUTS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_get_timeouts_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 udp;
    u32 tcp_established;
    u32 tcp_transitory;
    u32 icmp;
} vl_api_nat64_get_timeouts_reply_t;
#define VL_API_NAT64_GET_TIMEOUTS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_pool_addr_range {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t start_addr;
    vl_api_ip4_address_t end_addr;
    u32 vrf_id;
    bool is_add;
} vl_api_nat64_add_del_pool_addr_range_t;
#define VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_pool_addr_range_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_add_del_pool_addr_range_reply_t;
#define VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_pool_addr_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat64_pool_addr_dump_t;
#define VL_API_NAT64_POOL_ADDR_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_pool_addr_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip4_address_t address;
    u32 vrf_id;
} vl_api_nat64_pool_addr_details_t;
#define VL_API_NAT64_POOL_ADDR_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_nat_config_flags_t flags;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat64_add_del_interface_t;
#define VL_API_NAT64_ADD_DEL_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_add_del_interface_reply_t;
#define VL_API_NAT64_ADD_DEL_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_interface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat64_interface_dump_t;
#define VL_API_NAT64_INTERFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_interface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_nat_config_flags_t flags;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat64_interface_details_t;
#define VL_API_NAT64_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_static_bib {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip6_address_t i_addr;
    vl_api_ip4_address_t o_addr;
    u16 i_port;
    u16 o_port;
    u32 vrf_id;
    u8 proto;
    bool is_add;
} vl_api_nat64_add_del_static_bib_t;
#define VL_API_NAT64_ADD_DEL_STATIC_BIB_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_static_bib_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_add_del_static_bib_reply_t;
#define VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_bib_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 proto;
} vl_api_nat64_bib_dump_t;
#define VL_API_NAT64_BIB_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_bib_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip6_address_t i_addr;
    vl_api_ip4_address_t o_addr;
    u16 i_port;
    u16 o_port;
    u32 vrf_id;
    u8 proto;
    vl_api_nat_config_flags_t flags;
    u32 ses_num;
} vl_api_nat64_bib_details_t;
#define VL_API_NAT64_BIB_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_st_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 proto;
} vl_api_nat64_st_dump_t;
#define VL_API_NAT64_ST_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_st_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip6_address_t il_addr;
    vl_api_ip4_address_t ol_addr;
    u16 il_port;
    u16 ol_port;
    vl_api_ip6_address_t ir_addr;
    vl_api_ip4_address_t or_addr;
    u16 r_port;
    u32 vrf_id;
    u8 proto;
} vl_api_nat64_st_details_t;
#define VL_API_NAT64_ST_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_prefix {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip6_prefix_t prefix;
    u32 vrf_id;
    bool is_add;
} vl_api_nat64_add_del_prefix_t;
#define VL_API_NAT64_ADD_DEL_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_prefix_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_add_del_prefix_reply_t;
#define VL_API_NAT64_ADD_DEL_PREFIX_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_prefix_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_nat64_prefix_dump_t;
#define VL_API_NAT64_PREFIX_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_prefix_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_ip6_prefix_t prefix;
    u32 vrf_id;
} vl_api_nat64_prefix_details_t;
#define VL_API_NAT64_PREFIX_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_interface_addr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
} vl_api_nat64_add_del_interface_addr_t;
#define VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_nat64_add_del_interface_addr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_nat64_add_del_interface_addr_reply_t;
#define VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_NAT64_PLUGIN_ENABLE_DISABLE_CRC "nat64_plugin_enable_disable_45948b90"
#define VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY_CRC "nat64_plugin_enable_disable_reply_e8d4e804"
#define VL_API_NAT64_SET_TIMEOUTS_CRC "nat64_set_timeouts_d4746b16"
#define VL_API_NAT64_SET_TIMEOUTS_REPLY_CRC "nat64_set_timeouts_reply_e8d4e804"
#define VL_API_NAT64_GET_TIMEOUTS_CRC "nat64_get_timeouts_51077d14"
#define VL_API_NAT64_GET_TIMEOUTS_REPLY_CRC "nat64_get_timeouts_reply_3c4df4e1"
#define VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_CRC "nat64_add_del_pool_addr_range_a3b944e3"
#define VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY_CRC "nat64_add_del_pool_addr_range_reply_e8d4e804"
#define VL_API_NAT64_POOL_ADDR_DUMP_CRC "nat64_pool_addr_dump_51077d14"
#define VL_API_NAT64_POOL_ADDR_DETAILS_CRC "nat64_pool_addr_details_9bb99cdb"
#define VL_API_NAT64_ADD_DEL_INTERFACE_CRC "nat64_add_del_interface_f3699b83"
#define VL_API_NAT64_ADD_DEL_INTERFACE_REPLY_CRC "nat64_add_del_interface_reply_e8d4e804"
#define VL_API_NAT64_INTERFACE_DUMP_CRC "nat64_interface_dump_51077d14"
#define VL_API_NAT64_INTERFACE_DETAILS_CRC "nat64_interface_details_5d286289"
#define VL_API_NAT64_ADD_DEL_STATIC_BIB_CRC "nat64_add_del_static_bib_1c404de5"
#define VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY_CRC "nat64_add_del_static_bib_reply_e8d4e804"
#define VL_API_NAT64_BIB_DUMP_CRC "nat64_bib_dump_cfcb6b75"
#define VL_API_NAT64_BIB_DETAILS_CRC "nat64_bib_details_43bc3ddf"
#define VL_API_NAT64_ST_DUMP_CRC "nat64_st_dump_cfcb6b75"
#define VL_API_NAT64_ST_DETAILS_CRC "nat64_st_details_dd3361ed"
#define VL_API_NAT64_ADD_DEL_PREFIX_CRC "nat64_add_del_prefix_727b2f4c"
#define VL_API_NAT64_ADD_DEL_PREFIX_REPLY_CRC "nat64_add_del_prefix_reply_e8d4e804"
#define VL_API_NAT64_PREFIX_DUMP_CRC "nat64_prefix_dump_51077d14"
#define VL_API_NAT64_PREFIX_DETAILS_CRC "nat64_prefix_details_20568de3"
#define VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_CRC "nat64_add_del_interface_addr_47d6e753"
#define VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY_CRC "nat64_add_del_interface_addr_reply_e8d4e804"

#endif
