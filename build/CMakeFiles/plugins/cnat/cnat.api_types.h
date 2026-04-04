#ifndef included_cnat_api_types_h
#define included_cnat_api_types_h
#define VL_API_CNAT_API_VERSION_MAJOR 0
#define VL_API_CNAT_API_VERSION_MINOR 3
#define VL_API_CNAT_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/fib/fib_types.api_types.h>
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip.api_types.h>
typedef enum __attribute__((packed)) {
    CNAT_TRANSLATION_ALLOC_PORT = 1,
    CNAT_TRANSLATION_NO_RETURN_SESSION = 4,
} vl_api_cnat_translation_flags_t;
STATIC_ASSERT(sizeof(vl_api_cnat_translation_flags_t) == sizeof(u8), "size of API enum cnat_translation_flags is wrong");
typedef enum __attribute__((packed)) {
    CNAT_EPT_NO_NAT = 1,
} vl_api_cnat_endpoint_tuple_flags_t;
STATIC_ASSERT(sizeof(vl_api_cnat_endpoint_tuple_flags_t) == sizeof(u8), "size of API enum cnat_endpoint_tuple_flags is wrong");
typedef enum __attribute__((packed)) {
    CNAT_LB_TYPE_DEFAULT = 0,
    CNAT_LB_TYPE_MAGLEV = 1,
} vl_api_cnat_lb_type_t;
STATIC_ASSERT(sizeof(vl_api_cnat_lb_type_t) == sizeof(u8), "size of API enum cnat_lb_type is wrong");
typedef struct __attribute__ ((packed)) _vl_api_cnat_endpoint {
    vl_api_address_t addr;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_family_t if_af;
    u16 port;
} vl_api_cnat_endpoint_t;
#define VL_API_CNAT_ENDPOINT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_endpoint_tuple {
    vl_api_cnat_endpoint_t dst_ep;
    vl_api_cnat_endpoint_t src_ep;
    u8 flags;
} vl_api_cnat_endpoint_tuple_t;
#define VL_API_CNAT_ENDPOINT_TUPLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_translation {
    vl_api_cnat_endpoint_t vip;
    u32 id;
    vl_api_ip_proto_t ip_proto;
    u8 is_real_ip;
    u8 flags;
    vl_api_cnat_lb_type_t lb_type;
    u32 n_paths;
    vl_api_ip_flow_hash_config_v2_t flow_hash_config;
    vl_api_cnat_endpoint_tuple_t paths[0];
} vl_api_cnat_translation_t;
#define VL_API_CNAT_TRANSLATION_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_cnat_session {
    vl_api_cnat_endpoint_t src;
    vl_api_cnat_endpoint_t dst;
    vl_api_cnat_endpoint_t new;
    vl_api_ip_proto_t ip_proto;
    u8 location;
    f64 timestamp;
} vl_api_cnat_session_t;
#define VL_API_CNAT_SESSION_IS_CONSTANT_SIZE (1)

typedef enum __attribute__((packed)) {
    CNAT_POLICY_INCLUDE_V4 = 0,
    CNAT_POLICY_INCLUDE_V6 = 1,
    CNAT_POLICY_POD = 2,
    CNAT_POLICY_HOST = 3,
} vl_api_cnat_snat_policy_table_t;
STATIC_ASSERT(sizeof(vl_api_cnat_snat_policy_table_t) == sizeof(u8), "size of API enum cnat_snat_policy_table is wrong");
typedef enum __attribute__((packed)) {
    CNAT_POLICY_NONE = 0,
    CNAT_POLICY_IF_PFX = 1,
    CNAT_POLICY_K8S = 2,
} vl_api_cnat_snat_policies_t;
STATIC_ASSERT(sizeof(vl_api_cnat_snat_policies_t) == sizeof(u8), "size of API enum cnat_snat_policies is wrong");
typedef struct __attribute__ ((packed)) _vl_api_cnat_translation_update {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_cnat_translation_t translation;
} vl_api_cnat_translation_update_t;
#define VL_API_CNAT_TRANSLATION_UPDATE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_cnat_translation_update_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 id;
} vl_api_cnat_translation_update_reply_t;
#define VL_API_CNAT_TRANSLATION_UPDATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_translation_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 id;
} vl_api_cnat_translation_del_t;
#define VL_API_CNAT_TRANSLATION_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_translation_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_cnat_translation_del_reply_t;
#define VL_API_CNAT_TRANSLATION_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_translation_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_cnat_translation_t translation;
} vl_api_cnat_translation_details_t;
#define VL_API_CNAT_TRANSLATION_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_cnat_translation_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_cnat_translation_dump_t;
#define VL_API_CNAT_TRANSLATION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_session_purge {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_cnat_session_purge_t;
#define VL_API_CNAT_SESSION_PURGE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_session_purge_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_cnat_session_purge_reply_t;
#define VL_API_CNAT_SESSION_PURGE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_session_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_cnat_session_t session;
} vl_api_cnat_session_details_t;
#define VL_API_CNAT_SESSION_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_session_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_cnat_session_dump_t;
#define VL_API_CNAT_SESSION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_set_snat_addresses {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip4_address_t snat_ip4;
    vl_api_ip6_address_t snat_ip6;
    vl_api_interface_index_t sw_if_index;
} vl_api_cnat_set_snat_addresses_t;
#define VL_API_CNAT_SET_SNAT_ADDRESSES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_set_snat_addresses_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_cnat_set_snat_addresses_reply_t;
#define VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_get_snat_addresses {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_cnat_get_snat_addresses_t;
#define VL_API_CNAT_GET_SNAT_ADDRESSES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_get_snat_addresses_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 id;
    vl_api_ip4_address_t snat_ip4;
    vl_api_ip6_address_t snat_ip6;
    vl_api_interface_index_t sw_if_index;
} vl_api_cnat_get_snat_addresses_reply_t;
#define VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_snat_policy_add_del_exclude_pfx {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 is_add;
    vl_api_prefix_t prefix;
} vl_api_cnat_snat_policy_add_del_exclude_pfx_t;
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_snat_policy_add_del_exclude_pfx_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t;
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_snat_policy_add_del_if {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 is_add;
    vl_api_cnat_snat_policy_table_t table;
} vl_api_cnat_snat_policy_add_del_if_t;
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_snat_policy_add_del_if_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_cnat_snat_policy_add_del_if_reply_t;
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_set_snat_policy {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_cnat_snat_policies_t policy;
} vl_api_cnat_set_snat_policy_t;
#define VL_API_CNAT_SET_SNAT_POLICY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_cnat_set_snat_policy_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_cnat_set_snat_policy_reply_t;
#define VL_API_CNAT_SET_SNAT_POLICY_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_CNAT_TRANSLATION_UPDATE_CRC "cnat_translation_update_f8d40bc5"
#define VL_API_CNAT_TRANSLATION_UPDATE_REPLY_CRC "cnat_translation_update_reply_e2fc8294"
#define VL_API_CNAT_TRANSLATION_DEL_CRC "cnat_translation_del_3a91bde5"
#define VL_API_CNAT_TRANSLATION_DEL_REPLY_CRC "cnat_translation_del_reply_e8d4e804"
#define VL_API_CNAT_TRANSLATION_DETAILS_CRC "cnat_translation_details_1a5140b7"
#define VL_API_CNAT_TRANSLATION_DUMP_CRC "cnat_translation_dump_51077d14"
#define VL_API_CNAT_SESSION_PURGE_CRC "cnat_session_purge_51077d14"
#define VL_API_CNAT_SESSION_PURGE_REPLY_CRC "cnat_session_purge_reply_e8d4e804"
#define VL_API_CNAT_SESSION_DETAILS_CRC "cnat_session_details_7e5017c7"
#define VL_API_CNAT_SESSION_DUMP_CRC "cnat_session_dump_51077d14"
#define VL_API_CNAT_SET_SNAT_ADDRESSES_CRC "cnat_set_snat_addresses_d997e96c"
#define VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY_CRC "cnat_set_snat_addresses_reply_e8d4e804"
#define VL_API_CNAT_GET_SNAT_ADDRESSES_CRC "cnat_get_snat_addresses_51077d14"
#define VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY_CRC "cnat_get_snat_addresses_reply_879513c1"
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_CRC "cnat_snat_policy_add_del_exclude_pfx_e26dd79a"
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY_CRC "cnat_snat_policy_add_del_exclude_pfx_reply_e8d4e804"
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_CRC "cnat_snat_policy_add_del_if_4ebb8d02"
#define VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY_CRC "cnat_snat_policy_add_del_if_reply_e8d4e804"
#define VL_API_CNAT_SET_SNAT_POLICY_CRC "cnat_set_snat_policy_d3e6eaf4"
#define VL_API_CNAT_SET_SNAT_POLICY_REPLY_CRC "cnat_set_snat_policy_reply_e8d4e804"

#endif
