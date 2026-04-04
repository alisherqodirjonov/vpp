#ifndef included_lisp_api_types_h
#define included_lisp_api_types_h
#define VL_API_LISP_API_VERSION_MAJOR 2
#define VL_API_LISP_API_VERSION_MINOR 0
#define VL_API_LISP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <lisp/lisp-cp/lisp_types.api_types.h>
typedef enum __attribute__((packed)) {
    LISP_LOCATOR_SET_FILTER_API_ALL = 0,
    LISP_LOCATOR_SET_FILTER_API_LOCAL = 1,
    LISP_LOCATOR_SET_FILTER_API_REMOTE = 2,
} vl_api_lisp_locator_set_filter_t;
STATIC_ASSERT(sizeof(vl_api_lisp_locator_set_filter_t) == sizeof(u8), "size of API enum lisp_locator_set_filter is wrong");
typedef struct __attribute__ ((packed)) _vl_api_lisp_adjacency {
    vl_api_eid_t reid;
    vl_api_eid_t leid;
} vl_api_lisp_adjacency_t;
#define VL_API_LISP_ADJACENCY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_locator_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 locator_set_name[64];
    u32 locator_num;
    vl_api_local_locator_t locators[0];
} vl_api_lisp_add_del_locator_set_t;
#define VL_API_LISP_ADD_DEL_LOCATOR_SET_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_locator_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 ls_index;
} vl_api_lisp_add_del_locator_set_reply_t;
#define VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_locator {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 locator_set_name[64];
    vl_api_interface_index_t sw_if_index;
    u8 priority;
    u8 weight;
} vl_api_lisp_add_del_locator_t;
#define VL_API_LISP_ADD_DEL_LOCATOR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_locator_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_locator_reply_t;
#define VL_API_LISP_ADD_DEL_LOCATOR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_local_eid {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_eid_t eid;
    u8 locator_set_name[64];
    u32 vni;
    vl_api_hmac_key_t key;
} vl_api_lisp_add_del_local_eid_t;
#define VL_API_LISP_ADD_DEL_LOCAL_EID_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_local_eid_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_local_eid_reply_t;
#define VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_map_server {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t ip_address;
} vl_api_lisp_add_del_map_server_t;
#define VL_API_LISP_ADD_DEL_MAP_SERVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_map_server_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_map_server_reply_t;
#define VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_map_resolver {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t ip_address;
} vl_api_lisp_add_del_map_resolver_t;
#define VL_API_LISP_ADD_DEL_MAP_RESOLVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_map_resolver_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_map_resolver_reply_t;
#define VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_lisp_enable_disable_t;
#define VL_API_LISP_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_enable_disable_reply_t;
#define VL_API_LISP_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_pitr_set_locator_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 ls_name[64];
} vl_api_lisp_pitr_set_locator_set_t;
#define VL_API_LISP_PITR_SET_LOCATOR_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_pitr_set_locator_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_pitr_set_locator_set_reply_t;
#define VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_use_petr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t ip_address;
    bool is_add;
} vl_api_lisp_use_petr_t;
#define VL_API_LISP_USE_PETR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_use_petr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_use_petr_reply_t;
#define VL_API_LISP_USE_PETR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_use_petr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_lisp_use_petr_t;
#define VL_API_SHOW_LISP_USE_PETR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_use_petr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_petr_enable;
    vl_api_address_t ip_address;
} vl_api_show_lisp_use_petr_reply_t;
#define VL_API_SHOW_LISP_USE_PETR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_rloc_probe_state {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_lisp_rloc_probe_state_t;
#define VL_API_SHOW_LISP_RLOC_PROBE_STATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_rloc_probe_state_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enabled;
} vl_api_show_lisp_rloc_probe_state_reply_t;
#define VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_rloc_probe_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_lisp_rloc_probe_enable_disable_t;
#define VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_rloc_probe_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_rloc_probe_enable_disable_reply_t;
#define VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_register_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_lisp_map_register_enable_disable_t;
#define VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_register_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_map_register_enable_disable_reply_t;
#define VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_map_register_state {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_lisp_map_register_state_t;
#define VL_API_SHOW_LISP_MAP_REGISTER_STATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_map_register_state_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enabled;
} vl_api_show_lisp_map_register_state_reply_t;
#define VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_request_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_src_dst;
} vl_api_lisp_map_request_mode_t;
#define VL_API_LISP_MAP_REQUEST_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_request_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_map_request_mode_reply_t;
#define VL_API_LISP_MAP_REQUEST_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_map_request_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_lisp_map_request_mode_t;
#define VL_API_SHOW_LISP_MAP_REQUEST_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_map_request_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_src_dst;
} vl_api_show_lisp_map_request_mode_reply_t;
#define VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_remote_mapping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool is_src_dst;
    bool del_all;
    u32 vni;
    u8 action;
    vl_api_eid_t deid;
    vl_api_eid_t seid;
    u32 rloc_num;
    vl_api_remote_locator_t rlocs[0];
} vl_api_lisp_add_del_remote_mapping_t;
#define VL_API_LISP_ADD_DEL_REMOTE_MAPPING_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_remote_mapping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_remote_mapping_reply_t;
#define VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_adjacency {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 vni;
    vl_api_eid_t reid;
    vl_api_eid_t leid;
} vl_api_lisp_add_del_adjacency_t;
#define VL_API_LISP_ADD_DEL_ADJACENCY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_adjacency_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_adjacency_reply_t;
#define VL_API_LISP_ADD_DEL_ADJACENCY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_map_request_itr_rlocs {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 locator_set_name[64];
} vl_api_lisp_add_del_map_request_itr_rlocs_t;
#define VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_add_del_map_request_itr_rlocs_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_add_del_map_request_itr_rlocs_reply_t;
#define VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_add_del_map {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 vni;
    u32 dp_table;
    bool is_l2;
} vl_api_lisp_eid_table_add_del_map_t;
#define VL_API_LISP_EID_TABLE_ADD_DEL_MAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_add_del_map_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lisp_eid_table_add_del_map_reply_t;
#define VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_locator_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 ls_index;
    u8 ls_name[64];
    u8 is_index_set;
} vl_api_lisp_locator_dump_t;
#define VL_API_LISP_LOCATOR_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_locator_details {
    u16 _vl_msg_id;
    u32 context;
    u8 local;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t ip_address;
    u8 priority;
    u8 weight;
} vl_api_lisp_locator_details_t;
#define VL_API_LISP_LOCATOR_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_locator_set_details {
    u16 _vl_msg_id;
    u32 context;
    u32 ls_index;
    u8 ls_name[64];
} vl_api_lisp_locator_set_details_t;
#define VL_API_LISP_LOCATOR_SET_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_locator_set_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_lisp_locator_set_filter_t filter;
} vl_api_lisp_locator_set_dump_t;
#define VL_API_LISP_LOCATOR_SET_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_details {
    u16 _vl_msg_id;
    u32 context;
    u32 locator_set_index;
    u8 action;
    bool is_local;
    bool is_src_dst;
    u32 vni;
    vl_api_eid_t deid;
    vl_api_eid_t seid;
    u32 ttl;
    u8 authoritative;
    vl_api_hmac_key_t key;
} vl_api_lisp_eid_table_details_t;
#define VL_API_LISP_EID_TABLE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 eid_set;
    u8 prefix_length;
    u32 vni;
    vl_api_eid_t eid;
    vl_api_lisp_locator_set_filter_t filter;
} vl_api_lisp_eid_table_dump_t;
#define VL_API_LISP_EID_TABLE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_adjacencies_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_lisp_adjacency_t adjacencies[0];
} vl_api_lisp_adjacencies_get_reply_t;
#define VL_API_LISP_ADJACENCIES_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_lisp_adjacencies_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 vni;
} vl_api_lisp_adjacencies_get_t;
#define VL_API_LISP_ADJACENCIES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_map_details {
    u16 _vl_msg_id;
    u32 context;
    u32 vni;
    u32 dp_table;
} vl_api_lisp_eid_table_map_details_t;
#define VL_API_LISP_EID_TABLE_MAP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_map_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_l2;
} vl_api_lisp_eid_table_map_dump_t;
#define VL_API_LISP_EID_TABLE_MAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_vni_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lisp_eid_table_vni_dump_t;
#define VL_API_LISP_EID_TABLE_VNI_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_eid_table_vni_details {
    u16 _vl_msg_id;
    u32 context;
    u32 vni;
} vl_api_lisp_eid_table_vni_details_t;
#define VL_API_LISP_EID_TABLE_VNI_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_resolver_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_address_t ip_address;
} vl_api_lisp_map_resolver_details_t;
#define VL_API_LISP_MAP_RESOLVER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_resolver_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lisp_map_resolver_dump_t;
#define VL_API_LISP_MAP_RESOLVER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_server_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_address_t ip_address;
} vl_api_lisp_map_server_details_t;
#define VL_API_LISP_MAP_SERVER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_map_server_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lisp_map_server_dump_t;
#define VL_API_LISP_MAP_SERVER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_status {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_lisp_status_t;
#define VL_API_SHOW_LISP_STATUS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_status_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_lisp_enabled;
    bool is_gpe_enabled;
} vl_api_show_lisp_status_reply_t;
#define VL_API_SHOW_LISP_STATUS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_get_map_request_itr_rlocs {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lisp_get_map_request_itr_rlocs_t;
#define VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lisp_get_map_request_itr_rlocs_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 locator_set_name[64];
} vl_api_lisp_get_map_request_itr_rlocs_reply_t;
#define VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_pitr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_lisp_pitr_t;
#define VL_API_SHOW_LISP_PITR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_lisp_pitr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enabled;
    u8 locator_set_name[64];
} vl_api_show_lisp_pitr_reply_t;
#define VL_API_SHOW_LISP_PITR_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_LISP_ADD_DEL_LOCATOR_SET_CRC "lisp_add_del_locator_set_6fcd6471"
#define VL_API_LISP_ADD_DEL_LOCATOR_SET_REPLY_CRC "lisp_add_del_locator_set_reply_b6666db4"
#define VL_API_LISP_ADD_DEL_LOCATOR_CRC "lisp_add_del_locator_af4d8f13"
#define VL_API_LISP_ADD_DEL_LOCATOR_REPLY_CRC "lisp_add_del_locator_reply_e8d4e804"
#define VL_API_LISP_ADD_DEL_LOCAL_EID_CRC "lisp_add_del_local_eid_4e5a83a2"
#define VL_API_LISP_ADD_DEL_LOCAL_EID_REPLY_CRC "lisp_add_del_local_eid_reply_e8d4e804"
#define VL_API_LISP_ADD_DEL_MAP_SERVER_CRC "lisp_add_del_map_server_ce19e32d"
#define VL_API_LISP_ADD_DEL_MAP_SERVER_REPLY_CRC "lisp_add_del_map_server_reply_e8d4e804"
#define VL_API_LISP_ADD_DEL_MAP_RESOLVER_CRC "lisp_add_del_map_resolver_ce19e32d"
#define VL_API_LISP_ADD_DEL_MAP_RESOLVER_REPLY_CRC "lisp_add_del_map_resolver_reply_e8d4e804"
#define VL_API_LISP_ENABLE_DISABLE_CRC "lisp_enable_disable_c264d7bf"
#define VL_API_LISP_ENABLE_DISABLE_REPLY_CRC "lisp_enable_disable_reply_e8d4e804"
#define VL_API_LISP_PITR_SET_LOCATOR_SET_CRC "lisp_pitr_set_locator_set_486e2b76"
#define VL_API_LISP_PITR_SET_LOCATOR_SET_REPLY_CRC "lisp_pitr_set_locator_set_reply_e8d4e804"
#define VL_API_LISP_USE_PETR_CRC "lisp_use_petr_d87dbad9"
#define VL_API_LISP_USE_PETR_REPLY_CRC "lisp_use_petr_reply_e8d4e804"
#define VL_API_SHOW_LISP_USE_PETR_CRC "show_lisp_use_petr_51077d14"
#define VL_API_SHOW_LISP_USE_PETR_REPLY_CRC "show_lisp_use_petr_reply_22b9a4b0"
#define VL_API_SHOW_LISP_RLOC_PROBE_STATE_CRC "show_lisp_rloc_probe_state_51077d14"
#define VL_API_SHOW_LISP_RLOC_PROBE_STATE_REPLY_CRC "show_lisp_rloc_probe_state_reply_e33a377b"
#define VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_CRC "lisp_rloc_probe_enable_disable_c264d7bf"
#define VL_API_LISP_RLOC_PROBE_ENABLE_DISABLE_REPLY_CRC "lisp_rloc_probe_enable_disable_reply_e8d4e804"
#define VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_CRC "lisp_map_register_enable_disable_c264d7bf"
#define VL_API_LISP_MAP_REGISTER_ENABLE_DISABLE_REPLY_CRC "lisp_map_register_enable_disable_reply_e8d4e804"
#define VL_API_SHOW_LISP_MAP_REGISTER_STATE_CRC "show_lisp_map_register_state_51077d14"
#define VL_API_SHOW_LISP_MAP_REGISTER_STATE_REPLY_CRC "show_lisp_map_register_state_reply_e33a377b"
#define VL_API_LISP_MAP_REQUEST_MODE_CRC "lisp_map_request_mode_f43c26ae"
#define VL_API_LISP_MAP_REQUEST_MODE_REPLY_CRC "lisp_map_request_mode_reply_e8d4e804"
#define VL_API_SHOW_LISP_MAP_REQUEST_MODE_CRC "show_lisp_map_request_mode_51077d14"
#define VL_API_SHOW_LISP_MAP_REQUEST_MODE_REPLY_CRC "show_lisp_map_request_mode_reply_5b05038e"
#define VL_API_LISP_ADD_DEL_REMOTE_MAPPING_CRC "lisp_add_del_remote_mapping_6d5c789e"
#define VL_API_LISP_ADD_DEL_REMOTE_MAPPING_REPLY_CRC "lisp_add_del_remote_mapping_reply_e8d4e804"
#define VL_API_LISP_ADD_DEL_ADJACENCY_CRC "lisp_add_del_adjacency_2ce0e6f6"
#define VL_API_LISP_ADD_DEL_ADJACENCY_REPLY_CRC "lisp_add_del_adjacency_reply_e8d4e804"
#define VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_CRC "lisp_add_del_map_request_itr_rlocs_6be88e45"
#define VL_API_LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY_CRC "lisp_add_del_map_request_itr_rlocs_reply_e8d4e804"
#define VL_API_LISP_EID_TABLE_ADD_DEL_MAP_CRC "lisp_eid_table_add_del_map_9481416b"
#define VL_API_LISP_EID_TABLE_ADD_DEL_MAP_REPLY_CRC "lisp_eid_table_add_del_map_reply_e8d4e804"
#define VL_API_LISP_LOCATOR_DUMP_CRC "lisp_locator_dump_b954fad7"
#define VL_API_LISP_LOCATOR_DETAILS_CRC "lisp_locator_details_2c620ffe"
#define VL_API_LISP_LOCATOR_SET_DETAILS_CRC "lisp_locator_set_details_5b33a105"
#define VL_API_LISP_LOCATOR_SET_DUMP_CRC "lisp_locator_set_dump_c2cb5922"
#define VL_API_LISP_EID_TABLE_DETAILS_CRC "lisp_eid_table_details_1c29f792"
#define VL_API_LISP_EID_TABLE_DUMP_CRC "lisp_eid_table_dump_629468b5"
#define VL_API_LISP_ADJACENCIES_GET_REPLY_CRC "lisp_adjacencies_get_reply_807257bf"
#define VL_API_LISP_ADJACENCIES_GET_CRC "lisp_adjacencies_get_8d1f2fe9"
#define VL_API_LISP_EID_TABLE_MAP_DETAILS_CRC "lisp_eid_table_map_details_0b6859e2"
#define VL_API_LISP_EID_TABLE_MAP_DUMP_CRC "lisp_eid_table_map_dump_d6cf0c3d"
#define VL_API_LISP_EID_TABLE_VNI_DUMP_CRC "lisp_eid_table_vni_dump_51077d14"
#define VL_API_LISP_EID_TABLE_VNI_DETAILS_CRC "lisp_eid_table_vni_details_64abc01e"
#define VL_API_LISP_MAP_RESOLVER_DETAILS_CRC "lisp_map_resolver_details_3e78fc57"
#define VL_API_LISP_MAP_RESOLVER_DUMP_CRC "lisp_map_resolver_dump_51077d14"
#define VL_API_LISP_MAP_SERVER_DETAILS_CRC "lisp_map_server_details_3e78fc57"
#define VL_API_LISP_MAP_SERVER_DUMP_CRC "lisp_map_server_dump_51077d14"
#define VL_API_SHOW_LISP_STATUS_CRC "show_lisp_status_51077d14"
#define VL_API_SHOW_LISP_STATUS_REPLY_CRC "show_lisp_status_reply_9e8f10c0"
#define VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_CRC "lisp_get_map_request_itr_rlocs_51077d14"
#define VL_API_LISP_GET_MAP_REQUEST_ITR_RLOCS_REPLY_CRC "lisp_get_map_request_itr_rlocs_reply_76580f3a"
#define VL_API_SHOW_LISP_PITR_CRC "show_lisp_pitr_51077d14"
#define VL_API_SHOW_LISP_PITR_REPLY_CRC "show_lisp_pitr_reply_27aa69b1"

#endif
