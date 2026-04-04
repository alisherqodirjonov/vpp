#ifndef included_one_api_types_h
#define included_one_api_types_h
#define VL_API_ONE_API_VERSION_MAJOR 2
#define VL_API_ONE_API_VERSION_MINOR 0
#define VL_API_ONE_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <lisp/lisp-cp/lisp_types.api_types.h>
typedef enum {
    ONE_MAP_MODE_API_DST_ONLY = 0,
    ONE_MAP_MODE_API_SRC_DST = 1,
} vl_api_one_map_mode_t;
typedef struct __attribute__ ((packed)) _vl_api_one_l2_arp_entry {
    vl_api_mac_address_t mac;
    vl_api_ip4_address_t ip4;
} vl_api_one_l2_arp_entry_t;
#define VL_API_ONE_L2_ARP_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_ndp_entry {
    vl_api_mac_address_t mac;
    vl_api_ip6_address_t ip6;
} vl_api_one_ndp_entry_t;
#define VL_API_ONE_NDP_ENTRY_IS_CONSTANT_SIZE (1)

typedef enum {
    ONE_FILTER_API_ALL = 0,
    ONE_FILTER_API_LOCAL = 1,
    ONE_FILTER_API_REMOTE = 2,
} vl_api_one_filter_t;
typedef struct __attribute__ ((packed)) _vl_api_one_adjacency {
    vl_api_eid_t reid;
    vl_api_eid_t leid;
} vl_api_one_adjacency_t;
#define VL_API_ONE_ADJACENCY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_locator_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 locator_set_name[64];
    u32 locator_num;
    vl_api_local_locator_t locators[0];
} vl_api_one_add_del_locator_set_t;
#define VL_API_ONE_ADD_DEL_LOCATOR_SET_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_locator_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 ls_index;
} vl_api_one_add_del_locator_set_reply_t;
#define VL_API_ONE_ADD_DEL_LOCATOR_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_locator {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 locator_set_name[64];
    vl_api_interface_index_t sw_if_index;
    u8 priority;
    u8 weight;
} vl_api_one_add_del_locator_t;
#define VL_API_ONE_ADD_DEL_LOCATOR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_locator_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_locator_reply_t;
#define VL_API_ONE_ADD_DEL_LOCATOR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_local_eid {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_eid_t eid;
    u8 locator_set_name[64];
    u32 vni;
    vl_api_hmac_key_t key;
} vl_api_one_add_del_local_eid_t;
#define VL_API_ONE_ADD_DEL_LOCAL_EID_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_local_eid_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_local_eid_reply_t;
#define VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_register_set_ttl {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 ttl;
} vl_api_one_map_register_set_ttl_t;
#define VL_API_ONE_MAP_REGISTER_SET_TTL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_register_set_ttl_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_map_register_set_ttl_reply_t;
#define VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_register_ttl {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_map_register_ttl_t;
#define VL_API_SHOW_ONE_MAP_REGISTER_TTL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_register_ttl_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 ttl;
} vl_api_show_one_map_register_ttl_reply_t;
#define VL_API_SHOW_ONE_MAP_REGISTER_TTL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_map_server {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t ip_address;
} vl_api_one_add_del_map_server_t;
#define VL_API_ONE_ADD_DEL_MAP_SERVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_map_server_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_map_server_reply_t;
#define VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_map_resolver {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_address_t ip_address;
} vl_api_one_add_del_map_resolver_t;
#define VL_API_ONE_ADD_DEL_MAP_RESOLVER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_map_resolver_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_map_resolver_reply_t;
#define VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_enable_disable_t;
#define VL_API_ONE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_enable_disable_reply_t;
#define VL_API_ONE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_nsh_set_locator_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 ls_name[64];
} vl_api_one_nsh_set_locator_set_t;
#define VL_API_ONE_NSH_SET_LOCATOR_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_nsh_set_locator_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_nsh_set_locator_set_reply_t;
#define VL_API_ONE_NSH_SET_LOCATOR_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_pitr_set_locator_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 ls_name[64];
} vl_api_one_pitr_set_locator_set_t;
#define VL_API_ONE_PITR_SET_LOCATOR_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_pitr_set_locator_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_pitr_set_locator_set_reply_t;
#define VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_use_petr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t ip_address;
    bool is_add;
} vl_api_one_use_petr_t;
#define VL_API_ONE_USE_PETR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_use_petr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_use_petr_reply_t;
#define VL_API_ONE_USE_PETR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_use_petr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_use_petr_t;
#define VL_API_SHOW_ONE_USE_PETR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_use_petr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool status;
    vl_api_address_t ip_address;
} vl_api_show_one_use_petr_reply_t;
#define VL_API_SHOW_ONE_USE_PETR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_rloc_probe_state {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_rloc_probe_state_t;
#define VL_API_SHOW_ONE_RLOC_PROBE_STATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_rloc_probe_state_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enable;
} vl_api_show_one_rloc_probe_state_reply_t;
#define VL_API_SHOW_ONE_RLOC_PROBE_STATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_rloc_probe_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_rloc_probe_enable_disable_t;
#define VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_rloc_probe_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_rloc_probe_enable_disable_reply_t;
#define VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_register_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_map_register_enable_disable_t;
#define VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_register_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_map_register_enable_disable_reply_t;
#define VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_register_state {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_map_register_state_t;
#define VL_API_SHOW_ONE_MAP_REGISTER_STATE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_register_state_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enable;
} vl_api_show_one_map_register_state_reply_t;
#define VL_API_SHOW_ONE_MAP_REGISTER_STATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_request_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_one_map_mode_t mode;
} vl_api_one_map_request_mode_t;
#define VL_API_ONE_MAP_REQUEST_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_request_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_map_request_mode_reply_t;
#define VL_API_ONE_MAP_REQUEST_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_request_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_map_request_mode_t;
#define VL_API_SHOW_ONE_MAP_REQUEST_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_request_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_one_map_mode_t mode;
} vl_api_show_one_map_request_mode_reply_t;
#define VL_API_SHOW_ONE_MAP_REQUEST_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_remote_mapping {
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
} vl_api_one_add_del_remote_mapping_t;
#define VL_API_ONE_ADD_DEL_REMOTE_MAPPING_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_remote_mapping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_remote_mapping_reply_t;
#define VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_l2_arp_entry {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 bd;
    vl_api_one_l2_arp_entry_t entry;
} vl_api_one_add_del_l2_arp_entry_t;
#define VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_l2_arp_entry_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_l2_arp_entry_reply_t;
#define VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_l2_arp_entries_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bd;
} vl_api_one_l2_arp_entries_get_t;
#define VL_API_ONE_L2_ARP_ENTRIES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_l2_arp_entries_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_one_l2_arp_entry_t entries[0];
} vl_api_one_l2_arp_entries_get_reply_t;
#define VL_API_ONE_L2_ARP_ENTRIES_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_ndp_entry {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 bd;
    vl_api_one_ndp_entry_t entry;
} vl_api_one_add_del_ndp_entry_t;
#define VL_API_ONE_ADD_DEL_NDP_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_ndp_entry_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_ndp_entry_reply_t;
#define VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_ndp_entries_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bd;
} vl_api_one_ndp_entries_get_t;
#define VL_API_ONE_NDP_ENTRIES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_ndp_entries_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_one_ndp_entry_t entries[0];
} vl_api_one_ndp_entries_get_reply_t;
#define VL_API_ONE_NDP_ENTRIES_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_set_transport_protocol {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 protocol;
} vl_api_one_set_transport_protocol_t;
#define VL_API_ONE_SET_TRANSPORT_PROTOCOL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_set_transport_protocol_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_set_transport_protocol_reply_t;
#define VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_get_transport_protocol {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_get_transport_protocol_t;
#define VL_API_ONE_GET_TRANSPORT_PROTOCOL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_get_transport_protocol_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 protocol;
} vl_api_one_get_transport_protocol_reply_t;
#define VL_API_ONE_GET_TRANSPORT_PROTOCOL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_ndp_bd_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_ndp_bd_get_t;
#define VL_API_ONE_NDP_BD_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_ndp_bd_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    u32 bridge_domains[0];
} vl_api_one_ndp_bd_get_reply_t;
#define VL_API_ONE_NDP_BD_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_l2_arp_bd_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_l2_arp_bd_get_t;
#define VL_API_ONE_L2_ARP_BD_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_l2_arp_bd_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    u32 bridge_domains[0];
} vl_api_one_l2_arp_bd_get_reply_t;
#define VL_API_ONE_L2_ARP_BD_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_adjacency {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 is_add;
    u32 vni;
    vl_api_eid_t reid;
    vl_api_eid_t leid;
} vl_api_one_add_del_adjacency_t;
#define VL_API_ONE_ADD_DEL_ADJACENCY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_adjacency_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_adjacency_reply_t;
#define VL_API_ONE_ADD_DEL_ADJACENCY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_map_request_itr_rlocs {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u8 locator_set_name[64];
} vl_api_one_add_del_map_request_itr_rlocs_t;
#define VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_add_del_map_request_itr_rlocs_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_add_del_map_request_itr_rlocs_reply_t;
#define VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_add_del_map {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 vni;
    u32 dp_table;
    bool is_l2;
} vl_api_one_eid_table_add_del_map_t;
#define VL_API_ONE_EID_TABLE_ADD_DEL_MAP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_add_del_map_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_eid_table_add_del_map_reply_t;
#define VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_locator_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 ls_index;
    u8 ls_name[64];
    bool is_index_set;
} vl_api_one_locator_dump_t;
#define VL_API_ONE_LOCATOR_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_locator_details {
    u16 _vl_msg_id;
    u32 context;
    u8 local;
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t ip_address;
    u8 priority;
    u8 weight;
} vl_api_one_locator_details_t;
#define VL_API_ONE_LOCATOR_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_locator_set_details {
    u16 _vl_msg_id;
    u32 context;
    u32 ls_index;
    u8 ls_name[64];
} vl_api_one_locator_set_details_t;
#define VL_API_ONE_LOCATOR_SET_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_locator_set_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_one_filter_t filter;
} vl_api_one_locator_set_dump_t;
#define VL_API_ONE_LOCATOR_SET_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_details {
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
} vl_api_one_eid_table_details_t;
#define VL_API_ONE_EID_TABLE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool eid_set;
    u32 vni;
    vl_api_eid_t eid;
    vl_api_one_filter_t filter;
} vl_api_one_eid_table_dump_t;
#define VL_API_ONE_EID_TABLE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_adjacencies_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    vl_api_one_adjacency_t adjacencies[0];
} vl_api_one_adjacencies_get_reply_t;
#define VL_API_ONE_ADJACENCIES_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_one_adjacencies_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 vni;
} vl_api_one_adjacencies_get_t;
#define VL_API_ONE_ADJACENCIES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_map_details {
    u16 _vl_msg_id;
    u32 context;
    u32 vni;
    u32 dp_table;
} vl_api_one_eid_table_map_details_t;
#define VL_API_ONE_EID_TABLE_MAP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_map_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_l2;
} vl_api_one_eid_table_map_dump_t;
#define VL_API_ONE_EID_TABLE_MAP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_vni_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_eid_table_vni_dump_t;
#define VL_API_ONE_EID_TABLE_VNI_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_eid_table_vni_details {
    u16 _vl_msg_id;
    u32 context;
    u32 vni;
} vl_api_one_eid_table_vni_details_t;
#define VL_API_ONE_EID_TABLE_VNI_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_resolver_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_address_t ip_address;
} vl_api_one_map_resolver_details_t;
#define VL_API_ONE_MAP_RESOLVER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_resolver_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_map_resolver_dump_t;
#define VL_API_ONE_MAP_RESOLVER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_server_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_address_t ip_address;
} vl_api_one_map_server_details_t;
#define VL_API_ONE_MAP_SERVER_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_server_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_map_server_dump_t;
#define VL_API_ONE_MAP_SERVER_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_status {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_status_t;
#define VL_API_SHOW_ONE_STATUS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_status_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool feature_status;
    bool gpe_status;
} vl_api_show_one_status_reply_t;
#define VL_API_SHOW_ONE_STATUS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_get_map_request_itr_rlocs {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_get_map_request_itr_rlocs_t;
#define VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_get_map_request_itr_rlocs_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 locator_set_name[64];
} vl_api_one_get_map_request_itr_rlocs_reply_t;
#define VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_nsh_mapping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_nsh_mapping_t;
#define VL_API_SHOW_ONE_NSH_MAPPING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_nsh_mapping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_set;
    u8 locator_set_name[64];
} vl_api_show_one_nsh_mapping_reply_t;
#define VL_API_SHOW_ONE_NSH_MAPPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_pitr {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_pitr_t;
#define VL_API_SHOW_ONE_PITR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_pitr_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool status;
    u8 locator_set_name[64];
} vl_api_show_one_pitr_reply_t;
#define VL_API_SHOW_ONE_PITR_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_stats_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_stats_dump_t;
#define VL_API_ONE_STATS_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_stats_details {
    u16 _vl_msg_id;
    u32 context;
    u32 vni;
    vl_api_eid_t deid;
    vl_api_eid_t seid;
    vl_api_address_t rloc;
    vl_api_address_t lloc;
    u32 pkt_count;
    u32 bytes;
} vl_api_one_stats_details_t;
#define VL_API_ONE_STATS_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_stats_flush {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_stats_flush_t;
#define VL_API_ONE_STATS_FLUSH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_stats_flush_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_stats_flush_reply_t;
#define VL_API_ONE_STATS_FLUSH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_stats_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_stats_enable_disable_t;
#define VL_API_ONE_STATS_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_stats_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_stats_enable_disable_reply_t;
#define VL_API_ONE_STATS_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_stats_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_stats_enable_disable_t;
#define VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_stats_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enable;
} vl_api_show_one_stats_enable_disable_reply_t;
#define VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_register_fallback_threshold {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 value;
} vl_api_one_map_register_fallback_threshold_t;
#define VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_map_register_fallback_threshold_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_map_register_fallback_threshold_reply_t;
#define VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_register_fallback_threshold {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_show_one_map_register_fallback_threshold_t;
#define VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_show_one_map_register_fallback_threshold_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 value;
} vl_api_show_one_map_register_fallback_threshold_reply_t;
#define VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_xtr_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_enable_disable_xtr_mode_t;
#define VL_API_ONE_ENABLE_DISABLE_XTR_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_xtr_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_enable_disable_xtr_mode_reply_t;
#define VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_show_xtr_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_show_xtr_mode_t;
#define VL_API_ONE_SHOW_XTR_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_show_xtr_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enable;
} vl_api_one_show_xtr_mode_reply_t;
#define VL_API_ONE_SHOW_XTR_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_petr_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_enable_disable_petr_mode_t;
#define VL_API_ONE_ENABLE_DISABLE_PETR_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_petr_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_enable_disable_petr_mode_reply_t;
#define VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_show_petr_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_show_petr_mode_t;
#define VL_API_ONE_SHOW_PETR_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_show_petr_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enable;
} vl_api_one_show_petr_mode_reply_t;
#define VL_API_ONE_SHOW_PETR_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_pitr_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_enable;
} vl_api_one_enable_disable_pitr_mode_t;
#define VL_API_ONE_ENABLE_DISABLE_PITR_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_enable_disable_pitr_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_one_enable_disable_pitr_mode_reply_t;
#define VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_show_pitr_mode {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_one_show_pitr_mode_t;
#define VL_API_ONE_SHOW_PITR_MODE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_one_show_pitr_mode_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    bool is_enable;
} vl_api_one_show_pitr_mode_reply_t;
#define VL_API_ONE_SHOW_PITR_MODE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_ONE_ADD_DEL_LOCATOR_SET_CRC "one_add_del_locator_set_6fcd6471"
#define VL_API_ONE_ADD_DEL_LOCATOR_SET_REPLY_CRC "one_add_del_locator_set_reply_b6666db4"
#define VL_API_ONE_ADD_DEL_LOCATOR_CRC "one_add_del_locator_af4d8f13"
#define VL_API_ONE_ADD_DEL_LOCATOR_REPLY_CRC "one_add_del_locator_reply_e8d4e804"
#define VL_API_ONE_ADD_DEL_LOCAL_EID_CRC "one_add_del_local_eid_4e5a83a2"
#define VL_API_ONE_ADD_DEL_LOCAL_EID_REPLY_CRC "one_add_del_local_eid_reply_e8d4e804"
#define VL_API_ONE_MAP_REGISTER_SET_TTL_CRC "one_map_register_set_ttl_dd59f1f3"
#define VL_API_ONE_MAP_REGISTER_SET_TTL_REPLY_CRC "one_map_register_set_ttl_reply_e8d4e804"
#define VL_API_SHOW_ONE_MAP_REGISTER_TTL_CRC "show_one_map_register_ttl_51077d14"
#define VL_API_SHOW_ONE_MAP_REGISTER_TTL_REPLY_CRC "show_one_map_register_ttl_reply_fa83dd66"
#define VL_API_ONE_ADD_DEL_MAP_SERVER_CRC "one_add_del_map_server_ce19e32d"
#define VL_API_ONE_ADD_DEL_MAP_SERVER_REPLY_CRC "one_add_del_map_server_reply_e8d4e804"
#define VL_API_ONE_ADD_DEL_MAP_RESOLVER_CRC "one_add_del_map_resolver_ce19e32d"
#define VL_API_ONE_ADD_DEL_MAP_RESOLVER_REPLY_CRC "one_add_del_map_resolver_reply_e8d4e804"
#define VL_API_ONE_ENABLE_DISABLE_CRC "one_enable_disable_c264d7bf"
#define VL_API_ONE_ENABLE_DISABLE_REPLY_CRC "one_enable_disable_reply_e8d4e804"
#define VL_API_ONE_NSH_SET_LOCATOR_SET_CRC "one_nsh_set_locator_set_486e2b76"
#define VL_API_ONE_NSH_SET_LOCATOR_SET_REPLY_CRC "one_nsh_set_locator_set_reply_e8d4e804"
#define VL_API_ONE_PITR_SET_LOCATOR_SET_CRC "one_pitr_set_locator_set_486e2b76"
#define VL_API_ONE_PITR_SET_LOCATOR_SET_REPLY_CRC "one_pitr_set_locator_set_reply_e8d4e804"
#define VL_API_ONE_USE_PETR_CRC "one_use_petr_d87dbad9"
#define VL_API_ONE_USE_PETR_REPLY_CRC "one_use_petr_reply_e8d4e804"
#define VL_API_SHOW_ONE_USE_PETR_CRC "show_one_use_petr_51077d14"
#define VL_API_SHOW_ONE_USE_PETR_REPLY_CRC "show_one_use_petr_reply_84a03528"
#define VL_API_SHOW_ONE_RLOC_PROBE_STATE_CRC "show_one_rloc_probe_state_51077d14"
#define VL_API_SHOW_ONE_RLOC_PROBE_STATE_REPLY_CRC "show_one_rloc_probe_state_reply_f15abb16"
#define VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_CRC "one_rloc_probe_enable_disable_c264d7bf"
#define VL_API_ONE_RLOC_PROBE_ENABLE_DISABLE_REPLY_CRC "one_rloc_probe_enable_disable_reply_e8d4e804"
#define VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_CRC "one_map_register_enable_disable_c264d7bf"
#define VL_API_ONE_MAP_REGISTER_ENABLE_DISABLE_REPLY_CRC "one_map_register_enable_disable_reply_e8d4e804"
#define VL_API_SHOW_ONE_MAP_REGISTER_STATE_CRC "show_one_map_register_state_51077d14"
#define VL_API_SHOW_ONE_MAP_REGISTER_STATE_REPLY_CRC "show_one_map_register_state_reply_f15abb16"
#define VL_API_ONE_MAP_REQUEST_MODE_CRC "one_map_request_mode_ffa5d2f5"
#define VL_API_ONE_MAP_REQUEST_MODE_REPLY_CRC "one_map_request_mode_reply_e8d4e804"
#define VL_API_SHOW_ONE_MAP_REQUEST_MODE_CRC "show_one_map_request_mode_51077d14"
#define VL_API_SHOW_ONE_MAP_REQUEST_MODE_REPLY_CRC "show_one_map_request_mode_reply_d41f3c1d"
#define VL_API_ONE_ADD_DEL_REMOTE_MAPPING_CRC "one_add_del_remote_mapping_6d5c789e"
#define VL_API_ONE_ADD_DEL_REMOTE_MAPPING_REPLY_CRC "one_add_del_remote_mapping_reply_e8d4e804"
#define VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_CRC "one_add_del_l2_arp_entry_1aa5e8b3"
#define VL_API_ONE_ADD_DEL_L2_ARP_ENTRY_REPLY_CRC "one_add_del_l2_arp_entry_reply_e8d4e804"
#define VL_API_ONE_L2_ARP_ENTRIES_GET_CRC "one_l2_arp_entries_get_4d418cf4"
#define VL_API_ONE_L2_ARP_ENTRIES_GET_REPLY_CRC "one_l2_arp_entries_get_reply_b0dd200f"
#define VL_API_ONE_ADD_DEL_NDP_ENTRY_CRC "one_add_del_ndp_entry_0f8a287c"
#define VL_API_ONE_ADD_DEL_NDP_ENTRY_REPLY_CRC "one_add_del_ndp_entry_reply_e8d4e804"
#define VL_API_ONE_NDP_ENTRIES_GET_CRC "one_ndp_entries_get_4d418cf4"
#define VL_API_ONE_NDP_ENTRIES_GET_REPLY_CRC "one_ndp_entries_get_reply_70719b1a"
#define VL_API_ONE_SET_TRANSPORT_PROTOCOL_CRC "one_set_transport_protocol_07b6b85f"
#define VL_API_ONE_SET_TRANSPORT_PROTOCOL_REPLY_CRC "one_set_transport_protocol_reply_e8d4e804"
#define VL_API_ONE_GET_TRANSPORT_PROTOCOL_CRC "one_get_transport_protocol_51077d14"
#define VL_API_ONE_GET_TRANSPORT_PROTOCOL_REPLY_CRC "one_get_transport_protocol_reply_62a28eb3"
#define VL_API_ONE_NDP_BD_GET_CRC "one_ndp_bd_get_51077d14"
#define VL_API_ONE_NDP_BD_GET_REPLY_CRC "one_ndp_bd_get_reply_221ac888"
#define VL_API_ONE_L2_ARP_BD_GET_CRC "one_l2_arp_bd_get_51077d14"
#define VL_API_ONE_L2_ARP_BD_GET_REPLY_CRC "one_l2_arp_bd_get_reply_221ac888"
#define VL_API_ONE_ADD_DEL_ADJACENCY_CRC "one_add_del_adjacency_9e830312"
#define VL_API_ONE_ADD_DEL_ADJACENCY_REPLY_CRC "one_add_del_adjacency_reply_e8d4e804"
#define VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_CRC "one_add_del_map_request_itr_rlocs_6be88e45"
#define VL_API_ONE_ADD_DEL_MAP_REQUEST_ITR_RLOCS_REPLY_CRC "one_add_del_map_request_itr_rlocs_reply_e8d4e804"
#define VL_API_ONE_EID_TABLE_ADD_DEL_MAP_CRC "one_eid_table_add_del_map_9481416b"
#define VL_API_ONE_EID_TABLE_ADD_DEL_MAP_REPLY_CRC "one_eid_table_add_del_map_reply_e8d4e804"
#define VL_API_ONE_LOCATOR_DUMP_CRC "one_locator_dump_9b11076c"
#define VL_API_ONE_LOCATOR_DETAILS_CRC "one_locator_details_2c620ffe"
#define VL_API_ONE_LOCATOR_SET_DETAILS_CRC "one_locator_set_details_5b33a105"
#define VL_API_ONE_LOCATOR_SET_DUMP_CRC "one_locator_set_dump_71190768"
#define VL_API_ONE_EID_TABLE_DETAILS_CRC "one_eid_table_details_1c29f792"
#define VL_API_ONE_EID_TABLE_DUMP_CRC "one_eid_table_dump_bd190269"
#define VL_API_ONE_ADJACENCIES_GET_REPLY_CRC "one_adjacencies_get_reply_085bab89"
#define VL_API_ONE_ADJACENCIES_GET_CRC "one_adjacencies_get_8d1f2fe9"
#define VL_API_ONE_EID_TABLE_MAP_DETAILS_CRC "one_eid_table_map_details_0b6859e2"
#define VL_API_ONE_EID_TABLE_MAP_DUMP_CRC "one_eid_table_map_dump_d6cf0c3d"
#define VL_API_ONE_EID_TABLE_VNI_DUMP_CRC "one_eid_table_vni_dump_51077d14"
#define VL_API_ONE_EID_TABLE_VNI_DETAILS_CRC "one_eid_table_vni_details_64abc01e"
#define VL_API_ONE_MAP_RESOLVER_DETAILS_CRC "one_map_resolver_details_3e78fc57"
#define VL_API_ONE_MAP_RESOLVER_DUMP_CRC "one_map_resolver_dump_51077d14"
#define VL_API_ONE_MAP_SERVER_DETAILS_CRC "one_map_server_details_3e78fc57"
#define VL_API_ONE_MAP_SERVER_DUMP_CRC "one_map_server_dump_51077d14"
#define VL_API_SHOW_ONE_STATUS_CRC "show_one_status_51077d14"
#define VL_API_SHOW_ONE_STATUS_REPLY_CRC "show_one_status_reply_961bb25b"
#define VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_CRC "one_get_map_request_itr_rlocs_51077d14"
#define VL_API_ONE_GET_MAP_REQUEST_ITR_RLOCS_REPLY_CRC "one_get_map_request_itr_rlocs_reply_76580f3a"
#define VL_API_SHOW_ONE_NSH_MAPPING_CRC "show_one_nsh_mapping_51077d14"
#define VL_API_SHOW_ONE_NSH_MAPPING_REPLY_CRC "show_one_nsh_mapping_reply_46478c02"
#define VL_API_SHOW_ONE_PITR_CRC "show_one_pitr_51077d14"
#define VL_API_SHOW_ONE_PITR_REPLY_CRC "show_one_pitr_reply_a2d1a49f"
#define VL_API_ONE_STATS_DUMP_CRC "one_stats_dump_51077d14"
#define VL_API_ONE_STATS_DETAILS_CRC "one_stats_details_2eb74678"
#define VL_API_ONE_STATS_FLUSH_CRC "one_stats_flush_51077d14"
#define VL_API_ONE_STATS_FLUSH_REPLY_CRC "one_stats_flush_reply_e8d4e804"
#define VL_API_ONE_STATS_ENABLE_DISABLE_CRC "one_stats_enable_disable_c264d7bf"
#define VL_API_ONE_STATS_ENABLE_DISABLE_REPLY_CRC "one_stats_enable_disable_reply_e8d4e804"
#define VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_CRC "show_one_stats_enable_disable_51077d14"
#define VL_API_SHOW_ONE_STATS_ENABLE_DISABLE_REPLY_CRC "show_one_stats_enable_disable_reply_f15abb16"
#define VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_CRC "one_map_register_fallback_threshold_f7d4a475"
#define VL_API_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY_CRC "one_map_register_fallback_threshold_reply_e8d4e804"
#define VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_CRC "show_one_map_register_fallback_threshold_51077d14"
#define VL_API_SHOW_ONE_MAP_REGISTER_FALLBACK_THRESHOLD_REPLY_CRC "show_one_map_register_fallback_threshold_reply_c93a9113"
#define VL_API_ONE_ENABLE_DISABLE_XTR_MODE_CRC "one_enable_disable_xtr_mode_c264d7bf"
#define VL_API_ONE_ENABLE_DISABLE_XTR_MODE_REPLY_CRC "one_enable_disable_xtr_mode_reply_e8d4e804"
#define VL_API_ONE_SHOW_XTR_MODE_CRC "one_show_xtr_mode_51077d14"
#define VL_API_ONE_SHOW_XTR_MODE_REPLY_CRC "one_show_xtr_mode_reply_f15abb16"
#define VL_API_ONE_ENABLE_DISABLE_PETR_MODE_CRC "one_enable_disable_petr_mode_c264d7bf"
#define VL_API_ONE_ENABLE_DISABLE_PETR_MODE_REPLY_CRC "one_enable_disable_petr_mode_reply_e8d4e804"
#define VL_API_ONE_SHOW_PETR_MODE_CRC "one_show_petr_mode_51077d14"
#define VL_API_ONE_SHOW_PETR_MODE_REPLY_CRC "one_show_petr_mode_reply_f15abb16"
#define VL_API_ONE_ENABLE_DISABLE_PITR_MODE_CRC "one_enable_disable_pitr_mode_c264d7bf"
#define VL_API_ONE_ENABLE_DISABLE_PITR_MODE_REPLY_CRC "one_enable_disable_pitr_mode_reply_e8d4e804"
#define VL_API_ONE_SHOW_PITR_MODE_CRC "one_show_pitr_mode_51077d14"
#define VL_API_ONE_SHOW_PITR_MODE_REPLY_CRC "one_show_pitr_mode_reply_f15abb16"

#endif
