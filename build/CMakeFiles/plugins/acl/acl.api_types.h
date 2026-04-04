#ifndef included_acl_api_types_h
#define included_acl_api_types_h
#define VL_API_ACL_API_VERSION_MAJOR 2
#define VL_API_ACL_API_VERSION_MINOR 0
#define VL_API_ACL_API_VERSION_PATCH 1
/* Imported API files */
#include <acl/acl_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_get_version {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_acl_plugin_get_version_t;
#define VL_API_ACL_PLUGIN_GET_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_get_version_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 major;
    u32 minor;
} vl_api_acl_plugin_get_version_reply_t;
#define VL_API_ACL_PLUGIN_GET_VERSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_control_ping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_acl_plugin_control_ping_t;
#define VL_API_ACL_PLUGIN_CONTROL_PING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_control_ping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 client_index;
    u32 vpe_pid;
} vl_api_acl_plugin_control_ping_reply_t;
#define VL_API_ACL_PLUGIN_CONTROL_PING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_get_conn_table_max_entries {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_acl_plugin_get_conn_table_max_entries_t;
#define VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_get_conn_table_max_entries_reply {
    u16 _vl_msg_id;
    u32 context;
    u64 conn_table_max_entries;
} vl_api_acl_plugin_get_conn_table_max_entries_reply_t;
#define VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_add_replace {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 acl_index;
    u8 tag[64];
    u32 count;
    vl_api_acl_rule_t r[0];
} vl_api_acl_add_replace_t;
#define VL_API_ACL_ADD_REPLACE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_acl_add_replace_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 acl_index;
    i32 retval;
} vl_api_acl_add_replace_reply_t;
#define VL_API_ACL_ADD_REPLACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 acl_index;
} vl_api_acl_del_t;
#define VL_API_ACL_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_acl_del_reply_t;
#define VL_API_ACL_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool is_input;
    vl_api_interface_index_t sw_if_index;
    u32 acl_index;
} vl_api_acl_interface_add_del_t;
#define VL_API_ACL_INTERFACE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_acl_interface_add_del_reply_t;
#define VL_API_ACL_INTERFACE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_set_acl_list {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 count;
    u8 n_input;
    u32 acls[0];
} vl_api_acl_interface_set_acl_list_t;
#define VL_API_ACL_INTERFACE_SET_ACL_LIST_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_set_acl_list_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_acl_interface_set_acl_list_reply_t;
#define VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 acl_index;
} vl_api_acl_dump_t;
#define VL_API_ACL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_details {
    u16 _vl_msg_id;
    u32 context;
    u32 acl_index;
    u8 tag[64];
    u32 count;
    vl_api_acl_rule_t r[0];
} vl_api_acl_details_t;
#define VL_API_ACL_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_list_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_acl_interface_list_dump_t;
#define VL_API_ACL_INTERFACE_LIST_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_list_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 count;
    u8 n_input;
    u32 acls[0];
} vl_api_acl_interface_list_details_t;
#define VL_API_ACL_INTERFACE_LIST_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 tag[64];
    u32 count;
    vl_api_macip_acl_rule_t r[0];
} vl_api_macip_acl_add_t;
#define VL_API_MACIP_ACL_ADD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_add_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 acl_index;
    i32 retval;
} vl_api_macip_acl_add_reply_t;
#define VL_API_MACIP_ACL_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_add_replace {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 acl_index;
    u8 tag[64];
    u32 count;
    vl_api_macip_acl_rule_t r[0];
} vl_api_macip_acl_add_replace_t;
#define VL_API_MACIP_ACL_ADD_REPLACE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_add_replace_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 acl_index;
    i32 retval;
} vl_api_macip_acl_add_replace_reply_t;
#define VL_API_MACIP_ACL_ADD_REPLACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 acl_index;
} vl_api_macip_acl_del_t;
#define VL_API_MACIP_ACL_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_macip_acl_del_reply_t;
#define VL_API_MACIP_ACL_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_interface_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    u32 acl_index;
} vl_api_macip_acl_interface_add_del_t;
#define VL_API_MACIP_ACL_INTERFACE_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_interface_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_macip_acl_interface_add_del_reply_t;
#define VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 acl_index;
} vl_api_macip_acl_dump_t;
#define VL_API_MACIP_ACL_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_details {
    u16 _vl_msg_id;
    u32 context;
    u32 acl_index;
    u8 tag[64];
    u32 count;
    vl_api_macip_acl_rule_t r[0];
} vl_api_macip_acl_details_t;
#define VL_API_MACIP_ACL_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_interface_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_macip_acl_interface_get_t;
#define VL_API_MACIP_ACL_INTERFACE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_interface_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 count;
    u32 acls[0];
} vl_api_macip_acl_interface_get_reply_t;
#define VL_API_MACIP_ACL_INTERFACE_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_interface_list_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_macip_acl_interface_list_dump_t;
#define VL_API_MACIP_ACL_INTERFACE_LIST_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_macip_acl_interface_list_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 count;
    u32 acls[0];
} vl_api_macip_acl_interface_list_details_t;
#define VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_set_etype_whitelist {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 count;
    u8 n_input;
    u16 whitelist[0];
} vl_api_acl_interface_set_etype_whitelist_t;
#define VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_set_etype_whitelist_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_acl_interface_set_etype_whitelist_reply_t;
#define VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_etype_whitelist_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_acl_interface_etype_whitelist_dump_t;
#define VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_interface_etype_whitelist_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 count;
    u8 n_input;
    u16 whitelist[0];
} vl_api_acl_interface_etype_whitelist_details_t;
#define VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_acl_stats_intf_counters_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
} vl_api_acl_stats_intf_counters_enable_t;
#define VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_stats_intf_counters_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_acl_stats_intf_counters_enable_reply_t;
#define VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_use_hash_lookup_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool enable;
} vl_api_acl_plugin_use_hash_lookup_set_t;
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_use_hash_lookup_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_acl_plugin_use_hash_lookup_set_reply_t;
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_use_hash_lookup_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_acl_plugin_use_hash_lookup_get_t;
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_acl_plugin_use_hash_lookup_get_reply {
    u16 _vl_msg_id;
    u32 context;
    bool enable;
} vl_api_acl_plugin_use_hash_lookup_get_reply_t;
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_ACL_PLUGIN_GET_VERSION_CRC "acl_plugin_get_version_51077d14"
#define VL_API_ACL_PLUGIN_GET_VERSION_REPLY_CRC "acl_plugin_get_version_reply_9b32cf86"
#define VL_API_ACL_PLUGIN_CONTROL_PING_CRC "acl_plugin_control_ping_51077d14"
#define VL_API_ACL_PLUGIN_CONTROL_PING_REPLY_CRC "acl_plugin_control_ping_reply_f6b0b8ca"
#define VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_CRC "acl_plugin_get_conn_table_max_entries_51077d14"
#define VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY_CRC "acl_plugin_get_conn_table_max_entries_reply_7a096d3d"
#define VL_API_ACL_ADD_REPLACE_CRC "acl_add_replace_ee5c2f18"
#define VL_API_ACL_ADD_REPLACE_REPLY_CRC "acl_add_replace_reply_ac407b0c"
#define VL_API_ACL_DEL_CRC "acl_del_ef34fea4"
#define VL_API_ACL_DEL_REPLY_CRC "acl_del_reply_e8d4e804"
#define VL_API_ACL_INTERFACE_ADD_DEL_CRC "acl_interface_add_del_4b54bebd"
#define VL_API_ACL_INTERFACE_ADD_DEL_REPLY_CRC "acl_interface_add_del_reply_e8d4e804"
#define VL_API_ACL_INTERFACE_SET_ACL_LIST_CRC "acl_interface_set_acl_list_473982bd"
#define VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY_CRC "acl_interface_set_acl_list_reply_e8d4e804"
#define VL_API_ACL_DUMP_CRC "acl_dump_ef34fea4"
#define VL_API_ACL_DETAILS_CRC "acl_details_95babae0"
#define VL_API_ACL_INTERFACE_LIST_DUMP_CRC "acl_interface_list_dump_f9e6675e"
#define VL_API_ACL_INTERFACE_LIST_DETAILS_CRC "acl_interface_list_details_e695d256"
#define VL_API_MACIP_ACL_ADD_CRC "macip_acl_add_ce6fbad0"
#define VL_API_MACIP_ACL_ADD_REPLY_CRC "macip_acl_add_reply_ac407b0c"
#define VL_API_MACIP_ACL_ADD_REPLACE_CRC "macip_acl_add_replace_2a461dd4"
#define VL_API_MACIP_ACL_ADD_REPLACE_REPLY_CRC "macip_acl_add_replace_reply_ac407b0c"
#define VL_API_MACIP_ACL_DEL_CRC "macip_acl_del_ef34fea4"
#define VL_API_MACIP_ACL_DEL_REPLY_CRC "macip_acl_del_reply_e8d4e804"
#define VL_API_MACIP_ACL_INTERFACE_ADD_DEL_CRC "macip_acl_interface_add_del_4b8690b1"
#define VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY_CRC "macip_acl_interface_add_del_reply_e8d4e804"
#define VL_API_MACIP_ACL_DUMP_CRC "macip_acl_dump_ef34fea4"
#define VL_API_MACIP_ACL_DETAILS_CRC "macip_acl_details_27135b59"
#define VL_API_MACIP_ACL_INTERFACE_GET_CRC "macip_acl_interface_get_51077d14"
#define VL_API_MACIP_ACL_INTERFACE_GET_REPLY_CRC "macip_acl_interface_get_reply_accf9b05"
#define VL_API_MACIP_ACL_INTERFACE_LIST_DUMP_CRC "macip_acl_interface_list_dump_f9e6675e"
#define VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS_CRC "macip_acl_interface_list_details_a0c5d56d"
#define VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_CRC "acl_interface_set_etype_whitelist_3f5c2d2d"
#define VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY_CRC "acl_interface_set_etype_whitelist_reply_e8d4e804"
#define VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DUMP_CRC "acl_interface_etype_whitelist_dump_f9e6675e"
#define VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS_CRC "acl_interface_etype_whitelist_details_cc2bfded"
#define VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_CRC "acl_stats_intf_counters_enable_b3e225d2"
#define VL_API_ACL_STATS_INTF_COUNTERS_ENABLE_REPLY_CRC "acl_stats_intf_counters_enable_reply_e8d4e804"
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_CRC "acl_plugin_use_hash_lookup_set_b3e225d2"
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_SET_REPLY_CRC "acl_plugin_use_hash_lookup_set_reply_e8d4e804"
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_CRC "acl_plugin_use_hash_lookup_get_51077d14"
#define VL_API_ACL_PLUGIN_USE_HASH_LOOKUP_GET_REPLY_CRC "acl_plugin_use_hash_lookup_get_reply_5392ad31"

#endif
