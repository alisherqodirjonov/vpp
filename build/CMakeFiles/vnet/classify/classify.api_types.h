#ifndef included_classify_api_types_h
#define included_classify_api_types_h
#define VL_API_CLASSIFY_API_VERSION_MAJOR 3
#define VL_API_CLASSIFY_API_VERSION_MINOR 1
#define VL_API_CLASSIFY_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef enum __attribute__((packed)) {
    CLASSIFY_API_ACTION_NONE = 0,
    CLASSIFY_API_ACTION_SET_IP4_FIB_INDEX = 1,
    CLASSIFY_API_ACTION_SET_IP6_FIB_INDEX = 2,
    CLASSIFY_API_ACTION_SET_METADATA = 3,
} vl_api_classify_action_t;
STATIC_ASSERT(sizeof(vl_api_classify_action_t) == sizeof(u8), "size of API enum classify_action is wrong");
typedef enum __attribute__((packed)) {
    POLICER_CLASSIFY_API_TABLE_IP4 = 0,
    POLICER_CLASSIFY_API_TABLE_IP6 = 1,
    POLICER_CLASSIFY_API_TABLE_L2 = 2,
} vl_api_policer_classify_table_t;
STATIC_ASSERT(sizeof(vl_api_policer_classify_table_t) == sizeof(u8), "size of API enum policer_classify_table is wrong");
typedef enum __attribute__((packed)) {
    FLOW_CLASSIFY_API_TABLE_IP4 = 0,
    FLOW_CLASSIFY_API_TABLE_IP6 = 1,
} vl_api_flow_classify_table_t;
STATIC_ASSERT(sizeof(vl_api_flow_classify_table_t) == sizeof(u8), "size of API enum flow_classify_table is wrong");
typedef struct __attribute__ ((packed)) _vl_api_classify_add_del_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    bool del_chain;
    u32 table_index;
    u32 nbuckets;
    u32 memory_size;
    u32 skip_n_vectors;
    u32 match_n_vectors;
    u32 next_table_index;
    u32 miss_next_index;
    u8 current_data_flag;
    i16 current_data_offset;
    u32 mask_len;
    u8 mask[0];
} vl_api_classify_add_del_table_t;
#define VL_API_CLASSIFY_ADD_DEL_TABLE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_add_del_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 new_table_index;
    u32 skip_n_vectors;
    u32 match_n_vectors;
} vl_api_classify_add_del_table_reply_t;
#define VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_add_del_session {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    u32 table_index;
    u32 hit_next_index;
    u32 opaque_index;
    i32 advance;
    vl_api_classify_action_t action;
    u32 metadata;
    u32 match_len;
    u8 match[0];
} vl_api_classify_add_del_session_t;
#define VL_API_CLASSIFY_ADD_DEL_SESSION_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_add_del_session_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_classify_add_del_session_reply_t;
#define VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_classify_set_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 ip4_table_index;
    u32 ip6_table_index;
    u32 l2_table_index;
    bool is_add;
} vl_api_policer_classify_set_interface_t;
#define VL_API_POLICER_CLASSIFY_SET_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_classify_set_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_policer_classify_set_interface_reply_t;
#define VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_classify_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_policer_classify_table_t type;
    vl_api_interface_index_t sw_if_index;
} vl_api_policer_classify_dump_t;
#define VL_API_POLICER_CLASSIFY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_policer_classify_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 table_index;
} vl_api_policer_classify_details_t;
#define VL_API_POLICER_CLASSIFY_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_table_ids {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_classify_table_ids_t;
#define VL_API_CLASSIFY_TABLE_IDS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_table_ids_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    u32 ids[0];
} vl_api_classify_table_ids_reply_t;
#define VL_API_CLASSIFY_TABLE_IDS_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_table_by_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_classify_table_by_interface_t;
#define VL_API_CLASSIFY_TABLE_BY_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_table_by_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t sw_if_index;
    u32 l2_table_id;
    u32 ip4_table_id;
    u32 ip6_table_id;
} vl_api_classify_table_by_interface_reply_t;
#define VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_table_info {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_id;
} vl_api_classify_table_info_t;
#define VL_API_CLASSIFY_TABLE_INFO_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_table_info_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_id;
    u32 nbuckets;
    u32 match_n_vectors;
    u32 skip_n_vectors;
    u32 active_sessions;
    u32 next_table_index;
    u32 miss_next_index;
    u32 mask_length;
    u8 mask[0];
} vl_api_classify_table_info_reply_t;
#define VL_API_CLASSIFY_TABLE_INFO_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_session_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_id;
} vl_api_classify_session_dump_t;
#define VL_API_CLASSIFY_SESSION_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_session_details {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_id;
    u32 hit_next_index;
    i32 advance;
    u32 opaque_index;
    u32 match_length;
    u8 match[0];
} vl_api_classify_session_details_t;
#define VL_API_CLASSIFY_SESSION_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_flow_classify_set_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 ip4_table_index;
    u32 ip6_table_index;
    bool is_add;
} vl_api_flow_classify_set_interface_t;
#define VL_API_FLOW_CLASSIFY_SET_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_classify_set_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_flow_classify_set_interface_reply_t;
#define VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_classify_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_flow_classify_table_t type;
    vl_api_interface_index_t sw_if_index;
} vl_api_flow_classify_dump_t;
#define VL_API_FLOW_CLASSIFY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_flow_classify_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 table_index;
} vl_api_flow_classify_details_t;
#define VL_API_FLOW_CLASSIFY_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_set_interface_ip_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_ipv6;
    vl_api_interface_index_t sw_if_index;
    u32 table_index;
} vl_api_classify_set_interface_ip_table_t;
#define VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_set_interface_ip_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_classify_set_interface_ip_table_reply_t;
#define VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_set_interface_l2_tables {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 ip4_table_index;
    u32 ip6_table_index;
    u32 other_table_index;
    bool is_input;
} vl_api_classify_set_interface_l2_tables_t;
#define VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_set_interface_l2_tables_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_classify_set_interface_l2_tables_reply_t;
#define VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_input_acl_set_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 ip4_table_index;
    u32 ip6_table_index;
    u32 l2_table_index;
    bool is_add;
} vl_api_input_acl_set_interface_t;
#define VL_API_INPUT_ACL_SET_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_input_acl_set_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_input_acl_set_interface_reply_t;
#define VL_API_INPUT_ACL_SET_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_acl_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 ip4_table_index;
    u32 ip6_table_index;
    bool is_add;
} vl_api_punt_acl_add_del_t;
#define VL_API_PUNT_ACL_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_acl_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_punt_acl_add_del_reply_t;
#define VL_API_PUNT_ACL_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_acl_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_punt_acl_get_t;
#define VL_API_PUNT_ACL_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_punt_acl_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 ip4_table_index;
    u32 ip6_table_index;
} vl_api_punt_acl_get_reply_t;
#define VL_API_PUNT_ACL_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_output_acl_set_interface {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 ip4_table_index;
    u32 ip6_table_index;
    u32 l2_table_index;
    bool is_add;
} vl_api_output_acl_set_interface_t;
#define VL_API_OUTPUT_ACL_SET_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_output_acl_set_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_output_acl_set_interface_reply_t;
#define VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_pcap_lookup_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 skip_n_vectors;
    u32 match_n_vectors;
    u32 mask_len;
    u8 mask[0];
} vl_api_classify_pcap_lookup_table_t;
#define VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_pcap_lookup_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_index;
} vl_api_classify_pcap_lookup_table_reply_t;
#define VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_pcap_set_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u32 table_index;
    bool sort_masks;
} vl_api_classify_pcap_set_table_t;
#define VL_API_CLASSIFY_PCAP_SET_TABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_pcap_set_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_index;
} vl_api_classify_pcap_set_table_reply_t;
#define VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_pcap_get_tables {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_classify_pcap_get_tables_t;
#define VL_API_CLASSIFY_PCAP_GET_TABLES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_pcap_get_tables_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    u32 indices[0];
} vl_api_classify_pcap_get_tables_reply_t;
#define VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_trace_lookup_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 skip_n_vectors;
    u32 match_n_vectors;
    u32 mask_len;
    u8 mask[0];
} vl_api_classify_trace_lookup_table_t;
#define VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_classify_trace_lookup_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_index;
} vl_api_classify_trace_lookup_table_reply_t;
#define VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_trace_set_table {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 table_index;
    bool sort_masks;
} vl_api_classify_trace_set_table_t;
#define VL_API_CLASSIFY_TRACE_SET_TABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_trace_set_table_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 table_index;
} vl_api_classify_trace_set_table_reply_t;
#define VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_trace_get_tables {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_classify_trace_get_tables_t;
#define VL_API_CLASSIFY_TRACE_GET_TABLES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_classify_trace_get_tables_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 count;
    u32 indices[0];
} vl_api_classify_trace_get_tables_reply_t;
#define VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY_IS_CONSTANT_SIZE (0)

#define VL_API_CLASSIFY_ADD_DEL_TABLE_CRC "classify_add_del_table_6849e39e"
#define VL_API_CLASSIFY_ADD_DEL_TABLE_REPLY_CRC "classify_add_del_table_reply_05486349"
#define VL_API_CLASSIFY_ADD_DEL_SESSION_CRC "classify_add_del_session_f20879f0"
#define VL_API_CLASSIFY_ADD_DEL_SESSION_REPLY_CRC "classify_add_del_session_reply_e8d4e804"
#define VL_API_POLICER_CLASSIFY_SET_INTERFACE_CRC "policer_classify_set_interface_de7ad708"
#define VL_API_POLICER_CLASSIFY_SET_INTERFACE_REPLY_CRC "policer_classify_set_interface_reply_e8d4e804"
#define VL_API_POLICER_CLASSIFY_DUMP_CRC "policer_classify_dump_56cbb5fb"
#define VL_API_POLICER_CLASSIFY_DETAILS_CRC "policer_classify_details_dfd08765"
#define VL_API_CLASSIFY_TABLE_IDS_CRC "classify_table_ids_51077d14"
#define VL_API_CLASSIFY_TABLE_IDS_REPLY_CRC "classify_table_ids_reply_d1d20e1d"
#define VL_API_CLASSIFY_TABLE_BY_INTERFACE_CRC "classify_table_by_interface_f9e6675e"
#define VL_API_CLASSIFY_TABLE_BY_INTERFACE_REPLY_CRC "classify_table_by_interface_reply_ed4197db"
#define VL_API_CLASSIFY_TABLE_INFO_CRC "classify_table_info_0cca2cd9"
#define VL_API_CLASSIFY_TABLE_INFO_REPLY_CRC "classify_table_info_reply_4a573c0e"
#define VL_API_CLASSIFY_SESSION_DUMP_CRC "classify_session_dump_0cca2cd9"
#define VL_API_CLASSIFY_SESSION_DETAILS_CRC "classify_session_details_60e3ef94"
#define VL_API_FLOW_CLASSIFY_SET_INTERFACE_CRC "flow_classify_set_interface_b6192f1c"
#define VL_API_FLOW_CLASSIFY_SET_INTERFACE_REPLY_CRC "flow_classify_set_interface_reply_e8d4e804"
#define VL_API_FLOW_CLASSIFY_DUMP_CRC "flow_classify_dump_25dd3e4c"
#define VL_API_FLOW_CLASSIFY_DETAILS_CRC "flow_classify_details_dfd08765"
#define VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_CRC "classify_set_interface_ip_table_e0b097c7"
#define VL_API_CLASSIFY_SET_INTERFACE_IP_TABLE_REPLY_CRC "classify_set_interface_ip_table_reply_e8d4e804"
#define VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_CRC "classify_set_interface_l2_tables_5a6ddf65"
#define VL_API_CLASSIFY_SET_INTERFACE_L2_TABLES_REPLY_CRC "classify_set_interface_l2_tables_reply_e8d4e804"
#define VL_API_INPUT_ACL_SET_INTERFACE_CRC "input_acl_set_interface_de7ad708"
#define VL_API_INPUT_ACL_SET_INTERFACE_REPLY_CRC "input_acl_set_interface_reply_e8d4e804"
#define VL_API_PUNT_ACL_ADD_DEL_CRC "punt_acl_add_del_a93bf3a0"
#define VL_API_PUNT_ACL_ADD_DEL_REPLY_CRC "punt_acl_add_del_reply_e8d4e804"
#define VL_API_PUNT_ACL_GET_CRC "punt_acl_get_51077d14"
#define VL_API_PUNT_ACL_GET_REPLY_CRC "punt_acl_get_reply_8409b9dd"
#define VL_API_OUTPUT_ACL_SET_INTERFACE_CRC "output_acl_set_interface_de7ad708"
#define VL_API_OUTPUT_ACL_SET_INTERFACE_REPLY_CRC "output_acl_set_interface_reply_e8d4e804"
#define VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_CRC "classify_pcap_lookup_table_e1b4cc6b"
#define VL_API_CLASSIFY_PCAP_LOOKUP_TABLE_REPLY_CRC "classify_pcap_lookup_table_reply_9c6c6773"
#define VL_API_CLASSIFY_PCAP_SET_TABLE_CRC "classify_pcap_set_table_006051b3"
#define VL_API_CLASSIFY_PCAP_SET_TABLE_REPLY_CRC "classify_pcap_set_table_reply_9c6c6773"
#define VL_API_CLASSIFY_PCAP_GET_TABLES_CRC "classify_pcap_get_tables_f9e6675e"
#define VL_API_CLASSIFY_PCAP_GET_TABLES_REPLY_CRC "classify_pcap_get_tables_reply_5f5bc9e6"
#define VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_CRC "classify_trace_lookup_table_3f7b72e4"
#define VL_API_CLASSIFY_TRACE_LOOKUP_TABLE_REPLY_CRC "classify_trace_lookup_table_reply_9c6c6773"
#define VL_API_CLASSIFY_TRACE_SET_TABLE_CRC "classify_trace_set_table_3909b55a"
#define VL_API_CLASSIFY_TRACE_SET_TABLE_REPLY_CRC "classify_trace_set_table_reply_9c6c6773"
#define VL_API_CLASSIFY_TRACE_GET_TABLES_CRC "classify_trace_get_tables_51077d14"
#define VL_API_CLASSIFY_TRACE_GET_TABLES_REPLY_CRC "classify_trace_get_tables_reply_5f5bc9e6"

#endif
