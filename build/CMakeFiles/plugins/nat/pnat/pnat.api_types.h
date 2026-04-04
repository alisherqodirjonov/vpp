#ifndef included_pnat_api_types_h
#define included_pnat_api_types_h
#define VL_API_PNAT_API_VERSION_MAJOR 0
#define VL_API_PNAT_API_VERSION_MINOR 1
#define VL_API_PNAT_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    PNAT_SA = 1,
    PNAT_DA = 2,
    PNAT_SPORT = 4,
    PNAT_DPORT = 8,
    PNAT_COPY_BYTE = 16,
    PNAT_CLEAR_BYTE = 32,
    PNAT_PROTO = 64,
} vl_api_pnat_mask_t;
typedef enum {
    PNAT_IP4_INPUT = 0,
    PNAT_IP4_OUTPUT = 1,
    PNAT_ATTACHMENT_POINT_MAX = 2,
} vl_api_pnat_attachment_point_t;
typedef struct __attribute__ ((packed)) _vl_api_pnat_match_tuple {
    vl_api_ip4_address_t src;
    vl_api_ip4_address_t dst;
    vl_api_ip_proto_t proto;
    u16 sport;
    u16 dport;
    vl_api_pnat_mask_t mask;
} vl_api_pnat_match_tuple_t;
#define VL_API_PNAT_MATCH_TUPLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_rewrite_tuple {
    vl_api_ip4_address_t src;
    vl_api_ip4_address_t dst;
    u16 sport;
    u16 dport;
    vl_api_pnat_mask_t mask;
    u8 from_offset;
    u8 to_offset;
    u8 clear_offset;
} vl_api_pnat_rewrite_tuple_t;
#define VL_API_PNAT_REWRITE_TUPLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_pnat_match_tuple_t match;
    vl_api_pnat_rewrite_tuple_t rewrite;
} vl_api_pnat_binding_add_t;
#define VL_API_PNAT_BINDING_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 binding_index;
} vl_api_pnat_binding_add_reply_t;
#define VL_API_PNAT_BINDING_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_add_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_pnat_match_tuple_t match;
    vl_api_pnat_rewrite_tuple_t rewrite;
} vl_api_pnat_binding_add_v2_t;
#define VL_API_PNAT_BINDING_ADD_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_add_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 binding_index;
} vl_api_pnat_binding_add_v2_reply_t;
#define VL_API_PNAT_BINDING_ADD_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 binding_index;
} vl_api_pnat_binding_del_t;
#define VL_API_PNAT_BINDING_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pnat_binding_del_reply_t;
#define VL_API_PNAT_BINDING_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_attach {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_pnat_attachment_point_t attachment;
    u32 binding_index;
} vl_api_pnat_binding_attach_t;
#define VL_API_PNAT_BINDING_ATTACH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_attach_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pnat_binding_attach_reply_t;
#define VL_API_PNAT_BINDING_ATTACH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_detach {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_pnat_attachment_point_t attachment;
    u32 binding_index;
} vl_api_pnat_binding_detach_t;
#define VL_API_PNAT_BINDING_DETACH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_binding_detach_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_pnat_binding_detach_reply_t;
#define VL_API_PNAT_BINDING_DETACH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_bindings_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_pnat_bindings_get_t;
#define VL_API_PNAT_BINDINGS_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_bindings_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_pnat_bindings_get_reply_t;
#define VL_API_PNAT_BINDINGS_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_bindings_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_pnat_match_tuple_t match;
    vl_api_pnat_rewrite_tuple_t rewrite;
} vl_api_pnat_bindings_details_t;
#define VL_API_PNAT_BINDINGS_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_interfaces_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_pnat_interfaces_get_t;
#define VL_API_PNAT_INTERFACES_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_interfaces_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_pnat_interfaces_get_reply_t;
#define VL_API_PNAT_INTERFACES_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_interfaces_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enabled[2];
    vl_api_pnat_mask_t lookup_mask[2];
} vl_api_pnat_interfaces_details_t;
#define VL_API_PNAT_INTERFACES_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_flow_lookup {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    vl_api_pnat_attachment_point_t attachment;
    vl_api_pnat_match_tuple_t match;
} vl_api_pnat_flow_lookup_t;
#define VL_API_PNAT_FLOW_LOOKUP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_pnat_flow_lookup_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 binding_index;
} vl_api_pnat_flow_lookup_reply_t;
#define VL_API_PNAT_FLOW_LOOKUP_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_PNAT_BINDING_ADD_CRC "pnat_binding_add_946ee0b7"
#define VL_API_PNAT_BINDING_ADD_REPLY_CRC "pnat_binding_add_reply_4cd980a7"
#define VL_API_PNAT_BINDING_ADD_V2_CRC "pnat_binding_add_v2_946ee0b7"
#define VL_API_PNAT_BINDING_ADD_V2_REPLY_CRC "pnat_binding_add_v2_reply_4cd980a7"
#define VL_API_PNAT_BINDING_DEL_CRC "pnat_binding_del_9259df7b"
#define VL_API_PNAT_BINDING_DEL_REPLY_CRC "pnat_binding_del_reply_e8d4e804"
#define VL_API_PNAT_BINDING_ATTACH_CRC "pnat_binding_attach_6e074232"
#define VL_API_PNAT_BINDING_ATTACH_REPLY_CRC "pnat_binding_attach_reply_e8d4e804"
#define VL_API_PNAT_BINDING_DETACH_CRC "pnat_binding_detach_6e074232"
#define VL_API_PNAT_BINDING_DETACH_REPLY_CRC "pnat_binding_detach_reply_e8d4e804"
#define VL_API_PNAT_BINDINGS_GET_CRC "pnat_bindings_get_f75ba505"
#define VL_API_PNAT_BINDINGS_GET_REPLY_CRC "pnat_bindings_get_reply_53b48f5d"
#define VL_API_PNAT_BINDINGS_DETAILS_CRC "pnat_bindings_details_08fb2815"
#define VL_API_PNAT_INTERFACES_GET_CRC "pnat_interfaces_get_f75ba505"
#define VL_API_PNAT_INTERFACES_GET_REPLY_CRC "pnat_interfaces_get_reply_53b48f5d"
#define VL_API_PNAT_INTERFACES_DETAILS_CRC "pnat_interfaces_details_4cb09493"
#define VL_API_PNAT_FLOW_LOOKUP_CRC "pnat_flow_lookup_1ef8747c"
#define VL_API_PNAT_FLOW_LOOKUP_REPLY_CRC "pnat_flow_lookup_reply_4cd980a7"

#endif
