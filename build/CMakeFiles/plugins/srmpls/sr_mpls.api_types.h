#ifndef included_sr_mpls_api_types_h
#define included_sr_mpls_api_types_h
#define VL_API_SR_MPLS_API_VERSION_MAJOR 3
#define VL_API_SR_MPLS_API_VERSION_MINOR 0
#define VL_API_SR_MPLS_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/srv6/sr_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bsid;
    u32 weight;
    bool is_spray;
    u8 n_segments;
    u32 segments[0];
} vl_api_sr_mpls_policy_add_t;
#define VL_API_SR_MPLS_POLICY_ADD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mpls_policy_add_reply_t;
#define VL_API_SR_MPLS_POLICY_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_mod {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bsid;
    vl_api_sr_policy_op_t operation;
    u32 sl_index;
    u32 weight;
    u8 n_segments;
    u32 segments[0];
} vl_api_sr_mpls_policy_mod_t;
#define VL_API_SR_MPLS_POLICY_MOD_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_mod_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mpls_policy_mod_reply_t;
#define VL_API_SR_MPLS_POLICY_MOD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bsid;
} vl_api_sr_mpls_policy_del_t;
#define VL_API_SR_MPLS_POLICY_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mpls_policy_del_reply_t;
#define VL_API_SR_MPLS_POLICY_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_steering_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_del;
    u32 bsid;
    u32 table_id;
    vl_api_prefix_t prefix;
    u32 mask_width;
    vl_api_address_t next_hop;
    u32 color;
    u8 co_bits;
    u32 vpn_label;
} vl_api_sr_mpls_steering_add_del_t;
#define VL_API_SR_MPLS_STEERING_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_steering_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mpls_steering_add_del_reply_t;
#define VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_assign_endpoint_color {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 bsid;
    vl_api_address_t endpoint;
    u32 color;
} vl_api_sr_mpls_policy_assign_endpoint_color_t;
#define VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mpls_policy_assign_endpoint_color_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mpls_policy_assign_endpoint_color_reply_t;
#define VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_SR_MPLS_POLICY_ADD_CRC "sr_mpls_policy_add_a1a70c70"
#define VL_API_SR_MPLS_POLICY_ADD_REPLY_CRC "sr_mpls_policy_add_reply_e8d4e804"
#define VL_API_SR_MPLS_POLICY_MOD_CRC "sr_mpls_policy_mod_88482c17"
#define VL_API_SR_MPLS_POLICY_MOD_REPLY_CRC "sr_mpls_policy_mod_reply_e8d4e804"
#define VL_API_SR_MPLS_POLICY_DEL_CRC "sr_mpls_policy_del_e29d34fa"
#define VL_API_SR_MPLS_POLICY_DEL_REPLY_CRC "sr_mpls_policy_del_reply_e8d4e804"
#define VL_API_SR_MPLS_STEERING_ADD_DEL_CRC "sr_mpls_steering_add_del_64acff63"
#define VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY_CRC "sr_mpls_steering_add_del_reply_e8d4e804"
#define VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_CRC "sr_mpls_policy_assign_endpoint_color_0e7eb978"
#define VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY_CRC "sr_mpls_policy_assign_endpoint_color_reply_e8d4e804"

#endif
