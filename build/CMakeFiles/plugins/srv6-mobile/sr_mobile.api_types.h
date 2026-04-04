#ifndef included_sr_mobile_api_types_h
#define included_sr_mobile_api_types_h
#define VL_API_SR_MOBILE_API_VERSION_MAJOR 0
#define VL_API_SR_MOBILE_API_VERSION_MINOR 1
#define VL_API_SR_MOBILE_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/srv6/sr_types.api_types.h>
#include <vnet/srv6/sr.api_types.h>
#include <srv6-mobile/sr_mobile_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_sr_mobile_localsid_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_del;
    vl_api_ip6_prefix_t localsid_prefix;
    u8 behavior[64];
    u32 fib_table;
    u32 local_fib_table;
    bool drop_in;
    vl_api_sr_mobile_nhtype_t nhtype;
    vl_api_ip6_prefix_t sr_prefix;
    vl_api_ip4_address_t v4src_addr;
    u32 v4src_position;
} vl_api_sr_mobile_localsid_add_del_t;
#define VL_API_SR_MOBILE_LOCALSID_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mobile_localsid_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mobile_localsid_add_del_reply_t;
#define VL_API_SR_MOBILE_LOCALSID_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mobile_policy_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_ip6_address_t bsid_addr;
    vl_api_ip6_prefix_t sr_prefix;
    vl_api_ip6_prefix_t v6src_prefix;
    u8 behavior[64];
    u32 fib_table;
    u32 local_fib_table;
    vl_api_ip6_address_t encap_src;
    bool drop_in;
    vl_api_sr_mobile_nhtype_t nhtype;
} vl_api_sr_mobile_policy_add_t;
#define VL_API_SR_MOBILE_POLICY_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_mobile_policy_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_mobile_policy_add_reply_t;
#define VL_API_SR_MOBILE_POLICY_ADD_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_SR_MOBILE_LOCALSID_ADD_DEL_CRC "sr_mobile_localsid_add_del_b85a7ed7"
#define VL_API_SR_MOBILE_LOCALSID_ADD_DEL_REPLY_CRC "sr_mobile_localsid_add_del_reply_e8d4e804"
#define VL_API_SR_MOBILE_POLICY_ADD_CRC "sr_mobile_policy_add_8f051658"
#define VL_API_SR_MOBILE_POLICY_ADD_REPLY_CRC "sr_mobile_policy_add_reply_e8d4e804"

#endif
