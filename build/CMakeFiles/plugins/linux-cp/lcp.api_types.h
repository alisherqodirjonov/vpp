#ifndef included_lcp_api_types_h
#define included_lcp_api_types_h
#define VL_API_LCP_API_VERSION_MAJOR 1
#define VL_API_LCP_API_VERSION_MINOR 0
#define VL_API_LCP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef enum __attribute__((packed)) {
    LCP_API_ITF_HOST_TAP = 0,
    LCP_API_ITF_HOST_TUN = 1,
} vl_api_lcp_itf_host_type_t;
STATIC_ASSERT(sizeof(vl_api_lcp_itf_host_type_t) == sizeof(u8), "size of API enum lcp_itf_host_type is wrong");
typedef struct __attribute__ ((packed)) _vl_api_lcp_default_ns_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 netns[32];
} vl_api_lcp_default_ns_set_t;
#define VL_API_LCP_DEFAULT_NS_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_default_ns_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lcp_default_ns_set_reply_t;
#define VL_API_LCP_DEFAULT_NS_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_default_ns_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lcp_default_ns_get_t;
#define VL_API_LCP_DEFAULT_NS_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_default_ns_get_reply {
    u16 _vl_msg_id;
    u32 context;
    u8 netns[32];
} vl_api_lcp_default_ns_get_reply_t;
#define VL_API_LCP_DEFAULT_NS_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    u8 host_if_name[16];
    vl_api_lcp_itf_host_type_t host_if_type;
    u8 netns[32];
} vl_api_lcp_itf_pair_add_del_t;
#define VL_API_LCP_ITF_PAIR_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lcp_itf_pair_add_del_reply_t;
#define VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_add_del_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    u8 host_if_name[16];
    vl_api_lcp_itf_host_type_t host_if_type;
    u8 netns[32];
} vl_api_lcp_itf_pair_add_del_v2_t;
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_add_del_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_interface_index_t host_sw_if_index;
} vl_api_lcp_itf_pair_add_del_v2_reply_t;
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_add_del_v3 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    u8 host_if_name[16];
    vl_api_lcp_itf_host_type_t host_if_type;
    u8 netns[32];
} vl_api_lcp_itf_pair_add_del_v3_t;
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V3_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_add_del_v3_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 vif_index;
    vl_api_interface_index_t host_sw_if_index;
} vl_api_lcp_itf_pair_add_del_v3_reply_t;
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
} vl_api_lcp_itf_pair_get_t;
#define VL_API_LCP_ITF_PAIR_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_lcp_itf_pair_get_reply_t;
#define VL_API_LCP_ITF_PAIR_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_get_v2 {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
    vl_api_interface_index_t sw_if_index;
} vl_api_lcp_itf_pair_get_v2_t;
#define VL_API_LCP_ITF_PAIR_GET_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_get_v2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_lcp_itf_pair_get_v2_reply_t;
#define VL_API_LCP_ITF_PAIR_GET_V2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t phy_sw_if_index;
    vl_api_interface_index_t host_sw_if_index;
    u32 vif_index;
    u8 host_if_name[16];
    vl_api_lcp_itf_host_type_t host_if_type;
    u8 netns[32];
} vl_api_lcp_itf_pair_details_t;
#define VL_API_LCP_ITF_PAIR_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_ethertype_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 ethertype;
} vl_api_lcp_ethertype_enable_t;
#define VL_API_LCP_ETHERTYPE_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_ethertype_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lcp_ethertype_enable_reply_t;
#define VL_API_LCP_ETHERTYPE_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_ethertype_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lcp_ethertype_get_t;
#define VL_API_LCP_ETHERTYPE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_ethertype_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u16 count;
    u16 ethertypes[0];
} vl_api_lcp_ethertype_get_reply_t;
#define VL_API_LCP_ETHERTYPE_GET_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_replace_begin {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lcp_itf_pair_replace_begin_t;
#define VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_replace_begin_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lcp_itf_pair_replace_begin_reply_t;
#define VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_replace_end {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_lcp_itf_pair_replace_end_t;
#define VL_API_LCP_ITF_PAIR_REPLACE_END_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_lcp_itf_pair_replace_end_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_lcp_itf_pair_replace_end_reply_t;
#define VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_LCP_DEFAULT_NS_SET_CRC "lcp_default_ns_set_69749409"
#define VL_API_LCP_DEFAULT_NS_SET_REPLY_CRC "lcp_default_ns_set_reply_e8d4e804"
#define VL_API_LCP_DEFAULT_NS_GET_CRC "lcp_default_ns_get_51077d14"
#define VL_API_LCP_DEFAULT_NS_GET_REPLY_CRC "lcp_default_ns_get_reply_5102feee"
#define VL_API_LCP_ITF_PAIR_ADD_DEL_CRC "lcp_itf_pair_add_del_40482b80"
#define VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY_CRC "lcp_itf_pair_add_del_reply_e8d4e804"
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V2_CRC "lcp_itf_pair_add_del_v2_40482b80"
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V2_REPLY_CRC "lcp_itf_pair_add_del_v2_reply_39452f52"
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V3_CRC "lcp_itf_pair_add_del_v3_40482b80"
#define VL_API_LCP_ITF_PAIR_ADD_DEL_V3_REPLY_CRC "lcp_itf_pair_add_del_v3_reply_c2502663"
#define VL_API_LCP_ITF_PAIR_GET_CRC "lcp_itf_pair_get_f75ba505"
#define VL_API_LCP_ITF_PAIR_GET_REPLY_CRC "lcp_itf_pair_get_reply_53b48f5d"
#define VL_API_LCP_ITF_PAIR_GET_V2_CRC "lcp_itf_pair_get_v2_47250981"
#define VL_API_LCP_ITF_PAIR_GET_V2_REPLY_CRC "lcp_itf_pair_get_v2_reply_53b48f5d"
#define VL_API_LCP_ITF_PAIR_DETAILS_CRC "lcp_itf_pair_details_8b5481af"
#define VL_API_LCP_ETHERTYPE_ENABLE_CRC "lcp_ethertype_enable_f893dae1"
#define VL_API_LCP_ETHERTYPE_ENABLE_REPLY_CRC "lcp_ethertype_enable_reply_e8d4e804"
#define VL_API_LCP_ETHERTYPE_GET_CRC "lcp_ethertype_get_51077d14"
#define VL_API_LCP_ETHERTYPE_GET_REPLY_CRC "lcp_ethertype_get_reply_db48c31e"
#define VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_CRC "lcp_itf_pair_replace_begin_51077d14"
#define VL_API_LCP_ITF_PAIR_REPLACE_BEGIN_REPLY_CRC "lcp_itf_pair_replace_begin_reply_e8d4e804"
#define VL_API_LCP_ITF_PAIR_REPLACE_END_CRC "lcp_itf_pair_replace_end_51077d14"
#define VL_API_LCP_ITF_PAIR_REPLACE_END_REPLY_CRC "lcp_itf_pair_replace_end_reply_e8d4e804"

#endif
