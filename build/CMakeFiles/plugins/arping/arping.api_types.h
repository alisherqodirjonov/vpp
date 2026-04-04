#ifndef included_arping_api_types_h
#define included_arping_api_types_h
#define VL_API_ARPING_API_VERSION_MAJOR 1
#define VL_API_ARPING_API_VERSION_MINOR 0
#define VL_API_ARPING_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_arping {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t address;
    vl_api_interface_index_t sw_if_index;
    bool is_garp;
    u32 repeat;
    f64 interval;
} vl_api_arping_t;
#define VL_API_ARPING_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_arping_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 reply_count;
} vl_api_arping_reply_t;
#define VL_API_ARPING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_arping_acd {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_address_t address;
    vl_api_interface_index_t sw_if_index;
    bool is_garp;
    u32 repeat;
    f64 interval;
} vl_api_arping_acd_t;
#define VL_API_ARPING_ACD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_arping_acd_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 reply_count;
    vl_api_mac_address_t mac_address;
} vl_api_arping_acd_reply_t;
#define VL_API_ARPING_ACD_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_ARPING_CRC "arping_48817482"
#define VL_API_ARPING_REPLY_CRC "arping_reply_bb9d1cbd"
#define VL_API_ARPING_ACD_CRC "arping_acd_48817482"
#define VL_API_ARPING_ACD_REPLY_CRC "arping_acd_reply_e08c3b05"

#endif
