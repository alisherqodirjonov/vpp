#ifndef included_rd_cp_api_types_h
#define included_rd_cp_api_types_h
#define VL_API_RD_CP_API_VERSION_MAJOR 1
#define VL_API_RD_CP_API_VERSION_MINOR 0
#define VL_API_RD_CP_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_ip6_nd_address_autoconfig {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enable;
    bool install_default_routes;
} vl_api_ip6_nd_address_autoconfig_t;
#define VL_API_IP6_ND_ADDRESS_AUTOCONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_nd_address_autoconfig_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip6_nd_address_autoconfig_reply_t;
#define VL_API_IP6_ND_ADDRESS_AUTOCONFIG_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_IP6_ND_ADDRESS_AUTOCONFIG_CRC "ip6_nd_address_autoconfig_9e14a4a7"
#define VL_API_IP6_ND_ADDRESS_AUTOCONFIG_REPLY_CRC "ip6_nd_address_autoconfig_reply_e8d4e804"

#endif
