#ifndef included_dhcp6_pd_client_cp_api_types_h
#define included_dhcp6_pd_client_cp_api_types_h
#define VL_API_DHCP6_PD_CLIENT_CP_API_VERSION_MAJOR 2
#define VL_API_DHCP6_PD_CLIENT_CP_API_VERSION_MINOR 0
#define VL_API_DHCP6_PD_CLIENT_CP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_dhcp6_pd_client_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 prefix_group[64];
    bool enable;
} vl_api_dhcp6_pd_client_enable_disable_t;
#define VL_API_DHCP6_PD_CLIENT_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dhcp6_pd_client_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dhcp6_pd_client_enable_disable_reply_t;
#define VL_API_DHCP6_PD_CLIENT_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_add_del_address_using_prefix {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u8 prefix_group[64];
    vl_api_ip6_address_with_prefix_t address_with_prefix;
    bool is_add;
} vl_api_ip6_add_del_address_using_prefix_t;
#define VL_API_IP6_ADD_DEL_ADDRESS_USING_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_add_del_address_using_prefix_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_ip6_add_del_address_using_prefix_reply_t;
#define VL_API_IP6_ADD_DEL_ADDRESS_USING_PREFIX_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_DHCP6_PD_CLIENT_ENABLE_DISABLE_CRC "dhcp6_pd_client_enable_disable_a75a0772"
#define VL_API_DHCP6_PD_CLIENT_ENABLE_DISABLE_REPLY_CRC "dhcp6_pd_client_enable_disable_reply_e8d4e804"
#define VL_API_IP6_ADD_DEL_ADDRESS_USING_PREFIX_CRC "ip6_add_del_address_using_prefix_3982f30a"
#define VL_API_IP6_ADD_DEL_ADDRESS_USING_PREFIX_REPLY_CRC "ip6_add_del_address_using_prefix_reply_e8d4e804"

#endif
