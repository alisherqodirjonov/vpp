#ifndef included_arp_api_types_h
#define included_arp_api_types_h
#define VL_API_ARP_API_VERSION_MAJOR 1
#define VL_API_ARP_API_VERSION_MINOR 0
#define VL_API_ARP_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_proxy_arp {
    u32 table_id;
    vl_api_ip4_address_t low;
    vl_api_ip4_address_t hi;
} vl_api_proxy_arp_t;
#define VL_API_PROXY_ARP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_proxy_arp_t proxy;
} vl_api_proxy_arp_add_del_t;
#define VL_API_PROXY_ARP_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_proxy_arp_add_del_reply_t;
#define VL_API_PROXY_ARP_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_proxy_arp_dump_t;
#define VL_API_PROXY_ARP_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_proxy_arp_t proxy;
} vl_api_proxy_arp_details_t;
#define VL_API_PROXY_ARP_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_intfc_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    bool enable;
} vl_api_proxy_arp_intfc_enable_disable_t;
#define VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_intfc_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_proxy_arp_intfc_enable_disable_reply_t;
#define VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_intfc_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_proxy_arp_intfc_dump_t;
#define VL_API_PROXY_ARP_INTFC_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_proxy_arp_intfc_details {
    u16 _vl_msg_id;
    u32 context;
    u32 sw_if_index;
} vl_api_proxy_arp_intfc_details_t;
#define VL_API_PROXY_ARP_INTFC_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_PROXY_ARP_ADD_DEL_CRC "proxy_arp_add_del_1823c3e7"
#define VL_API_PROXY_ARP_ADD_DEL_REPLY_CRC "proxy_arp_add_del_reply_e8d4e804"
#define VL_API_PROXY_ARP_DUMP_CRC "proxy_arp_dump_51077d14"
#define VL_API_PROXY_ARP_DETAILS_CRC "proxy_arp_details_5b948673"
#define VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_CRC "proxy_arp_intfc_enable_disable_ae6cfcfb"
#define VL_API_PROXY_ARP_INTFC_ENABLE_DISABLE_REPLY_CRC "proxy_arp_intfc_enable_disable_reply_e8d4e804"
#define VL_API_PROXY_ARP_INTFC_DUMP_CRC "proxy_arp_intfc_dump_51077d14"
#define VL_API_PROXY_ARP_INTFC_DETAILS_CRC "proxy_arp_intfc_details_f6458e5f"

#endif
