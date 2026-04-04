#ifndef included_lb_types_api_types_h
#define included_lb_types_api_types_h
#define VL_API_LB_TYPES_API_VERSION_MAJOR 1
#define VL_API_LB_TYPES_API_VERSION_MINOR 0
#define VL_API_LB_TYPES_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef enum {
    LB_API_SRV_TYPE_CLUSTERIP = 0,
    LB_API_SRV_TYPE_NODEPORT = 1,
    LB_API_SRV_N_TYPES = 2,
} vl_api_lb_srv_type_t;
typedef enum {
    LB_API_ENCAP_TYPE_GRE4 = 0,
    LB_API_ENCAP_TYPE_GRE6 = 1,
    LB_API_ENCAP_TYPE_L3DSR = 2,
    LB_API_ENCAP_TYPE_NAT4 = 3,
    LB_API_ENCAP_TYPE_NAT6 = 4,
    LB_API_ENCAP_N_TYPES = 5,
} vl_api_lb_encap_type_t;
typedef enum {
    LB_API_LKP_SAME_IP_PORT = 0,
    LB_API_LKP_DIFF_IP_PORT = 1,
    LB_API_LKP_ALL_PORT_IP = 2,
    LB_API_LKP_N_TYPES = 3,
} vl_api_lb_lkp_type_t_t;
typedef enum {
    LB_API_VIP_TYPE_IP6_GRE6 = 0,
    LB_API_VIP_TYPE_IP6_GRE4 = 1,
    LB_API_VIP_TYPE_IP4_GRE6 = 2,
    LB_API_VIP_TYPE_IP4_GRE4 = 3,
    LB_API_VIP_TYPE_IP4_L3DSR = 4,
    LB_API_VIP_TYPE_IP4_NAT4 = 5,
    LB_API_VIP_TYPE_IP6_NAT6 = 6,
    LB_API_VIP_N_TYPES = 7,
} vl_api_lb_vip_type_t;
typedef enum {
    LB_API_NAT_PROTOCOL_UDP = 6,
    LB_API_NAT_PROTOCOL_TCP = 23,
    LB_API_NAT_PROTOCOL_ANY = 4294967295,
} vl_api_lb_nat_protocol_t;
typedef struct __attribute__ ((packed)) _vl_api_lb_vip {
    vl_api_address_with_prefix_t pfx;
    vl_api_ip_proto_t protocol;
    u16 port;
} vl_api_lb_vip_t;
#define VL_API_LB_VIP_IS_CONSTANT_SIZE (1)


#endif
