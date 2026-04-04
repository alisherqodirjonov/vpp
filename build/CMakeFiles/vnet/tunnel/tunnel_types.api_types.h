#ifndef included_tunnel_types_api_types_h
#define included_tunnel_types_api_types_h
#define VL_API_TUNNEL_TYPES_API_VERSION_MAJOR 1
#define VL_API_TUNNEL_TYPES_API_VERSION_MINOR 0
#define VL_API_TUNNEL_TYPES_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef enum __attribute__((packed)) {
    TUNNEL_API_ENCAP_DECAP_FLAG_NONE = 0,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF = 1,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF = 2,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP = 4,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN = 8,
    TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN = 16,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH = 32,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT = 64,
    TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL = 128,
} vl_api_tunnel_encap_decap_flags_t;
STATIC_ASSERT(sizeof(vl_api_tunnel_encap_decap_flags_t) == sizeof(u8), "size of API enum tunnel_encap_decap_flags is wrong");
typedef enum __attribute__((packed)) {
    TUNNEL_API_MODE_P2P = 0,
    TUNNEL_API_MODE_MP = 1,
} vl_api_tunnel_mode_t;
STATIC_ASSERT(sizeof(vl_api_tunnel_mode_t) == sizeof(u8), "size of API enum tunnel_mode is wrong");
typedef enum __attribute__((packed)) {
    TUNNEL_API_FLAG_TRACK_MTU = 1,
} vl_api_tunnel_flags_t;
STATIC_ASSERT(sizeof(vl_api_tunnel_flags_t) == sizeof(u8), "size of API enum tunnel_flags is wrong");
typedef struct __attribute__ ((packed)) _vl_api_tunnel {
    u32 instance;
    vl_api_address_t src;
    vl_api_address_t dst;
    vl_api_interface_index_t sw_if_index;
    u32 table_id;
    vl_api_tunnel_encap_decap_flags_t encap_decap_flags;
    vl_api_tunnel_mode_t mode;
    vl_api_tunnel_flags_t flags;
    vl_api_ip_dscp_t dscp;
    u8 hop_limit;
} vl_api_tunnel_t;
#define VL_API_TUNNEL_IS_CONSTANT_SIZE (1)


#endif
