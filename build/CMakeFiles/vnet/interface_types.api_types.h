#ifndef included_interface_types_api_types_h
#define included_interface_types_api_types_h
#define VL_API_INTERFACE_TYPES_API_VERSION_MAJOR 1
#define VL_API_INTERFACE_TYPES_API_VERSION_MINOR 0
#define VL_API_INTERFACE_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef u32 vl_api_interface_index_t;
typedef enum {
    IF_STATUS_API_FLAG_ADMIN_UP = 1,
    IF_STATUS_API_FLAG_LINK_UP = 2,
} vl_api_if_status_flags_t;
typedef enum {
    MTU_PROTO_API_L3 = 0,
    MTU_PROTO_API_IP4 = 1,
    MTU_PROTO_API_IP6 = 2,
    MTU_PROTO_API_MPLS = 3,
} vl_api_mtu_proto_t;
typedef enum {
    LINK_DUPLEX_API_UNKNOWN = 0,
    LINK_DUPLEX_API_HALF = 1,
    LINK_DUPLEX_API_FULL = 2,
} vl_api_link_duplex_t;
typedef enum {
    SUB_IF_API_FLAG_NO_TAGS = 1,
    SUB_IF_API_FLAG_ONE_TAG = 2,
    SUB_IF_API_FLAG_TWO_TAGS = 4,
    SUB_IF_API_FLAG_DOT1AD = 8,
    SUB_IF_API_FLAG_EXACT_MATCH = 16,
    SUB_IF_API_FLAG_DEFAULT = 32,
    SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
    SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
    SUB_IF_API_FLAG_MASK_VNET = 254,
    SUB_IF_API_FLAG_DOT1AH = 256,
} vl_api_sub_if_flags_t;
typedef enum {
    RX_MODE_API_UNKNOWN = 0,
    RX_MODE_API_POLLING = 1,
    RX_MODE_API_INTERRUPT = 2,
    RX_MODE_API_ADAPTIVE = 3,
    RX_MODE_API_DEFAULT = 4,
} vl_api_rx_mode_t;
typedef enum {
    IF_API_TYPE_HARDWARE = 0,
    IF_API_TYPE_SUB = 1,
    IF_API_TYPE_P2P = 2,
    IF_API_TYPE_PIPE = 3,
} vl_api_if_type_t;
typedef enum __attribute__((packed)) {
    RX = 0,
    TX = 1,
} vl_api_direction_t;
STATIC_ASSERT(sizeof(vl_api_direction_t) == sizeof(u8), "size of API enum direction is wrong");

#endif
