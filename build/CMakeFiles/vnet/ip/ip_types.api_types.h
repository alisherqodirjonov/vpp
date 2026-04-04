#ifndef included_ip_types_api_types_h
#define included_ip_types_api_types_h
#define VL_API_IP_TYPES_API_VERSION_MAJOR 3
#define VL_API_IP_TYPES_API_VERSION_MINOR 0
#define VL_API_IP_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef u8 vl_api_ip4_address_t[4];
typedef u8 vl_api_ip6_address_t[16];
typedef enum __attribute__((packed)) {
    ADDRESS_IP4 = 0,
    ADDRESS_IP6 = 1,
} vl_api_address_family_t;
STATIC_ASSERT(sizeof(vl_api_address_family_t) == sizeof(u8), "size of API enum address_family is wrong");
typedef enum __attribute__((packed)) {
    IP_API_FEATURE_INPUT = 0,
    IP_API_FEATURE_OUTPUT = 1,
    IP_API_FEATURE_LOCAL = 2,
    IP_API_FEATURE_PUNT = 3,
    IP_API_FEATURE_DROP = 4,
} vl_api_ip_feature_location_t;
STATIC_ASSERT(sizeof(vl_api_ip_feature_location_t) == sizeof(u8), "size of API enum ip_feature_location is wrong");
typedef enum __attribute__((packed)) {
    IP_API_ECN_NONE = 0,
    IP_API_ECN_ECT0 = 1,
    IP_API_ECN_ECT1 = 2,
    IP_API_ECN_CE = 3,
} vl_api_ip_ecn_t;
STATIC_ASSERT(sizeof(vl_api_ip_ecn_t) == sizeof(u8), "size of API enum ip_ecn is wrong");
typedef enum __attribute__((packed)) {
    IP_API_DSCP_CS0 = 0,
    IP_API_DSCP_CS1 = 8,
    IP_API_DSCP_AF11 = 10,
    IP_API_DSCP_AF12 = 12,
    IP_API_DSCP_AF13 = 14,
    IP_API_DSCP_CS2 = 16,
    IP_API_DSCP_AF21 = 18,
    IP_API_DSCP_AF22 = 20,
    IP_API_DSCP_AF23 = 22,
    IP_API_DSCP_CS3 = 24,
    IP_API_DSCP_AF31 = 26,
    IP_API_DSCP_AF32 = 28,
    IP_API_DSCP_AF33 = 30,
    IP_API_DSCP_CS4 = 32,
    IP_API_DSCP_AF41 = 34,
    IP_API_DSCP_AF42 = 36,
    IP_API_DSCP_AF43 = 38,
    IP_API_DSCP_CS5 = 40,
    IP_API_DSCP_EF = 46,
    IP_API_DSCP_CS6 = 48,
    IP_API_DSCP_CS7 = 50,
} vl_api_ip_dscp_t;
STATIC_ASSERT(sizeof(vl_api_ip_dscp_t) == sizeof(u8), "size of API enum ip_dscp is wrong");
typedef enum __attribute__((packed)) {
    IP_API_PROTO_HOPOPT = 0,
    IP_API_PROTO_ICMP = 1,
    IP_API_PROTO_IGMP = 2,
    IP_API_PROTO_TCP = 6,
    IP_API_PROTO_UDP = 17,
    IP_API_PROTO_GRE = 47,
    IP_API_PROTO_ESP = 50,
    IP_API_PROTO_AH = 51,
    IP_API_PROTO_ICMP6 = 58,
    IP_API_PROTO_EIGRP = 88,
    IP_API_PROTO_OSPF = 89,
    IP_API_PROTO_SCTP = 132,
    IP_API_PROTO_RESERVED = 255,
} vl_api_ip_proto_t;
STATIC_ASSERT(sizeof(vl_api_ip_proto_t) == sizeof(u8), "size of API enum ip_proto is wrong");
typedef union __attribute__ ((packed)) _vl_api_address_union {
    vl_api_ip4_address_t ip4;
    vl_api_ip6_address_t ip6;
} vl_api_address_union_t;
#define VL_API_ADDRESS_UNION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_address {
    vl_api_address_family_t af;
    vl_api_address_union_t un;
} vl_api_address_t;
#define VL_API_ADDRESS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_prefix {
    vl_api_address_t address;
    u8 len;
} vl_api_prefix_t;
#define VL_API_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip4_address_and_mask {
    vl_api_ip4_address_t addr;
    vl_api_ip4_address_t mask;
} vl_api_ip4_address_and_mask_t;
#define VL_API_IP4_ADDRESS_AND_MASK_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_address_and_mask {
    vl_api_ip6_address_t addr;
    vl_api_ip6_address_t mask;
} vl_api_ip6_address_and_mask_t;
#define VL_API_IP6_ADDRESS_AND_MASK_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_mprefix {
    vl_api_address_family_t af;
    u16 grp_address_length;
    vl_api_address_union_t grp_address;
    vl_api_address_union_t src_address;
} vl_api_mprefix_t;
#define VL_API_MPREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip6_prefix {
    vl_api_ip6_address_t address;
    u8 len;
} vl_api_ip6_prefix_t;
#define VL_API_IP6_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ip4_prefix {
    vl_api_ip4_address_t address;
    u8 len;
} vl_api_ip4_prefix_t;
#define VL_API_IP4_PREFIX_IS_CONSTANT_SIZE (1)

typedef vl_api_prefix_t vl_api_address_with_prefix_t;
typedef vl_api_ip4_prefix_t vl_api_ip4_address_with_prefix_t;
typedef vl_api_ip6_prefix_t vl_api_ip6_address_with_prefix_t;
typedef struct __attribute__ ((packed)) _vl_api_prefix_matcher {
    u8 le;
    u8 ge;
} vl_api_prefix_matcher_t;
#define VL_API_PREFIX_MATCHER_IS_CONSTANT_SIZE (1)


#endif
