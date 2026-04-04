#ifndef included_fib_types_api_types_h
#define included_fib_types_api_types_h
#define VL_API_FIB_TYPES_API_VERSION_MAJOR 2
#define VL_API_FIB_TYPES_API_VERSION_MINOR 0
#define VL_API_FIB_TYPES_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_fib_mpls_label {
    u8 is_uniform;
    u32 label;
    u8 ttl;
    u8 exp;
} vl_api_fib_mpls_label_t;
#define VL_API_FIB_MPLS_LABEL_IS_CONSTANT_SIZE (1)

typedef enum {
    FIB_API_PATH_NH_PROTO_IP4 = 0,
    FIB_API_PATH_NH_PROTO_IP6 = 1,
    FIB_API_PATH_NH_PROTO_MPLS = 2,
    FIB_API_PATH_NH_PROTO_ETHERNET = 3,
    FIB_API_PATH_NH_PROTO_BIER = 4,
} vl_api_fib_path_nh_proto_t;
typedef enum {
    FIB_API_PATH_FLAG_NONE = 0,
    FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
    FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
    FIB_API_PATH_FLAG_POP_PW_CW = 4,
} vl_api_fib_path_flags_t;
typedef struct __attribute__ ((packed)) _vl_api_fib_path_nh {
    vl_api_address_union_t address;
    u32 via_label;
    u32 obj_id;
    u32 classify_table_index;
} vl_api_fib_path_nh_t;
#define VL_API_FIB_PATH_NH_IS_CONSTANT_SIZE (1)

typedef enum {
    FIB_API_PATH_TYPE_NORMAL = 0,
    FIB_API_PATH_TYPE_LOCAL = 1,
    FIB_API_PATH_TYPE_DROP = 2,
    FIB_API_PATH_TYPE_UDP_ENCAP = 3,
    FIB_API_PATH_TYPE_BIER_IMP = 4,
    FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
    FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
    FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
    FIB_API_PATH_TYPE_DVR = 8,
    FIB_API_PATH_TYPE_INTERFACE_RX = 9,
    FIB_API_PATH_TYPE_CLASSIFY = 10,
} vl_api_fib_path_type_t;
typedef struct __attribute__ ((packed)) _vl_api_fib_path {
    u32 sw_if_index;
    u32 table_id;
    u32 rpf_id;
    u8 weight;
    u8 preference;
    vl_api_fib_path_type_t type;
    vl_api_fib_path_flags_t flags;
    vl_api_fib_path_nh_proto_t proto;
    vl_api_fib_path_nh_t nh;
    u8 n_labels;
    vl_api_fib_mpls_label_t label_stack[16];
} vl_api_fib_path_t;
#define VL_API_FIB_PATH_IS_CONSTANT_SIZE (1)


#endif
