#ifndef included_ioam_vxlan_gpe_api_types_h
#define included_ioam_vxlan_gpe_api_types_h
#define VL_API_IOAM_VXLAN_GPE_API_VERSION_MAJOR 1
#define VL_API_IOAM_VXLAN_GPE_API_VERSION_MINOR 0
#define VL_API_IOAM_VXLAN_GPE_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 id;
    u8 trace_ppc;
    bool pow_enable;
    bool trace_enable;
} vl_api_vxlan_gpe_ioam_enable_t;
#define VL_API_VXLAN_GPE_IOAM_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vxlan_gpe_ioam_enable_reply_t;
#define VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u16 id;
} vl_api_vxlan_gpe_ioam_disable_t;
#define VL_API_VXLAN_GPE_IOAM_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vxlan_gpe_ioam_disable_reply_t;
#define VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_vni_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 vni;
    vl_api_address_t local;
    vl_api_address_t remote;
} vl_api_vxlan_gpe_ioam_vni_enable_t;
#define VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_vni_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vxlan_gpe_ioam_vni_enable_reply_t;
#define VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_vni_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 vni;
    vl_api_address_t local;
    vl_api_address_t remote;
} vl_api_vxlan_gpe_ioam_vni_disable_t;
#define VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_vni_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vxlan_gpe_ioam_vni_disable_reply_t;
#define VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_transit_enable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 outer_fib_index;
    vl_api_address_t dst_addr;
} vl_api_vxlan_gpe_ioam_transit_enable_t;
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_transit_enable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vxlan_gpe_ioam_transit_enable_reply_t;
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_transit_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 outer_fib_index;
    vl_api_address_t dst_addr;
} vl_api_vxlan_gpe_ioam_transit_disable_t;
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_vxlan_gpe_ioam_transit_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_vxlan_gpe_ioam_transit_disable_reply_t;
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_VXLAN_GPE_IOAM_ENABLE_CRC "vxlan_gpe_ioam_enable_2481bef7"
#define VL_API_VXLAN_GPE_IOAM_ENABLE_REPLY_CRC "vxlan_gpe_ioam_enable_reply_e8d4e804"
#define VL_API_VXLAN_GPE_IOAM_DISABLE_CRC "vxlan_gpe_ioam_disable_6b16a45e"
#define VL_API_VXLAN_GPE_IOAM_DISABLE_REPLY_CRC "vxlan_gpe_ioam_disable_reply_e8d4e804"
#define VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_CRC "vxlan_gpe_ioam_vni_enable_0fbb5fb1"
#define VL_API_VXLAN_GPE_IOAM_VNI_ENABLE_REPLY_CRC "vxlan_gpe_ioam_vni_enable_reply_e8d4e804"
#define VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_CRC "vxlan_gpe_ioam_vni_disable_0fbb5fb1"
#define VL_API_VXLAN_GPE_IOAM_VNI_DISABLE_REPLY_CRC "vxlan_gpe_ioam_vni_disable_reply_e8d4e804"
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_CRC "vxlan_gpe_ioam_transit_enable_3d3ec657"
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_ENABLE_REPLY_CRC "vxlan_gpe_ioam_transit_enable_reply_e8d4e804"
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_CRC "vxlan_gpe_ioam_transit_disable_3d3ec657"
#define VL_API_VXLAN_GPE_IOAM_TRANSIT_DISABLE_REPLY_CRC "vxlan_gpe_ioam_transit_disable_reply_e8d4e804"

#endif
