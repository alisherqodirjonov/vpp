#ifndef included_sr_pt_api_types_h
#define included_sr_pt_api_types_h
#define VL_API_SR_PT_API_VERSION_MAJOR 1
#define VL_API_SR_PT_API_VERSION_MINOR 0
#define VL_API_SR_PT_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_sr_pt_iface_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_sr_pt_iface_dump_t;
#define VL_API_SR_PT_IFACE_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_pt_iface_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u16 id;
    u8 ingress_load;
    u8 egress_load;
    u8 tts_template;
} vl_api_sr_pt_iface_details_t;
#define VL_API_SR_PT_IFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_pt_iface_add {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
    u16 id;
    u8 ingress_load;
    u8 egress_load;
    u8 tts_template;
} vl_api_sr_pt_iface_add_t;
#define VL_API_SR_PT_IFACE_ADD_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_pt_iface_add_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_pt_iface_add_reply_t;
#define VL_API_SR_PT_IFACE_ADD_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_pt_iface_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    vl_api_interface_index_t sw_if_index;
} vl_api_sr_pt_iface_del_t;
#define VL_API_SR_PT_IFACE_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_sr_pt_iface_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_sr_pt_iface_del_reply_t;
#define VL_API_SR_PT_IFACE_DEL_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_SR_PT_IFACE_DUMP_CRC "sr_pt_iface_dump_51077d14"
#define VL_API_SR_PT_IFACE_DETAILS_CRC "sr_pt_iface_details_1f472f85"
#define VL_API_SR_PT_IFACE_ADD_CRC "sr_pt_iface_add_852c0cda"
#define VL_API_SR_PT_IFACE_ADD_REPLY_CRC "sr_pt_iface_add_reply_e8d4e804"
#define VL_API_SR_PT_IFACE_DEL_CRC "sr_pt_iface_del_f9e6675e"
#define VL_API_SR_PT_IFACE_DEL_REPLY_CRC "sr_pt_iface_del_reply_e8d4e804"

#endif
