#ifndef included_npt66_api_types_h
#define included_npt66_api_types_h
#define VL_API_NPT66_API_VERSION_MAJOR 0
#define VL_API_NPT66_API_VERSION_MINOR 0
#define VL_API_NPT66_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_npt66_binding_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_interface_index_t sw_if_index;
    vl_api_ip6_prefix_t internal;
    vl_api_ip6_prefix_t external;
} vl_api_npt66_binding_add_del_t;
#define VL_API_NPT66_BINDING_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_npt66_binding_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_npt66_binding_add_del_reply_t;
#define VL_API_NPT66_BINDING_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_NPT66_BINDING_ADD_DEL_CRC "npt66_binding_add_del_8aa10a52"
#define VL_API_NPT66_BINDING_ADD_DEL_REPLY_CRC "npt66_binding_add_del_reply_e8d4e804"

#endif
