#ifndef included_abf_api_types_h
#define included_abf_api_types_h
#define VL_API_ABF_API_VERSION_MAJOR 1
#define VL_API_ABF_API_VERSION_MINOR 0
#define VL_API_ABF_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/fib/fib_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_abf_policy {
    u32 policy_id;
    u32 acl_index;
    u8 n_paths;
    vl_api_fib_path_t paths[0];
} vl_api_abf_policy_t;
#define VL_API_ABF_POLICY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_abf_itf_attach {
    u32 policy_id;
    vl_api_interface_index_t sw_if_index;
    u32 priority;
    bool is_ipv6;
} vl_api_abf_itf_attach_t;
#define VL_API_ABF_ITF_ATTACH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_plugin_get_version {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_abf_plugin_get_version_t;
#define VL_API_ABF_PLUGIN_GET_VERSION_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_plugin_get_version_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 major;
    u32 minor;
} vl_api_abf_plugin_get_version_reply_t;
#define VL_API_ABF_PLUGIN_GET_VERSION_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_policy_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_abf_policy_t policy;
} vl_api_abf_policy_add_del_t;
#define VL_API_ABF_POLICY_ADD_DEL_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_abf_policy_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_abf_policy_add_del_reply_t;
#define VL_API_ABF_POLICY_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_policy_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_abf_policy_t policy;
} vl_api_abf_policy_details_t;
#define VL_API_ABF_POLICY_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_abf_policy_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_abf_policy_dump_t;
#define VL_API_ABF_POLICY_DUMP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_itf_attach_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    bool is_add;
    vl_api_abf_itf_attach_t attach;
} vl_api_abf_itf_attach_add_del_t;
#define VL_API_ABF_ITF_ATTACH_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_itf_attach_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_abf_itf_attach_add_del_reply_t;
#define VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_itf_attach_details {
    u16 _vl_msg_id;
    u32 context;
    vl_api_abf_itf_attach_t attach;
} vl_api_abf_itf_attach_details_t;
#define VL_API_ABF_ITF_ATTACH_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_abf_itf_attach_dump {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_abf_itf_attach_dump_t;
#define VL_API_ABF_ITF_ATTACH_DUMP_IS_CONSTANT_SIZE (1)

#define VL_API_ABF_PLUGIN_GET_VERSION_CRC "abf_plugin_get_version_51077d14"
#define VL_API_ABF_PLUGIN_GET_VERSION_REPLY_CRC "abf_plugin_get_version_reply_9b32cf86"
#define VL_API_ABF_POLICY_ADD_DEL_CRC "abf_policy_add_del_c6131197"
#define VL_API_ABF_POLICY_ADD_DEL_REPLY_CRC "abf_policy_add_del_reply_e8d4e804"
#define VL_API_ABF_POLICY_DETAILS_CRC "abf_policy_details_b7487fa4"
#define VL_API_ABF_POLICY_DUMP_CRC "abf_policy_dump_51077d14"
#define VL_API_ABF_ITF_ATTACH_ADD_DEL_CRC "abf_itf_attach_add_del_25c8621b"
#define VL_API_ABF_ITF_ATTACH_ADD_DEL_REPLY_CRC "abf_itf_attach_add_del_reply_e8d4e804"
#define VL_API_ABF_ITF_ATTACH_DETAILS_CRC "abf_itf_attach_details_7819523e"
#define VL_API_ABF_ITF_ATTACH_DUMP_CRC "abf_itf_attach_dump_51077d14"

#endif
