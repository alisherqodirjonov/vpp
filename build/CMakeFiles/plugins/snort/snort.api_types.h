#ifndef included_snort_api_types_h
#define included_snort_api_types_h
#define VL_API_SNORT_API_VERSION_MAJOR 1
#define VL_API_SNORT_API_VERSION_MINOR 0
#define VL_API_SNORT_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_snort_instance_create {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 queue_size;
    u8 drop_on_disconnect;
    vl_api_string_t name;
} vl_api_snort_instance_create_t;
#define VL_API_SNORT_INSTANCE_CREATE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_create_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 instance_index;
} vl_api_snort_instance_create_reply_t;
#define VL_API_SNORT_INSTANCE_CREATE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_delete {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 instance_index;
} vl_api_snort_instance_delete_t;
#define VL_API_SNORT_INSTANCE_DELETE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_delete_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_snort_instance_delete_reply_t;
#define VL_API_SNORT_INSTANCE_DELETE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_client_disconnect {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 snort_client_index;
} vl_api_snort_client_disconnect_t;
#define VL_API_SNORT_CLIENT_DISCONNECT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_client_disconnect_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_snort_client_disconnect_reply_t;
#define VL_API_SNORT_CLIENT_DISCONNECT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_disconnect {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 instance_index;
} vl_api_snort_instance_disconnect_t;
#define VL_API_SNORT_INSTANCE_DISCONNECT_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_disconnect_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_snort_instance_disconnect_reply_t;
#define VL_API_SNORT_INSTANCE_DISCONNECT_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_attach {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 instance_index;
    u32 sw_if_index;
    u8 snort_dir;
} vl_api_snort_interface_attach_t;
#define VL_API_SNORT_INTERFACE_ATTACH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_attach_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_snort_interface_attach_reply_t;
#define VL_API_SNORT_INTERFACE_ATTACH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_detach {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sw_if_index;
} vl_api_snort_interface_detach_t;
#define VL_API_SNORT_INTERFACE_DETACH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_detach_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_snort_interface_detach_reply_t;
#define VL_API_SNORT_INTERFACE_DETACH_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_input_mode_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_snort_input_mode_get_t;
#define VL_API_SNORT_INPUT_MODE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_input_mode_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 snort_mode;
} vl_api_snort_input_mode_get_reply_t;
#define VL_API_SNORT_INPUT_MODE_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_input_mode_set {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 input_mode;
} vl_api_snort_input_mode_set_t;
#define VL_API_SNORT_INPUT_MODE_SET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_input_mode_set_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_snort_input_mode_set_reply_t;
#define VL_API_SNORT_INPUT_MODE_SET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
    u32 instance_index;
} vl_api_snort_instance_get_t;
#define VL_API_SNORT_INSTANCE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_snort_instance_get_reply_t;
#define VL_API_SNORT_INSTANCE_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_instance_details {
    u16 _vl_msg_id;
    u32 context;
    u32 instance_index;
    u32 shm_size;
    u32 shm_fd;
    u8 drop_on_disconnect;
    u32 snort_client_index;
    vl_api_string_t name;
} vl_api_snort_instance_details_t;
#define VL_API_SNORT_INSTANCE_DETAILS_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
    u32 sw_if_index;
} vl_api_snort_interface_get_t;
#define VL_API_SNORT_INTERFACE_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_snort_interface_get_reply_t;
#define VL_API_SNORT_INTERFACE_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_interface_details {
    u16 _vl_msg_id;
    u32 context;
    u32 sw_if_index;
    u32 instance_index;
} vl_api_snort_interface_details_t;
#define VL_API_SNORT_INTERFACE_DETAILS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_client_get {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 cursor;
    u32 snort_client_index;
} vl_api_snort_client_get_t;
#define VL_API_SNORT_CLIENT_GET_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_client_get_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u32 cursor;
} vl_api_snort_client_get_reply_t;
#define VL_API_SNORT_CLIENT_GET_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_snort_client_details {
    u16 _vl_msg_id;
    u32 context;
    u32 client_index;
    u32 instance_index;
} vl_api_snort_client_details_t;
#define VL_API_SNORT_CLIENT_DETAILS_IS_CONSTANT_SIZE (1)

#define VL_API_SNORT_INSTANCE_CREATE_CRC "snort_instance_create_248cc390"
#define VL_API_SNORT_INSTANCE_CREATE_REPLY_CRC "snort_instance_create_reply_e63a3fba"
#define VL_API_SNORT_INSTANCE_DELETE_CRC "snort_instance_delete_6981211a"
#define VL_API_SNORT_INSTANCE_DELETE_REPLY_CRC "snort_instance_delete_reply_e8d4e804"
#define VL_API_SNORT_CLIENT_DISCONNECT_CRC "snort_client_disconnect_30a221a6"
#define VL_API_SNORT_CLIENT_DISCONNECT_REPLY_CRC "snort_client_disconnect_reply_e8d4e804"
#define VL_API_SNORT_INSTANCE_DISCONNECT_CRC "snort_instance_disconnect_6981211a"
#define VL_API_SNORT_INSTANCE_DISCONNECT_REPLY_CRC "snort_instance_disconnect_reply_e8d4e804"
#define VL_API_SNORT_INTERFACE_ATTACH_CRC "snort_interface_attach_79ceda89"
#define VL_API_SNORT_INTERFACE_ATTACH_REPLY_CRC "snort_interface_attach_reply_e8d4e804"
#define VL_API_SNORT_INTERFACE_DETACH_CRC "snort_interface_detach_529cb13f"
#define VL_API_SNORT_INTERFACE_DETACH_REPLY_CRC "snort_interface_detach_reply_e8d4e804"
#define VL_API_SNORT_INPUT_MODE_GET_CRC "snort_input_mode_get_51077d14"
#define VL_API_SNORT_INPUT_MODE_GET_REPLY_CRC "snort_input_mode_get_reply_a18796bf"
#define VL_API_SNORT_INPUT_MODE_SET_CRC "snort_input_mode_set_d595d008"
#define VL_API_SNORT_INPUT_MODE_SET_REPLY_CRC "snort_input_mode_set_reply_e8d4e804"
#define VL_API_SNORT_INSTANCE_GET_CRC "snort_instance_get_07c37475"
#define VL_API_SNORT_INSTANCE_GET_REPLY_CRC "snort_instance_get_reply_53b48f5d"
#define VL_API_SNORT_INSTANCE_DETAILS_CRC "snort_instance_details_abb60d49"
#define VL_API_SNORT_INTERFACE_GET_CRC "snort_interface_get_765a2424"
#define VL_API_SNORT_INTERFACE_GET_REPLY_CRC "snort_interface_get_reply_53b48f5d"
#define VL_API_SNORT_INTERFACE_DETAILS_CRC "snort_interface_details_52c75990"
#define VL_API_SNORT_CLIENT_GET_CRC "snort_client_get_51d54b70"
#define VL_API_SNORT_CLIENT_GET_REPLY_CRC "snort_client_get_reply_53b48f5d"
#define VL_API_SNORT_CLIENT_DETAILS_CRC "snort_client_details_7e29e6f5"

#endif
