#ifndef included_dev_api_types_h
#define included_dev_api_types_h
#define VL_API_DEV_API_VERSION_MAJOR 0
#define VL_API_DEV_API_VERSION_MINOR 0
#define VL_API_DEV_API_VERSION_PATCH 1
/* Imported API files */
typedef enum {
    VL_API_DEV_FLAG_NO_STATS = 1,
} vl_api_dev_flags_t;
typedef enum {
    VL_API_DEV_PORT_FLAG_INTERRUPT_MODE = 1,
    VL_API_DEV_PORT_FLAG_CONSISTENT_QP = 2,
} vl_api_dev_port_flags_t;
typedef struct __attribute__ ((packed)) _vl_api_dev_attach {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 device_id[48];
    u8 driver_name[16];
    vl_api_dev_flags_t flags;
    vl_api_string_t args;
} vl_api_dev_attach_t;
#define VL_API_DEV_ATTACH_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dev_attach_reply {
    u16 _vl_msg_id;
    u32 context;
    u32 dev_index;
    i32 retval;
    vl_api_string_t error_string;
} vl_api_dev_attach_reply_t;
#define VL_API_DEV_ATTACH_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dev_detach {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 dev_index;
} vl_api_dev_detach_t;
#define VL_API_DEV_DETACH_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dev_detach_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_string_t error_string;
} vl_api_dev_detach_reply_t;
#define VL_API_DEV_DETACH_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dev_create_port_if {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 dev_index;
    u8 intf_name[32];
    u16 num_rx_queues;
    u16 num_tx_queues;
    u16 rx_queue_size;
    u16 tx_queue_size;
    u16 port_id;
    vl_api_dev_port_flags_t flags;
    vl_api_string_t args;
} vl_api_dev_create_port_if_t;
#define VL_API_DEV_CREATE_PORT_IF_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dev_create_port_if_reply {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sw_if_index;
    i32 retval;
    vl_api_string_t error_string;
} vl_api_dev_create_port_if_reply_t;
#define VL_API_DEV_CREATE_PORT_IF_REPLY_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_dev_remove_port_if {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 sw_if_index;
} vl_api_dev_remove_port_if_t;
#define VL_API_DEV_REMOVE_PORT_IF_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dev_remove_port_if_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    vl_api_string_t error_string;
} vl_api_dev_remove_port_if_reply_t;
#define VL_API_DEV_REMOVE_PORT_IF_REPLY_IS_CONSTANT_SIZE (0)

#define VL_API_DEV_ATTACH_CRC "dev_attach_44b725fc"
#define VL_API_DEV_ATTACH_REPLY_CRC "dev_attach_reply_6082b181"
#define VL_API_DEV_DETACH_CRC "dev_detach_afae52d6"
#define VL_API_DEV_DETACH_REPLY_CRC "dev_detach_reply_c8d74455"
#define VL_API_DEV_CREATE_PORT_IF_CRC "dev_create_port_if_dbdf06f3"
#define VL_API_DEV_CREATE_PORT_IF_REPLY_CRC "dev_create_port_if_reply_243c2374"
#define VL_API_DEV_REMOVE_PORT_IF_CRC "dev_remove_port_if_529cb13f"
#define VL_API_DEV_REMOVE_PORT_IF_REPLY_CRC "dev_remove_port_if_reply_c8d74455"

#endif
