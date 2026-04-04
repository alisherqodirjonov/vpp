#ifndef included_dns_api_types_h
#define included_dns_api_types_h
#define VL_API_DNS_API_VERSION_MAJOR 1
#define VL_API_DNS_API_VERSION_MINOR 0
#define VL_API_DNS_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_dns_enable_disable {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 enable;
} vl_api_dns_enable_disable_t;
#define VL_API_DNS_ENABLE_DISABLE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_enable_disable_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dns_enable_disable_reply_t;
#define VL_API_DNS_ENABLE_DISABLE_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_name_server_add_del {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 is_ip6;
    u8 is_add;
    u8 server_address[16];
} vl_api_dns_name_server_add_del_t;
#define VL_API_DNS_NAME_SERVER_ADD_DEL_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_name_server_add_del_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_dns_name_server_add_del_reply_t;
#define VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_resolve_name {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 name[256];
} vl_api_dns_resolve_name_t;
#define VL_API_DNS_RESOLVE_NAME_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_resolve_name_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 ip4_set;
    u8 ip6_set;
    u8 ip4_address[4];
    u8 ip6_address[16];
} vl_api_dns_resolve_name_reply_t;
#define VL_API_DNS_RESOLVE_NAME_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_resolve_ip {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u8 is_ip6;
    u8 address[16];
} vl_api_dns_resolve_ip_t;
#define VL_API_DNS_RESOLVE_IP_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_dns_resolve_ip_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
    u8 name[256];
} vl_api_dns_resolve_ip_reply_t;
#define VL_API_DNS_RESOLVE_IP_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_DNS_ENABLE_DISABLE_CRC "dns_enable_disable_8050327d"
#define VL_API_DNS_ENABLE_DISABLE_REPLY_CRC "dns_enable_disable_reply_e8d4e804"
#define VL_API_DNS_NAME_SERVER_ADD_DEL_CRC "dns_name_server_add_del_3bb05d8c"
#define VL_API_DNS_NAME_SERVER_ADD_DEL_REPLY_CRC "dns_name_server_add_del_reply_e8d4e804"
#define VL_API_DNS_RESOLVE_NAME_CRC "dns_resolve_name_c6566676"
#define VL_API_DNS_RESOLVE_NAME_REPLY_CRC "dns_resolve_name_reply_c2d758c3"
#define VL_API_DNS_RESOLVE_IP_CRC "dns_resolve_ip_ae96a1a3"
#define VL_API_DNS_RESOLVE_IP_REPLY_CRC "dns_resolve_ip_reply_49ed78d6"

#endif
