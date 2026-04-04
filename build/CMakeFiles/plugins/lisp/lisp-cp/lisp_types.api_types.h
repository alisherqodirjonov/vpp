#ifndef included_lisp_types_api_types_h
#define included_lisp_types_api_types_h
#define VL_API_LISP_TYPES_API_VERSION_MAJOR 1
#define VL_API_LISP_TYPES_API_VERSION_MINOR 0
#define VL_API_LISP_TYPES_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/interface_types.api_types.h>
#include <vnet/ethernet/ethernet_types.api_types.h>
#include <vnet/ip/ip_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_local_locator {
    vl_api_interface_index_t sw_if_index;
    u8 priority;
    u8 weight;
} vl_api_local_locator_t;
#define VL_API_LOCAL_LOCATOR_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_remote_locator {
    u8 priority;
    u8 weight;
    vl_api_address_t ip_address;
} vl_api_remote_locator_t;
#define VL_API_REMOTE_LOCATOR_IS_CONSTANT_SIZE (1)

typedef enum __attribute__((packed)) {
    EID_TYPE_API_PREFIX = 0,
    EID_TYPE_API_MAC = 1,
    EID_TYPE_API_NSH = 2,
} vl_api_eid_type_t;
STATIC_ASSERT(sizeof(vl_api_eid_type_t) == sizeof(u8), "size of API enum eid_type is wrong");
typedef struct __attribute__ ((packed)) _vl_api_nsh {
    u32 spi;
    u8 si;
} vl_api_nsh_t;
#define VL_API_NSH_IS_CONSTANT_SIZE (1)

typedef union __attribute__ ((packed)) _vl_api_eid_address {
    vl_api_prefix_t prefix;
    vl_api_mac_address_t mac;
    vl_api_nsh_t nsh;
} vl_api_eid_address_t;
#define VL_API_EID_ADDRESS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_eid {
    vl_api_eid_type_t type;
    vl_api_eid_address_t address;
} vl_api_eid_t;
#define VL_API_EID_IS_CONSTANT_SIZE (1)

typedef enum __attribute__((packed)) {
    KEY_ID_API_HMAC_NO_KEY = 0,
    KEY_ID_API_HMAC_SHA_1_96 = 1,
    KEY_ID_API_HMAC_SHA_256_128 = 2,
} vl_api_hmac_key_id_t;
STATIC_ASSERT(sizeof(vl_api_hmac_key_id_t) == sizeof(u8), "size of API enum hmac_key_id is wrong");
typedef struct __attribute__ ((packed)) _vl_api_hmac_key {
    vl_api_hmac_key_id_t id;
    u8 key[64];
} vl_api_hmac_key_t;
#define VL_API_HMAC_KEY_IS_CONSTANT_SIZE (1)


#endif
