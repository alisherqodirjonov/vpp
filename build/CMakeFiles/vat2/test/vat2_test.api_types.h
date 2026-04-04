#ifndef included_vat2_test_api_types_h
#define included_vat2_test_api_types_h
#define VL_API_VAT2_TEST_API_VERSION_MAJOR 0
#define VL_API_VAT2_TEST_API_VERSION_MINOR 0
#define VL_API_VAT2_TEST_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef enum {
    RED = 1,
    BLUE = 2,
    GREEN = 4,
} vl_api_test_enumflags_t;
typedef struct __attribute__ ((packed)) _vl_api_test_stringtype {
    vl_api_string_t str;
} vl_api_test_stringtype_t;
#define VL_API_TEST_STRINGTYPE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vlatype {
    u32 data;
} vl_api_test_vlatype_t;
#define VL_API_TEST_VLATYPE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_vlatype2 {
    u32 count;
    u32 vla[0];
} vl_api_test_vlatype2_t;
#define VL_API_TEST_VLATYPE2_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vlatype3 {
    u32 count;
    u8 vla[0];
} vl_api_test_vlatype3_t;
#define VL_API_TEST_VLATYPE3_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_prefix {
    u16 _vl_msg_id;
    vl_api_prefix_t pref;
} vl_api_test_prefix_t;
#define VL_API_TEST_PREFIX_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_prefix_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_prefix_reply_t;
#define VL_API_TEST_PREFIX_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_enum {
    u16 _vl_msg_id;
    vl_api_test_enumflags_t flags;
} vl_api_test_enum_t;
#define VL_API_TEST_ENUM_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_enum_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_enum_reply_t;
#define VL_API_TEST_ENUM_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_string {
    u16 _vl_msg_id;
    vl_api_test_stringtype_t str;
} vl_api_test_string_t;
#define VL_API_TEST_STRING_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_string_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_string_reply_t;
#define VL_API_TEST_STRING_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_string2 {
    u16 _vl_msg_id;
    vl_api_string_t str;
} vl_api_test_string2_t;
#define VL_API_TEST_STRING2_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_string2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_string2_reply_t;
#define VL_API_TEST_STRING2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_vla {
    u16 _vl_msg_id;
    u32 count;
    u32 vla[0];
} vl_api_test_vla_t;
#define VL_API_TEST_VLA_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vla_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_vla_reply_t;
#define VL_API_TEST_VLA_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_vla2 {
    u16 _vl_msg_id;
    u32 count;
    u8 vla[0];
} vl_api_test_vla2_t;
#define VL_API_TEST_VLA2_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vla2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_vla2_reply_t;
#define VL_API_TEST_VLA2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_vla3 {
    u16 _vl_msg_id;
    u32 count;
    vl_api_test_vlatype_t vla[0];
} vl_api_test_vla3_t;
#define VL_API_TEST_VLA3_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vla3_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_vla3_reply_t;
#define VL_API_TEST_VLA3_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_vla4 {
    u16 _vl_msg_id;
    vl_api_test_vlatype2_t data;
} vl_api_test_vla4_t;
#define VL_API_TEST_VLA4_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vla4_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_vla4_reply_t;
#define VL_API_TEST_VLA4_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_vla5 {
    u16 _vl_msg_id;
    vl_api_test_vlatype3_t data;
} vl_api_test_vla5_t;
#define VL_API_TEST_VLA5_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_vla5_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_vla5_reply_t;
#define VL_API_TEST_VLA5_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_addresses {
    u16 _vl_msg_id;
    vl_api_address_t a;
} vl_api_test_addresses_t;
#define VL_API_TEST_ADDRESSES_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_addresses_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_addresses_reply_t;
#define VL_API_TEST_ADDRESSES_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_addresses2 {
    u16 _vl_msg_id;
    vl_api_address_t a[2];
} vl_api_test_addresses2_t;
#define VL_API_TEST_ADDRESSES2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_addresses2_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_addresses2_reply_t;
#define VL_API_TEST_ADDRESSES2_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_addresses3 {
    u16 _vl_msg_id;
    u32 n;
    vl_api_address_t a[0];
} vl_api_test_addresses3_t;
#define VL_API_TEST_ADDRESSES3_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_test_addresses3_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_addresses3_reply_t;
#define VL_API_TEST_ADDRESSES3_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_empty {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
} vl_api_test_empty_t;
#define VL_API_TEST_EMPTY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_empty_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_empty_reply_t;
#define VL_API_TEST_EMPTY_REPLY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_interface {
    u16 _vl_msg_id;
    vl_api_interface_index_t sw_if_index;
} vl_api_test_interface_t;
#define VL_API_TEST_INTERFACE_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_test_interface_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_test_interface_reply_t;
#define VL_API_TEST_INTERFACE_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_TEST_PREFIX_CRC "test_prefix_d866c1a9"
#define VL_API_TEST_PREFIX_REPLY_CRC "test_prefix_reply_e8d4e804"
#define VL_API_TEST_ENUM_CRC "test_enum_e3190a2e"
#define VL_API_TEST_ENUM_REPLY_CRC "test_enum_reply_e8d4e804"
#define VL_API_TEST_STRING_CRC "test_string_3955d673"
#define VL_API_TEST_STRING_REPLY_CRC "test_string_reply_e8d4e804"
#define VL_API_TEST_STRING2_CRC "test_string2_64a8785b"
#define VL_API_TEST_STRING2_REPLY_CRC "test_string2_reply_e8d4e804"
#define VL_API_TEST_VLA_CRC "test_vla_5d944dfc"
#define VL_API_TEST_VLA_REPLY_CRC "test_vla_reply_e8d4e804"
#define VL_API_TEST_VLA2_CRC "test_vla2_471f6687"
#define VL_API_TEST_VLA2_REPLY_CRC "test_vla2_reply_e8d4e804"
#define VL_API_TEST_VLA3_CRC "test_vla3_bac4a968"
#define VL_API_TEST_VLA3_REPLY_CRC "test_vla3_reply_e8d4e804"
#define VL_API_TEST_VLA4_CRC "test_vla4_c061d9d1"
#define VL_API_TEST_VLA4_REPLY_CRC "test_vla4_reply_e8d4e804"
#define VL_API_TEST_VLA5_CRC "test_vla5_09b0e1f3"
#define VL_API_TEST_VLA5_REPLY_CRC "test_vla5_reply_e8d4e804"
#define VL_API_TEST_ADDRESSES_CRC "test_addresses_2bef955c"
#define VL_API_TEST_ADDRESSES_REPLY_CRC "test_addresses_reply_e8d4e804"
#define VL_API_TEST_ADDRESSES2_CRC "test_addresses2_ff01dd23"
#define VL_API_TEST_ADDRESSES2_REPLY_CRC "test_addresses2_reply_e8d4e804"
#define VL_API_TEST_ADDRESSES3_CRC "test_addresses3_7f3e48a1"
#define VL_API_TEST_ADDRESSES3_REPLY_CRC "test_addresses3_reply_e8d4e804"
#define VL_API_TEST_EMPTY_CRC "test_empty_51077d14"
#define VL_API_TEST_EMPTY_REPLY_CRC "test_empty_reply_e8d4e804"
#define VL_API_TEST_INTERFACE_CRC "test_interface_00e34dc0"
#define VL_API_TEST_INTERFACE_REPLY_CRC "test_interface_reply_e8d4e804"

#endif
