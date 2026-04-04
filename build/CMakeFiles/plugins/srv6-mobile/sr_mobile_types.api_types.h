#ifndef included_sr_mobile_types_api_types_h
#define included_sr_mobile_types_api_types_h
#define VL_API_SR_MOBILE_TYPES_API_VERSION_MAJOR 0
#define VL_API_SR_MOBILE_TYPES_API_VERSION_MINOR 1
#define VL_API_SR_MOBILE_TYPES_API_VERSION_PATCH 0
/* Imported API files */
typedef enum __attribute__((packed)) {
    SRV6_NHTYPE_API_NONE = 0,
    SRV6_NHTYPE_API_IPV4 = 1,
    SRV6_NHTYPE_API_IPV6 = 2,
    SRV6_NHTYPE_API_NON_IP = 3,
} vl_api_sr_mobile_nhtype_t;
STATIC_ASSERT(sizeof(vl_api_sr_mobile_nhtype_t) == sizeof(u8), "size of API enum sr_mobile_nhtype is wrong");

#endif
