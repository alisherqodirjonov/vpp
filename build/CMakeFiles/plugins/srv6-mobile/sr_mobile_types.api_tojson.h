/* Imported API files */
#ifndef included_sr_mobile_types_api_tojson_h
#define included_sr_mobile_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sr_mobile_nhtype_t_tojson (vl_api_sr_mobile_nhtype_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SRV6_NHTYPE_API_NONE");
    case 1:
        return cJSON_CreateString("SRV6_NHTYPE_API_IPV4");
    case 2:
        return cJSON_CreateString("SRV6_NHTYPE_API_IPV6");
    case 3:
        return cJSON_CreateString("SRV6_NHTYPE_API_NON_IP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
#endif
