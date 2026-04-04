/* Imported API files */
#ifndef included_sr_mobile_types_api_fromjson_h
#define included_sr_mobile_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_sr_mobile_nhtype_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sr_mobile_nhtype_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SRV6_NHTYPE_API_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SRV6_NHTYPE_API_IPV4") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SRV6_NHTYPE_API_IPV6") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SRV6_NHTYPE_API_NON_IP") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
#endif
