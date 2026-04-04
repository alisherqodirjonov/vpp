/* Imported API files */
#ifndef included_nat_types_api_fromjson_h
#define included_nat_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_nat_timeouts_t_fromjson (void **mp, int *len, cJSON *o, vl_api_nat_timeouts_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "udp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->udp);

    item = cJSON_GetObjectItem(o, "tcp_established");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_established);

    item = cJSON_GetObjectItem(o, "tcp_transitory");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_transitory);

    item = cJSON_GetObjectItem(o, "icmp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->icmp);

    return 0;

  error:
    return -1;
}
static inline int vl_api_nat_log_level_t_fromjson(void **mp, int *len, cJSON *o, vl_api_nat_log_level_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "NAT_LOG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "NAT_LOG_ERROR") == 0) {*a = 1; return 0;}
    if (strcmp(p, "NAT_LOG_WARNING") == 0) {*a = 2; return 0;}
    if (strcmp(p, "NAT_LOG_NOTICE") == 0) {*a = 3; return 0;}
    if (strcmp(p, "NAT_LOG_INFO") == 0) {*a = 4; return 0;}
    if (strcmp(p, "NAT_LOG_DEBUG") == 0) {*a = 5; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_nat_config_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_nat_config_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "NAT_IS_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "NAT_IS_TWICE_NAT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "NAT_IS_SELF_TWICE_NAT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "NAT_IS_OUT2IN_ONLY") == 0) {*a = 4; return 0;}
    if (strcmp(p, "NAT_IS_ADDR_ONLY") == 0) {*a = 8; return 0;}
    if (strcmp(p, "NAT_IS_OUTSIDE") == 0) {*a = 16; return 0;}
    if (strcmp(p, "NAT_IS_INSIDE") == 0) {*a = 32; return 0;}
    if (strcmp(p, "NAT_IS_STATIC") == 0) {*a = 64; return 0;}
    if (strcmp(p, "NAT_IS_EXT_HOST_VALID") == 0) {*a = 128; return 0;}
    *a = 0;
    return -1;
}
#endif
