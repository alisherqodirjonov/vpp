/* Imported API files */
#ifndef included_vpe_types_api_fromjson_h
#define included_vpe_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_version_t_fromjson (void **mp, int *len, cJSON *o, vl_api_version_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "major");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->major);

    item = cJSON_GetObjectItem(o, "minor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->minor);

    item = cJSON_GetObjectItem(o, "patch");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->patch);

    item = cJSON_GetObjectItem(o, "pre_release");
    if (!item) goto error;
    if (u8string_fromjson2(o, "pre_release", a->pre_release) < 0) goto error;

    item = cJSON_GetObjectItem(o, "build_metadata");
    if (!item) goto error;
    if (u8string_fromjson2(o, "build_metadata", a->build_metadata) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_timestamp_t_fromjson (void **mp, int *len, cJSON *o, vl_api_timestamp_t *a) {
    vl_api_f64_fromjson(o, (f64 *)a);
    return 0;
}
static inline int vl_api_timedelta_t_fromjson (void **mp, int *len, cJSON *o, vl_api_timedelta_t *a) {
    vl_api_f64_fromjson(o, (f64 *)a);
    return 0;
}
static inline int vl_api_log_level_t_fromjson(void **mp, int *len, cJSON *o, vl_api_log_level_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "VPE_API_LOG_LEVEL_EMERG") == 0) {*a = 0; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_ALERT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_CRIT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_ERR") == 0) {*a = 3; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_WARNING") == 0) {*a = 4; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_NOTICE") == 0) {*a = 5; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_INFO") == 0) {*a = 6; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_DEBUG") == 0) {*a = 7; return 0;}
    if (strcmp(p, "VPE_API_LOG_LEVEL_DISABLED") == 0) {*a = 8; return 0;}
    *a = 0;
    return -1;
}
#endif
