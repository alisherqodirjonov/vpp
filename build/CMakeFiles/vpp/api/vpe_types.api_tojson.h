/* Imported API files */
#ifndef included_vpe_types_api_tojson_h
#define included_vpe_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_version_t_tojson (vl_api_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    cJSON_AddNumberToObject(o, "patch", a->patch);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->pre_release, 17);
    cJSON_AddStringToObject(o, "pre_release", s);
    vec_free(s);
    }
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->build_metadata, 17);
    cJSON_AddStringToObject(o, "build_metadata", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_timestamp_t_tojson (vl_api_timestamp_t *a) {
    char *s = format_c_string(0, "%U", format_vl_api_timestamp_t, a);
    cJSON *o = cJSON_CreateString(s);
    vec_free(s);
    return o;
}
static inline cJSON *vl_api_timedelta_t_tojson (vl_api_timedelta_t *a) {
    char *s = format_c_string(0, "%U", format_vl_api_timedelta_t, a);
    cJSON *o = cJSON_CreateString(s);
    vec_free(s);
    return o;
}
static inline cJSON *vl_api_log_level_t_tojson (vl_api_log_level_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_EMERG");
    case 1:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_ALERT");
    case 2:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_CRIT");
    case 3:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_ERR");
    case 4:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_WARNING");
    case 5:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_NOTICE");
    case 6:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_INFO");
    case 7:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_DEBUG");
    case 8:
        return cJSON_CreateString("VPE_API_LOG_LEVEL_DISABLED");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
#endif
