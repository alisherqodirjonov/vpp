/* Imported API files */
#include <vpp/api/vpe_types.api_fromjson.h>
#ifndef included_vpe_api_fromjson_h
#define included_vpe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_show_version_t *vl_api_show_version_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_version_t);
    vl_api_show_version_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_version_reply_t *vl_api_show_version_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_version_reply_t);
    vl_api_show_version_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "program");
    if (!item) goto error;
    strncpy_s((char *)a->program, sizeof(a->program), cJSON_GetStringValue(item), sizeof(a->program) - 1);

    item = cJSON_GetObjectItem(o, "version");
    if (!item) goto error;
    strncpy_s((char *)a->version, sizeof(a->version), cJSON_GetStringValue(item), sizeof(a->version) - 1);

    item = cJSON_GetObjectItem(o, "build_date");
    if (!item) goto error;
    strncpy_s((char *)a->build_date, sizeof(a->build_date), cJSON_GetStringValue(item), sizeof(a->build_date) - 1);

    item = cJSON_GetObjectItem(o, "build_directory");
    if (!item) goto error;
    strncpy_s((char *)a->build_directory, sizeof(a->build_directory), cJSON_GetStringValue(item), sizeof(a->build_directory) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_vpe_system_time_t *vl_api_show_vpe_system_time_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_vpe_system_time_t);
    vl_api_show_vpe_system_time_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_vpe_system_time_reply_t *vl_api_show_vpe_system_time_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_vpe_system_time_reply_t);
    vl_api_show_vpe_system_time_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vpe_system_time");
    if (!item) goto error;
    if (vl_api_timestamp_t_fromjson((void **)&a, &l, item, &a->vpe_system_time) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_log_dump_t *vl_api_log_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_log_dump_t);
    vl_api_log_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "start_timestamp");
    if (!item) goto error;
    if (vl_api_timestamp_t_fromjson((void **)&a, &l, item, &a->start_timestamp) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_log_details_t *vl_api_log_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_log_details_t);
    vl_api_log_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "timestamp");
    if (!item) goto error;
    if (vl_api_timestamp_t_fromjson((void **)&a, &l, item, &a->timestamp) < 0) goto error;

    item = cJSON_GetObjectItem(o, "level");
    if (!item) goto error;
    if (vl_api_log_level_t_fromjson((void **)&a, &l, item, &a->level) < 0) goto error;

    item = cJSON_GetObjectItem(o, "msg_class");
    if (!item) goto error;
    strncpy_s((char *)a->msg_class, sizeof(a->msg_class), cJSON_GetStringValue(item), sizeof(a->msg_class) - 1);

    item = cJSON_GetObjectItem(o, "message");
    if (!item) goto error;
    strncpy_s((char *)a->message, sizeof(a->message), cJSON_GetStringValue(item), sizeof(a->message) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
