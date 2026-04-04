/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_sflow_api_fromjson_h
#define included_sflow_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_sflow_enable_disable_t *vl_api_sflow_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_enable_disable_t);
    vl_api_sflow_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "hw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->hw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_enable_disable_reply_t *vl_api_sflow_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_enable_disable_reply_t);
    vl_api_sflow_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_sampling_rate_get_t *vl_api_sflow_sampling_rate_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_sampling_rate_get_t);
    vl_api_sflow_sampling_rate_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sflow_sampling_rate_get_reply_t *vl_api_sflow_sampling_rate_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_sampling_rate_get_reply_t);
    vl_api_sflow_sampling_rate_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sampling_N");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sampling_N);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_sampling_rate_set_t *vl_api_sflow_sampling_rate_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_sampling_rate_set_t);
    vl_api_sflow_sampling_rate_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sampling_N");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sampling_N);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_sampling_rate_set_reply_t *vl_api_sflow_sampling_rate_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_sampling_rate_set_reply_t);
    vl_api_sflow_sampling_rate_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_polling_interval_set_t *vl_api_sflow_polling_interval_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_polling_interval_set_t);
    vl_api_sflow_polling_interval_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "polling_S");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->polling_S);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_polling_interval_set_reply_t *vl_api_sflow_polling_interval_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_polling_interval_set_reply_t);
    vl_api_sflow_polling_interval_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_polling_interval_get_t *vl_api_sflow_polling_interval_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_polling_interval_get_t);
    vl_api_sflow_polling_interval_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sflow_polling_interval_get_reply_t *vl_api_sflow_polling_interval_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_polling_interval_get_reply_t);
    vl_api_sflow_polling_interval_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "polling_S");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->polling_S);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_header_bytes_set_t *vl_api_sflow_header_bytes_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_header_bytes_set_t);
    vl_api_sflow_header_bytes_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "header_B");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->header_B);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_header_bytes_set_reply_t *vl_api_sflow_header_bytes_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_header_bytes_set_reply_t);
    vl_api_sflow_header_bytes_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_header_bytes_get_t *vl_api_sflow_header_bytes_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_header_bytes_get_t);
    vl_api_sflow_header_bytes_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sflow_header_bytes_get_reply_t *vl_api_sflow_header_bytes_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_header_bytes_get_reply_t);
    vl_api_sflow_header_bytes_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "header_B");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->header_B);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_direction_set_t *vl_api_sflow_direction_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_direction_set_t);
    vl_api_sflow_direction_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sampling_D");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sampling_D);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_direction_set_reply_t *vl_api_sflow_direction_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_direction_set_reply_t);
    vl_api_sflow_direction_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_direction_get_t *vl_api_sflow_direction_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_direction_get_t);
    vl_api_sflow_direction_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sflow_direction_get_reply_t *vl_api_sflow_direction_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_direction_get_reply_t);
    vl_api_sflow_direction_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sampling_D");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sampling_D);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_drop_monitoring_set_t *vl_api_sflow_drop_monitoring_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_drop_monitoring_set_t);
    vl_api_sflow_drop_monitoring_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "drop_M");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->drop_M);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_drop_monitoring_set_reply_t *vl_api_sflow_drop_monitoring_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_drop_monitoring_set_reply_t);
    vl_api_sflow_drop_monitoring_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_drop_monitoring_get_t *vl_api_sflow_drop_monitoring_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_drop_monitoring_get_t);
    vl_api_sflow_drop_monitoring_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sflow_drop_monitoring_get_reply_t *vl_api_sflow_drop_monitoring_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_drop_monitoring_get_reply_t);
    vl_api_sflow_drop_monitoring_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "drop_M");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->drop_M);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_interface_dump_t *vl_api_sflow_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_interface_dump_t);
    vl_api_sflow_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "hw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->hw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sflow_interface_details_t *vl_api_sflow_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sflow_interface_details_t);
    vl_api_sflow_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "hw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->hw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
