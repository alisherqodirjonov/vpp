/* Imported API files */
#ifndef included_trace_api_fromjson_h
#define included_trace_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_trace_profile_add_t *vl_api_trace_profile_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_profile_add_t);
    vl_api_trace_profile_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "trace_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->trace_type);

    item = cJSON_GetObjectItem(o, "num_elts");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->num_elts);

    item = cJSON_GetObjectItem(o, "trace_tsp");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->trace_tsp);

    item = cJSON_GetObjectItem(o, "node_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->node_id);

    item = cJSON_GetObjectItem(o, "app_data");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->app_data);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_profile_add_reply_t *vl_api_trace_profile_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_profile_add_reply_t);
    vl_api_trace_profile_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_profile_del_t *vl_api_trace_profile_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_profile_del_t);
    vl_api_trace_profile_del_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_trace_profile_del_reply_t *vl_api_trace_profile_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_profile_del_reply_t);
    vl_api_trace_profile_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_profile_show_config_t *vl_api_trace_profile_show_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_profile_show_config_t);
    vl_api_trace_profile_show_config_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_trace_profile_show_config_reply_t *vl_api_trace_profile_show_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_profile_show_config_reply_t);
    vl_api_trace_profile_show_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "trace_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->trace_type);

    item = cJSON_GetObjectItem(o, "num_elts");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->num_elts);

    item = cJSON_GetObjectItem(o, "trace_tsp");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->trace_tsp);

    item = cJSON_GetObjectItem(o, "node_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->node_id);

    item = cJSON_GetObjectItem(o, "app_data");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->app_data);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
