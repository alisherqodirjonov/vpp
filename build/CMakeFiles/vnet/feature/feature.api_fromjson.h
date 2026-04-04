/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_feature_api_fromjson_h
#define included_feature_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_feature_enable_disable_t *vl_api_feature_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_feature_enable_disable_t);
    vl_api_feature_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "arc_name");
    if (!item) goto error;
    strncpy_s((char *)a->arc_name, sizeof(a->arc_name), cJSON_GetStringValue(item), sizeof(a->arc_name) - 1);

    item = cJSON_GetObjectItem(o, "feature_name");
    if (!item) goto error;
    strncpy_s((char *)a->feature_name, sizeof(a->feature_name), cJSON_GetStringValue(item), sizeof(a->feature_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_feature_enable_disable_reply_t *vl_api_feature_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_feature_enable_disable_reply_t);
    vl_api_feature_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_feature_is_enabled_t *vl_api_feature_is_enabled_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_feature_is_enabled_t);
    vl_api_feature_is_enabled_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "arc_name");
    if (!item) goto error;
    strncpy_s((char *)a->arc_name, sizeof(a->arc_name), cJSON_GetStringValue(item), sizeof(a->arc_name) - 1);

    item = cJSON_GetObjectItem(o, "feature_name");
    if (!item) goto error;
    strncpy_s((char *)a->feature_name, sizeof(a->feature_name), cJSON_GetStringValue(item), sizeof(a->feature_name) - 1);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_feature_is_enabled_reply_t *vl_api_feature_is_enabled_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_feature_is_enabled_reply_t);
    vl_api_feature_is_enabled_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enabled);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
