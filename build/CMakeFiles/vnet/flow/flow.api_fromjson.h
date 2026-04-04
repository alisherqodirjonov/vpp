/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/flow/flow_types.api_fromjson.h>
#ifndef included_flow_api_fromjson_h
#define included_flow_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_flow_add_t *vl_api_flow_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_add_t);
    vl_api_flow_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flow");
    if (!item) goto error;
    if (vl_api_flow_rule_t_fromjson((void **)&a, &l, item, &a->flow) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_add_v2_t *vl_api_flow_add_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_add_v2_t);
    vl_api_flow_add_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flow");
    if (!item) goto error;
    if (vl_api_flow_rule_v2_t_fromjson((void **)&a, &l, item, &a->flow) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_add_reply_t *vl_api_flow_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_add_reply_t);
    vl_api_flow_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "flow_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flow_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_add_v2_reply_t *vl_api_flow_add_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_add_v2_reply_t);
    vl_api_flow_add_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "flow_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flow_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_del_t *vl_api_flow_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_del_t);
    vl_api_flow_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flow_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flow_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_del_reply_t *vl_api_flow_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_del_reply_t);
    vl_api_flow_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_enable_t *vl_api_flow_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_enable_t);
    vl_api_flow_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flow_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flow_index);

    item = cJSON_GetObjectItem(o, "hw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->hw_if_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_enable_reply_t *vl_api_flow_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_enable_reply_t);
    vl_api_flow_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_disable_t *vl_api_flow_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_disable_t);
    vl_api_flow_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flow_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flow_index);

    item = cJSON_GetObjectItem(o, "hw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->hw_if_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_flow_disable_reply_t *vl_api_flow_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_flow_disable_reply_t);
    vl_api_flow_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
