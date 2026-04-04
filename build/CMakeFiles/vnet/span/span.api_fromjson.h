/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_span_api_fromjson_h
#define included_span_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_span_state_t_fromjson(void **mp, int *len, cJSON *o, vl_api_span_state_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SPAN_STATE_API_DISABLED") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SPAN_STATE_API_RX") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SPAN_STATE_API_TX") == 0) {*a = 2; return 0;}
    if (strcmp(p, "SPAN_STATE_API_RX_TX") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_sw_interface_span_enable_disable_t *vl_api_sw_interface_span_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_span_enable_disable_t);
    vl_api_sw_interface_span_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index_from");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index_from) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index_to");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index_to) < 0) goto error;

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_span_state_t_fromjson((void **)&a, &l, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_span_enable_disable_reply_t *vl_api_sw_interface_span_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_span_enable_disable_reply_t);
    vl_api_sw_interface_span_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_span_dump_t *vl_api_sw_interface_span_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_span_dump_t);
    vl_api_sw_interface_span_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_span_details_t *vl_api_sw_interface_span_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_span_details_t);
    vl_api_sw_interface_span_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index_from");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index_from) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index_to");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index_to) < 0) goto error;

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_span_state_t_fromjson((void **)&a, &l, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_l2");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_l2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
