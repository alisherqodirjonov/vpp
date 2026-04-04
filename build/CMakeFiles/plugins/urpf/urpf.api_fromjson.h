/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/fib/fib_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_urpf_api_fromjson_h
#define included_urpf_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_urpf_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_urpf_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "URPF_API_MODE_OFF") == 0) {*a = 0; return 0;}
    if (strcmp(p, "URPF_API_MODE_LOOSE") == 0) {*a = 1; return 0;}
    if (strcmp(p, "URPF_API_MODE_STRICT") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_urpf_update_t *vl_api_urpf_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_urpf_update_t);
    vl_api_urpf_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_input");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_input);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_urpf_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_urpf_update_reply_t *vl_api_urpf_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_urpf_update_reply_t);
    vl_api_urpf_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_urpf_update_v2_t *vl_api_urpf_update_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_urpf_update_v2_t);
    vl_api_urpf_update_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_input");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_input);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_urpf_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_urpf_update_v2_reply_t *vl_api_urpf_update_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_urpf_update_v2_reply_t);
    vl_api_urpf_update_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_urpf_interface_dump_t *vl_api_urpf_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_urpf_interface_dump_t);
    vl_api_urpf_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_urpf_interface_details_t *vl_api_urpf_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_urpf_interface_details_t);
    vl_api_urpf_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_input");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_input);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_urpf_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson((void **)&a, &l, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
