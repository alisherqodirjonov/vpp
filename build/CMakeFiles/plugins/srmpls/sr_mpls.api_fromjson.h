/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/srv6/sr_types.api_fromjson.h>
#ifndef included_sr_mpls_api_fromjson_h
#define included_sr_mpls_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_sr_mpls_policy_add_t *vl_api_sr_mpls_policy_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_add_t);
    vl_api_sr_mpls_policy_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bsid);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "is_spray");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_spray);

    item = cJSON_GetObjectItem(o, "segments");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "segments");
        int size = cJSON_GetArraySize(array);
        a->n_segments = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_add_reply_t *vl_api_sr_mpls_policy_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_add_reply_t);
    vl_api_sr_mpls_policy_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_mod_t *vl_api_sr_mpls_policy_mod_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_mod_t);
    vl_api_sr_mpls_policy_mod_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bsid);

    item = cJSON_GetObjectItem(o, "operation");
    if (!item) goto error;
    if (vl_api_sr_policy_op_t_fromjson((void **)&a, &l, item, &a->operation) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sl_index);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "segments");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "segments");
        int size = cJSON_GetArraySize(array);
        a->n_segments = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_mod_reply_t *vl_api_sr_mpls_policy_mod_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_mod_reply_t);
    vl_api_sr_mpls_policy_mod_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_del_t *vl_api_sr_mpls_policy_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_del_t);
    vl_api_sr_mpls_policy_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bsid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_del_reply_t *vl_api_sr_mpls_policy_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_del_reply_t);
    vl_api_sr_mpls_policy_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_steering_add_del_t *vl_api_sr_mpls_steering_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_steering_add_del_t);
    vl_api_sr_mpls_steering_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bsid);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mask_width");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mask_width);

    item = cJSON_GetObjectItem(o, "next_hop");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->next_hop) < 0) goto error;

    item = cJSON_GetObjectItem(o, "color");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->color);

    item = cJSON_GetObjectItem(o, "co_bits");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->co_bits);

    item = cJSON_GetObjectItem(o, "vpn_label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vpn_label);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_steering_add_del_reply_t *vl_api_sr_mpls_steering_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_steering_add_del_reply_t);
    vl_api_sr_mpls_steering_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_assign_endpoint_color_t *vl_api_sr_mpls_policy_assign_endpoint_color_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_assign_endpoint_color_t);
    vl_api_sr_mpls_policy_assign_endpoint_color_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bsid);

    item = cJSON_GetObjectItem(o, "endpoint");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->endpoint) < 0) goto error;

    item = cJSON_GetObjectItem(o, "color");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->color);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_mpls_policy_assign_endpoint_color_reply_t);
    vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *a = cJSON_malloc(l);

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
