/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_ioam_vxlan_gpe_api_fromjson_h
#define included_ioam_vxlan_gpe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_vxlan_gpe_ioam_enable_t *vl_api_vxlan_gpe_ioam_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_enable_t);
    vl_api_vxlan_gpe_ioam_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "trace_ppc");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->trace_ppc);

    item = cJSON_GetObjectItem(o, "pow_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->pow_enable);

    item = cJSON_GetObjectItem(o, "trace_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->trace_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_enable_reply_t *vl_api_vxlan_gpe_ioam_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_enable_reply_t);
    vl_api_vxlan_gpe_ioam_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_disable_t *vl_api_vxlan_gpe_ioam_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_disable_t);
    vl_api_vxlan_gpe_ioam_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_disable_reply_t *vl_api_vxlan_gpe_ioam_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_disable_reply_t);
    vl_api_vxlan_gpe_ioam_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_vni_enable_t *vl_api_vxlan_gpe_ioam_vni_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_vni_enable_t);
    vl_api_vxlan_gpe_ioam_vni_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->remote) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_vni_enable_reply_t *vl_api_vxlan_gpe_ioam_vni_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_vni_enable_reply_t);
    vl_api_vxlan_gpe_ioam_vni_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_vni_disable_t *vl_api_vxlan_gpe_ioam_vni_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_vni_disable_t);
    vl_api_vxlan_gpe_ioam_vni_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vni");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vni);

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->remote) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_vni_disable_reply_t *vl_api_vxlan_gpe_ioam_vni_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_vni_disable_reply_t);
    vl_api_vxlan_gpe_ioam_vni_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_transit_enable_t *vl_api_vxlan_gpe_ioam_transit_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_transit_enable_t);
    vl_api_vxlan_gpe_ioam_transit_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "outer_fib_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outer_fib_index);

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_transit_enable_reply_t *vl_api_vxlan_gpe_ioam_transit_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_transit_enable_reply_t);
    vl_api_vxlan_gpe_ioam_transit_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_transit_disable_t *vl_api_vxlan_gpe_ioam_transit_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_transit_disable_t);
    vl_api_vxlan_gpe_ioam_transit_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "outer_fib_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outer_fib_index);

    item = cJSON_GetObjectItem(o, "dst_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->dst_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_vxlan_gpe_ioam_transit_disable_reply_t *vl_api_vxlan_gpe_ioam_transit_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_vxlan_gpe_ioam_transit_disable_reply_t);
    vl_api_vxlan_gpe_ioam_transit_disable_reply_t *a = cJSON_malloc(l);

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
