/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_dslite_api_fromjson_h
#define included_dslite_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_dslite_add_del_pool_addr_range_t *vl_api_dslite_add_del_pool_addr_range_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_add_del_pool_addr_range_t);
    vl_api_dslite_add_del_pool_addr_range_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "start_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->start_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "end_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->end_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_add_del_pool_addr_range_reply_t *vl_api_dslite_add_del_pool_addr_range_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_add_del_pool_addr_range_reply_t);
    vl_api_dslite_add_del_pool_addr_range_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_address_dump_t *vl_api_dslite_address_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_address_dump_t);
    vl_api_dslite_address_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_dslite_address_details_t *vl_api_dslite_address_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_address_details_t);
    vl_api_dslite_address_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_set_aftr_addr_t *vl_api_dslite_set_aftr_addr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_set_aftr_addr_t);
    vl_api_dslite_set_aftr_addr_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip4_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_set_aftr_addr_reply_t *vl_api_dslite_set_aftr_addr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_set_aftr_addr_reply_t);
    vl_api_dslite_set_aftr_addr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_get_aftr_addr_t *vl_api_dslite_get_aftr_addr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_get_aftr_addr_t);
    vl_api_dslite_get_aftr_addr_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_dslite_get_aftr_addr_reply_t *vl_api_dslite_get_aftr_addr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_get_aftr_addr_reply_t);
    vl_api_dslite_get_aftr_addr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ip4_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_set_b4_addr_t *vl_api_dslite_set_b4_addr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_set_b4_addr_t);
    vl_api_dslite_set_b4_addr_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip4_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_set_b4_addr_reply_t *vl_api_dslite_set_b4_addr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_set_b4_addr_reply_t);
    vl_api_dslite_set_b4_addr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dslite_get_b4_addr_t *vl_api_dslite_get_b4_addr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_get_b4_addr_t);
    vl_api_dslite_get_b4_addr_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_dslite_get_b4_addr_reply_t *vl_api_dslite_get_b4_addr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dslite_get_b4_addr_reply_t);
    vl_api_dslite_get_b4_addr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ip4_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip6_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
