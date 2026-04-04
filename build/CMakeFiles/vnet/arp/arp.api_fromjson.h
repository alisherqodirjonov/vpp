/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_arp_api_fromjson_h
#define included_arp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_proxy_arp_t_fromjson (void **mp, int *len, cJSON *o, vl_api_proxy_arp_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "low");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->low) < 0) goto error;

    item = cJSON_GetObjectItem(o, "hi");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->hi) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_proxy_arp_add_del_t *vl_api_proxy_arp_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_add_del_t);
    vl_api_proxy_arp_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "proxy");
    if (!item) goto error;
    if (vl_api_proxy_arp_t_fromjson((void **)&a, &l, item, &a->proxy) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_proxy_arp_add_del_reply_t *vl_api_proxy_arp_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_add_del_reply_t);
    vl_api_proxy_arp_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_proxy_arp_dump_t *vl_api_proxy_arp_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_dump_t);
    vl_api_proxy_arp_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_proxy_arp_details_t *vl_api_proxy_arp_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_details_t);
    vl_api_proxy_arp_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "proxy");
    if (!item) goto error;
    if (vl_api_proxy_arp_t_fromjson((void **)&a, &l, item, &a->proxy) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_proxy_arp_intfc_enable_disable_t *vl_api_proxy_arp_intfc_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_intfc_enable_disable_t);
    vl_api_proxy_arp_intfc_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_proxy_arp_intfc_enable_disable_reply_t *vl_api_proxy_arp_intfc_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_intfc_enable_disable_reply_t);
    vl_api_proxy_arp_intfc_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_proxy_arp_intfc_dump_t *vl_api_proxy_arp_intfc_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_intfc_dump_t);
    vl_api_proxy_arp_intfc_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_proxy_arp_intfc_details_t *vl_api_proxy_arp_intfc_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_proxy_arp_intfc_details_t);
    vl_api_proxy_arp_intfc_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
