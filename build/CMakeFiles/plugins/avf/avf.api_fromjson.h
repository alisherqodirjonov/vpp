/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_avf_api_fromjson_h
#define included_avf_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_avf_create_t *vl_api_avf_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_avf_create_t);
    vl_api_avf_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pci_addr");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pci_addr);

    item = cJSON_GetObjectItem(o, "enable_elog");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->enable_elog);

    item = cJSON_GetObjectItem(o, "rxq_num");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rxq_num);

    item = cJSON_GetObjectItem(o, "rxq_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rxq_size);

    item = cJSON_GetObjectItem(o, "txq_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->txq_size);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_avf_create_reply_t *vl_api_avf_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_avf_create_reply_t);
    vl_api_avf_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_avf_delete_t *vl_api_avf_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_avf_delete_t);
    vl_api_avf_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_avf_delete_reply_t *vl_api_avf_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_avf_delete_reply_t);
    vl_api_avf_delete_reply_t *a = cJSON_malloc(l);

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
