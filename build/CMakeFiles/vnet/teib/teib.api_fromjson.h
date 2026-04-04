/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_teib_api_fromjson_h
#define included_teib_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_teib_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_teib_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->peer) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->nh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nh_table_id);

    return 0;

  error:
    return -1;
}
static inline vl_api_teib_entry_add_del_t *vl_api_teib_entry_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_teib_entry_add_del_t);
    vl_api_teib_entry_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_teib_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_teib_entry_add_del_reply_t *vl_api_teib_entry_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_teib_entry_add_del_reply_t);
    vl_api_teib_entry_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_teib_dump_t *vl_api_teib_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_teib_dump_t);
    vl_api_teib_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_teib_details_t *vl_api_teib_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_teib_details_t);
    vl_api_teib_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_teib_entry_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
