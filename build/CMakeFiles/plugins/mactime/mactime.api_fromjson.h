/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_mactime_api_fromjson_h
#define included_mactime_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_time_range_t_fromjson (void **mp, int *len, cJSON *o, vl_api_time_range_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "start");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->start);

    item = cJSON_GetObjectItem(o, "end");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->end);

    return 0;

  error:
    return -1;
}
static inline int vl_api_mactime_time_range_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mactime_time_range_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "start");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->start);

    item = cJSON_GetObjectItem(o, "end");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->end);

    return 0;

  error:
    return -1;
}
static inline vl_api_mactime_enable_disable_t *vl_api_mactime_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_enable_disable_t);
    vl_api_mactime_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mactime_enable_disable_reply_t *vl_api_mactime_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_enable_disable_reply_t);
    vl_api_mactime_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mactime_add_del_range_t *vl_api_mactime_add_del_range_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_add_del_range_t);
    vl_api_mactime_add_del_range_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "drop");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->drop);

    item = cJSON_GetObjectItem(o, "allow");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->allow);

    item = cJSON_GetObjectItem(o, "allow_quota");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->allow_quota);

    item = cJSON_GetObjectItem(o, "no_udp_10001");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_udp_10001);

    item = cJSON_GetObjectItem(o, "data_quota");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->data_quota);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "device_name");
    if (!item) goto error;
    strncpy_s((char *)a->device_name, sizeof(a->device_name), cJSON_GetStringValue(item), sizeof(a->device_name) - 1);

    item = cJSON_GetObjectItem(o, "ranges");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "ranges");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_time_range_t) * size);
        vl_api_time_range_t *d = (void *)a + l;
        l += sizeof(vl_api_time_range_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_time_range_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mactime_add_del_range_reply_t *vl_api_mactime_add_del_range_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_add_del_range_reply_t);
    vl_api_mactime_add_del_range_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mactime_dump_t *vl_api_mactime_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_dump_t);
    vl_api_mactime_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "my_table_epoch");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->my_table_epoch);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mactime_details_t *vl_api_mactime_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_details_t);
    vl_api_mactime_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pool_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pool_index);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "data_quota");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->data_quota);

    item = cJSON_GetObjectItem(o, "data_used_in_range");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->data_used_in_range);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "device_name");
    if (!item) goto error;
    strncpy_s((char *)a->device_name, sizeof(a->device_name), cJSON_GetStringValue(item), sizeof(a->device_name) - 1);

    item = cJSON_GetObjectItem(o, "ranges");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "ranges");
        int size = cJSON_GetArraySize(array);
        a->nranges = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_mactime_time_range_t) * size);
        vl_api_mactime_time_range_t *d = (void *)a + l;
        l += sizeof(vl_api_mactime_time_range_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_mactime_time_range_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mactime_dump_reply_t *vl_api_mactime_dump_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mactime_dump_reply_t);
    vl_api_mactime_dump_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "table_epoch");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_epoch);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
