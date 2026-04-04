/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_qos_api_fromjson_h
#define included_qos_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_qos_source_t_fromjson(void **mp, int *len, cJSON *o, vl_api_qos_source_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "QOS_API_SOURCE_EXT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "QOS_API_SOURCE_VLAN") == 0) {*a = 1; return 0;}
    if (strcmp(p, "QOS_API_SOURCE_MPLS") == 0) {*a = 2; return 0;}
    if (strcmp(p, "QOS_API_SOURCE_IP") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_qos_store_t_fromjson (void **mp, int *len, cJSON *o, vl_api_qos_store_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "input_source");
    if (!item) goto error;
    if (vl_api_qos_source_t_fromjson(mp, len, item, &a->input_source) < 0) goto error;

    item = cJSON_GetObjectItem(o, "value");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->value);

    return 0;

  error:
    return -1;
}
static inline int vl_api_qos_record_t_fromjson (void **mp, int *len, cJSON *o, vl_api_qos_record_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "input_source");
    if (!item) goto error;
    if (vl_api_qos_source_t_fromjson(mp, len, item, &a->input_source) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_qos_egress_map_row_t_fromjson (void **mp, int *len, cJSON *o, vl_api_qos_egress_map_row_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "outputs");
    if (!item) goto error;
    if (u8string_fromjson2(o, "outputs", a->outputs) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_qos_egress_map_t_fromjson (void **mp, int *len, cJSON *o, vl_api_qos_egress_map_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "rows");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "rows");
        int size = cJSON_GetArraySize(array);
        if (size != 4) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_qos_egress_map_row_t_fromjson(mp, len, e, &a->rows[i]) < 0) goto error;
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_qos_mark_t_fromjson (void **mp, int *len, cJSON *o, vl_api_qos_mark_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "map_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->map_id);

    item = cJSON_GetObjectItem(o, "output_source");
    if (!item) goto error;
    if (vl_api_qos_source_t_fromjson(mp, len, item, &a->output_source) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_qos_store_enable_disable_t *vl_api_qos_store_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_store_enable_disable_t);
    vl_api_qos_store_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "store");
    if (!item) goto error;
    if (vl_api_qos_store_t_fromjson((void **)&a, &l, item, &a->store) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_store_enable_disable_reply_t *vl_api_qos_store_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_store_enable_disable_reply_t);
    vl_api_qos_store_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_store_dump_t *vl_api_qos_store_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_store_dump_t);
    vl_api_qos_store_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_qos_store_details_t *vl_api_qos_store_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_store_details_t);
    vl_api_qos_store_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "store");
    if (!item) goto error;
    if (vl_api_qos_store_t_fromjson((void **)&a, &l, item, &a->store) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_record_enable_disable_t *vl_api_qos_record_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_record_enable_disable_t);
    vl_api_qos_record_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "record");
    if (!item) goto error;
    if (vl_api_qos_record_t_fromjson((void **)&a, &l, item, &a->record) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_record_enable_disable_reply_t *vl_api_qos_record_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_record_enable_disable_reply_t);
    vl_api_qos_record_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_record_dump_t *vl_api_qos_record_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_record_dump_t);
    vl_api_qos_record_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_qos_record_details_t *vl_api_qos_record_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_record_details_t);
    vl_api_qos_record_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "record");
    if (!item) goto error;
    if (vl_api_qos_record_t_fromjson((void **)&a, &l, item, &a->record) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_egress_map_update_t *vl_api_qos_egress_map_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_egress_map_update_t);
    vl_api_qos_egress_map_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "map");
    if (!item) goto error;
    if (vl_api_qos_egress_map_t_fromjson((void **)&a, &l, item, &a->map) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_egress_map_update_reply_t *vl_api_qos_egress_map_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_egress_map_update_reply_t);
    vl_api_qos_egress_map_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_egress_map_delete_t *vl_api_qos_egress_map_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_egress_map_delete_t);
    vl_api_qos_egress_map_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_egress_map_delete_reply_t *vl_api_qos_egress_map_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_egress_map_delete_reply_t);
    vl_api_qos_egress_map_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_egress_map_dump_t *vl_api_qos_egress_map_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_egress_map_dump_t);
    vl_api_qos_egress_map_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_qos_egress_map_details_t *vl_api_qos_egress_map_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_egress_map_details_t);
    vl_api_qos_egress_map_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "map");
    if (!item) goto error;
    if (vl_api_qos_egress_map_t_fromjson((void **)&a, &l, item, &a->map) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_mark_enable_disable_t *vl_api_qos_mark_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_mark_enable_disable_t);
    vl_api_qos_mark_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "mark");
    if (!item) goto error;
    if (vl_api_qos_mark_t_fromjson((void **)&a, &l, item, &a->mark) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_mark_enable_disable_reply_t *vl_api_qos_mark_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_mark_enable_disable_reply_t);
    vl_api_qos_mark_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_mark_dump_t *vl_api_qos_mark_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_mark_dump_t);
    vl_api_qos_mark_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_mark_details_t *vl_api_qos_mark_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_mark_details_t);
    vl_api_qos_mark_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mark");
    if (!item) goto error;
    if (vl_api_qos_mark_t_fromjson((void **)&a, &l, item, &a->mark) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_qos_mark_details_reply_t *vl_api_qos_mark_details_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_qos_mark_details_reply_t);
    vl_api_qos_mark_details_reply_t *a = cJSON_malloc(l);

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
