/* Imported API files */
#ifndef included_dev_api_fromjson_h
#define included_dev_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_dev_flags_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dev_flags_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "VL_API_DEV_FLAG_NO_STATS") == 0) *a |= 1;
    }
   return 0;
}
static inline int vl_api_dev_port_flags_t_fromjson (void **mp, int *len, cJSON *o, vl_api_dev_port_flags_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "VL_API_DEV_PORT_FLAG_INTERRUPT_MODE") == 0) *a |= 1;
       if (strcmp(p, "VL_API_DEV_PORT_FLAG_CONSISTENT_QP") == 0) *a |= 2;
    }
   return 0;
}
static inline vl_api_dev_attach_t *vl_api_dev_attach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_attach_t);
    vl_api_dev_attach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "device_id");
    if (!item) goto error;
    strncpy_s((char *)a->device_id, sizeof(a->device_id), cJSON_GetStringValue(item), sizeof(a->device_id) - 1);

    item = cJSON_GetObjectItem(o, "driver_name");
    if (!item) goto error;
    strncpy_s((char *)a->driver_name, sizeof(a->driver_name), cJSON_GetStringValue(item), sizeof(a->driver_name) - 1);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_dev_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "args");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_attach_reply_t *vl_api_dev_attach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_attach_reply_t);
    vl_api_dev_attach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dev_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dev_index);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "error_string");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_detach_t *vl_api_dev_detach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_detach_t);
    vl_api_dev_detach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dev_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dev_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_detach_reply_t *vl_api_dev_detach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_detach_reply_t);
    vl_api_dev_detach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "error_string");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_create_port_if_t *vl_api_dev_create_port_if_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_create_port_if_t);
    vl_api_dev_create_port_if_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dev_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->dev_index);

    item = cJSON_GetObjectItem(o, "intf_name");
    if (!item) goto error;
    strncpy_s((char *)a->intf_name, sizeof(a->intf_name), cJSON_GetStringValue(item), sizeof(a->intf_name) - 1);

    item = cJSON_GetObjectItem(o, "num_rx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_rx_queues);

    item = cJSON_GetObjectItem(o, "num_tx_queues");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->num_tx_queues);

    item = cJSON_GetObjectItem(o, "rx_queue_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rx_queue_size);

    item = cJSON_GetObjectItem(o, "tx_queue_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->tx_queue_size);

    item = cJSON_GetObjectItem(o, "port_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port_id);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_dev_port_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "args");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_create_port_if_reply_t *vl_api_dev_create_port_if_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_create_port_if_reply_t);
    vl_api_dev_create_port_if_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "error_string");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_remove_port_if_t *vl_api_dev_remove_port_if_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_remove_port_if_t);
    vl_api_dev_remove_port_if_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_dev_remove_port_if_reply_t *vl_api_dev_remove_port_if_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_dev_remove_port_if_reply_t);
    vl_api_dev_remove_port_if_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "error_string");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
