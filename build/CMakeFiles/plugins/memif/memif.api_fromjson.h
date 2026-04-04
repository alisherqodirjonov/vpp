/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_memif_api_fromjson_h
#define included_memif_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_memif_role_t_fromjson(void **mp, int *len, cJSON *o, vl_api_memif_role_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "MEMIF_ROLE_API_MASTER") == 0) {*a = 0; return 0;}
    if (strcmp(p, "MEMIF_ROLE_API_SLAVE") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_memif_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_memif_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "MEMIF_MODE_API_ETHERNET") == 0) {*a = 0; return 0;}
    if (strcmp(p, "MEMIF_MODE_API_IP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "MEMIF_MODE_API_PUNT_INJECT") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_memif_socket_filename_add_del_t *vl_api_memif_socket_filename_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_socket_filename_add_del_t);
    vl_api_memif_socket_filename_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    item = cJSON_GetObjectItem(o, "socket_filename");
    if (!item) goto error;
    strncpy_s((char *)a->socket_filename, sizeof(a->socket_filename), cJSON_GetStringValue(item), sizeof(a->socket_filename) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_socket_filename_add_del_reply_t *vl_api_memif_socket_filename_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_socket_filename_add_del_reply_t);
    vl_api_memif_socket_filename_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_socket_filename_add_del_v2_t *vl_api_memif_socket_filename_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_socket_filename_add_del_v2_t);
    vl_api_memif_socket_filename_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    item = cJSON_GetObjectItem(o, "socket_filename");
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
static inline vl_api_memif_socket_filename_add_del_v2_reply_t *vl_api_memif_socket_filename_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_socket_filename_add_del_v2_reply_t);
    vl_api_memif_socket_filename_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_create_t *vl_api_memif_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_create_t);
    vl_api_memif_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "role");
    if (!item) goto error;
    if (vl_api_memif_role_t_fromjson((void **)&a, &l, item, &a->role) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_memif_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rx_queues");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->rx_queues);

    item = cJSON_GetObjectItem(o, "tx_queues");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tx_queues);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    item = cJSON_GetObjectItem(o, "ring_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ring_size);

    item = cJSON_GetObjectItem(o, "buffer_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->buffer_size);

    item = cJSON_GetObjectItem(o, "no_zero_copy");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_zero_copy);

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "secret");
    if (!item) goto error;
    strncpy_s((char *)a->secret, sizeof(a->secret), cJSON_GetStringValue(item), sizeof(a->secret) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_create_reply_t *vl_api_memif_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_create_reply_t);
    vl_api_memif_create_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_memif_create_v2_t *vl_api_memif_create_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_create_v2_t);
    vl_api_memif_create_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "role");
    if (!item) goto error;
    if (vl_api_memif_role_t_fromjson((void **)&a, &l, item, &a->role) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_memif_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rx_queues");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->rx_queues);

    item = cJSON_GetObjectItem(o, "tx_queues");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tx_queues);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    item = cJSON_GetObjectItem(o, "ring_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ring_size);

    item = cJSON_GetObjectItem(o, "buffer_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->buffer_size);

    item = cJSON_GetObjectItem(o, "no_zero_copy");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_zero_copy);

    item = cJSON_GetObjectItem(o, "use_dma");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_dma);

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "secret");
    if (!item) goto error;
    strncpy_s((char *)a->secret, sizeof(a->secret), cJSON_GetStringValue(item), sizeof(a->secret) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_create_v2_reply_t *vl_api_memif_create_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_create_v2_reply_t);
    vl_api_memif_create_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_memif_delete_t *vl_api_memif_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_delete_t);
    vl_api_memif_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_delete_reply_t *vl_api_memif_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_delete_reply_t);
    vl_api_memif_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_socket_filename_details_t *vl_api_memif_socket_filename_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_socket_filename_details_t);
    vl_api_memif_socket_filename_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    item = cJSON_GetObjectItem(o, "socket_filename");
    if (!item) goto error;
    strncpy_s((char *)a->socket_filename, sizeof(a->socket_filename), cJSON_GetStringValue(item), sizeof(a->socket_filename) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_socket_filename_dump_t *vl_api_memif_socket_filename_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_socket_filename_dump_t);
    vl_api_memif_socket_filename_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_memif_details_t *vl_api_memif_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_details_t);
    vl_api_memif_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "hw_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->hw_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "role");
    if (!item) goto error;
    if (vl_api_memif_role_t_fromjson((void **)&a, &l, item, &a->role) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_memif_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "zero_copy");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->zero_copy);

    item = cJSON_GetObjectItem(o, "socket_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->socket_id);

    item = cJSON_GetObjectItem(o, "ring_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ring_size);

    item = cJSON_GetObjectItem(o, "buffer_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->buffer_size);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_if_status_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "if_name");
    if (!item) goto error;
    strncpy_s((char *)a->if_name, sizeof(a->if_name), cJSON_GetStringValue(item), sizeof(a->if_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memif_dump_t *vl_api_memif_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memif_dump_t);
    vl_api_memif_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
#endif
