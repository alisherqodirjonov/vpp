/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/devices/virtio/virtio_types.api_fromjson.h>
#ifndef included_vhost_user_api_fromjson_h
#define included_vhost_user_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_create_vhost_user_if_t *vl_api_create_vhost_user_if_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_vhost_user_if_t);
    vl_api_create_vhost_user_if_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_server");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_server);

    item = cJSON_GetObjectItem(o, "sock_filename");
    if (!item) goto error;
    strncpy_s((char *)a->sock_filename, sizeof(a->sock_filename), cJSON_GetStringValue(item), sizeof(a->sock_filename) - 1);

    item = cJSON_GetObjectItem(o, "renumber");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->renumber);

    item = cJSON_GetObjectItem(o, "disable_mrg_rxbuf");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->disable_mrg_rxbuf);

    item = cJSON_GetObjectItem(o, "disable_indirect_desc");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->disable_indirect_desc);

    item = cJSON_GetObjectItem(o, "enable_gso");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_gso);

    item = cJSON_GetObjectItem(o, "enable_packed");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_packed);

    item = cJSON_GetObjectItem(o, "custom_dev_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->custom_dev_instance);

    item = cJSON_GetObjectItem(o, "use_custom_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_custom_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_vhost_user_if_reply_t *vl_api_create_vhost_user_if_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_vhost_user_if_reply_t);
    vl_api_create_vhost_user_if_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_modify_vhost_user_if_t *vl_api_modify_vhost_user_if_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_modify_vhost_user_if_t);
    vl_api_modify_vhost_user_if_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_server");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_server);

    item = cJSON_GetObjectItem(o, "sock_filename");
    if (!item) goto error;
    strncpy_s((char *)a->sock_filename, sizeof(a->sock_filename), cJSON_GetStringValue(item), sizeof(a->sock_filename) - 1);

    item = cJSON_GetObjectItem(o, "renumber");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->renumber);

    item = cJSON_GetObjectItem(o, "enable_gso");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_gso);

    item = cJSON_GetObjectItem(o, "enable_packed");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_packed);

    item = cJSON_GetObjectItem(o, "custom_dev_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->custom_dev_instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_modify_vhost_user_if_reply_t *vl_api_modify_vhost_user_if_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_modify_vhost_user_if_reply_t);
    vl_api_modify_vhost_user_if_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_vhost_user_if_v2_t *vl_api_create_vhost_user_if_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_vhost_user_if_v2_t);
    vl_api_create_vhost_user_if_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_server");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_server);

    item = cJSON_GetObjectItem(o, "sock_filename");
    if (!item) goto error;
    strncpy_s((char *)a->sock_filename, sizeof(a->sock_filename), cJSON_GetStringValue(item), sizeof(a->sock_filename) - 1);

    item = cJSON_GetObjectItem(o, "renumber");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->renumber);

    item = cJSON_GetObjectItem(o, "disable_mrg_rxbuf");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->disable_mrg_rxbuf);

    item = cJSON_GetObjectItem(o, "disable_indirect_desc");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->disable_indirect_desc);

    item = cJSON_GetObjectItem(o, "enable_gso");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_gso);

    item = cJSON_GetObjectItem(o, "enable_packed");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_packed);

    item = cJSON_GetObjectItem(o, "enable_event_idx");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_event_idx);

    item = cJSON_GetObjectItem(o, "custom_dev_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->custom_dev_instance);

    item = cJSON_GetObjectItem(o, "use_custom_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_custom_mac);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_vhost_user_if_v2_reply_t *vl_api_create_vhost_user_if_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_vhost_user_if_v2_reply_t);
    vl_api_create_vhost_user_if_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_modify_vhost_user_if_v2_t *vl_api_modify_vhost_user_if_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_modify_vhost_user_if_v2_t);
    vl_api_modify_vhost_user_if_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_server");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_server);

    item = cJSON_GetObjectItem(o, "sock_filename");
    if (!item) goto error;
    strncpy_s((char *)a->sock_filename, sizeof(a->sock_filename), cJSON_GetStringValue(item), sizeof(a->sock_filename) - 1);

    item = cJSON_GetObjectItem(o, "renumber");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->renumber);

    item = cJSON_GetObjectItem(o, "enable_gso");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_gso);

    item = cJSON_GetObjectItem(o, "enable_packed");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_packed);

    item = cJSON_GetObjectItem(o, "enable_event_idx");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_event_idx);

    item = cJSON_GetObjectItem(o, "custom_dev_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->custom_dev_instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_modify_vhost_user_if_v2_reply_t *vl_api_modify_vhost_user_if_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_modify_vhost_user_if_v2_reply_t);
    vl_api_modify_vhost_user_if_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_delete_vhost_user_if_t *vl_api_delete_vhost_user_if_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_delete_vhost_user_if_t);
    vl_api_delete_vhost_user_if_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_delete_vhost_user_if_reply_t *vl_api_delete_vhost_user_if_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_delete_vhost_user_if_reply_t);
    vl_api_delete_vhost_user_if_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_vhost_user_details_t *vl_api_sw_interface_vhost_user_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_vhost_user_details_t);
    vl_api_sw_interface_vhost_user_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    item = cJSON_GetObjectItem(o, "virtio_net_hdr_sz");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->virtio_net_hdr_sz);

    item = cJSON_GetObjectItem(o, "features_first_32");
    if (!item) goto error;
    if (vl_api_virtio_net_features_first_32_t_fromjson((void **)&a, &l, item, &a->features_first_32) < 0) goto error;

    item = cJSON_GetObjectItem(o, "features_last_32");
    if (!item) goto error;
    if (vl_api_virtio_net_features_last_32_t_fromjson((void **)&a, &l, item, &a->features_last_32) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_server");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_server);

    item = cJSON_GetObjectItem(o, "sock_filename");
    if (!item) goto error;
    strncpy_s((char *)a->sock_filename, sizeof(a->sock_filename), cJSON_GetStringValue(item), sizeof(a->sock_filename) - 1);

    item = cJSON_GetObjectItem(o, "num_regions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->num_regions);

    item = cJSON_GetObjectItem(o, "sock_errno");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->sock_errno);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_vhost_user_dump_t *vl_api_sw_interface_vhost_user_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_vhost_user_dump_t);
    vl_api_sw_interface_vhost_user_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
