/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_snort_api_fromjson_h
#define included_snort_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_snort_instance_create_t *vl_api_snort_instance_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_create_t);
    vl_api_snort_instance_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "queue_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_size);

    item = cJSON_GetObjectItem(o, "drop_on_disconnect");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->drop_on_disconnect);

    item = cJSON_GetObjectItem(o, "name");
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
static inline vl_api_snort_instance_create_reply_t *vl_api_snort_instance_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_create_reply_t);
    vl_api_snort_instance_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_delete_t *vl_api_snort_instance_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_delete_t);
    vl_api_snort_instance_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_delete_reply_t *vl_api_snort_instance_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_delete_reply_t);
    vl_api_snort_instance_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_client_disconnect_t *vl_api_snort_client_disconnect_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_client_disconnect_t);
    vl_api_snort_client_disconnect_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "snort_client_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->snort_client_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_client_disconnect_reply_t *vl_api_snort_client_disconnect_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_client_disconnect_reply_t);
    vl_api_snort_client_disconnect_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_disconnect_t *vl_api_snort_instance_disconnect_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_disconnect_t);
    vl_api_snort_instance_disconnect_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_disconnect_reply_t *vl_api_snort_instance_disconnect_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_disconnect_reply_t);
    vl_api_snort_instance_disconnect_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_interface_attach_t *vl_api_snort_interface_attach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_attach_t);
    vl_api_snort_interface_attach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "snort_dir");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->snort_dir);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_interface_attach_reply_t *vl_api_snort_interface_attach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_attach_reply_t);
    vl_api_snort_interface_attach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_interface_detach_t *vl_api_snort_interface_detach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_detach_t);
    vl_api_snort_interface_detach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_interface_detach_reply_t *vl_api_snort_interface_detach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_detach_reply_t);
    vl_api_snort_interface_detach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_input_mode_get_t *vl_api_snort_input_mode_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_input_mode_get_t);
    vl_api_snort_input_mode_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_snort_input_mode_get_reply_t *vl_api_snort_input_mode_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_input_mode_get_reply_t);
    vl_api_snort_input_mode_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "snort_mode");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->snort_mode);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_input_mode_set_t *vl_api_snort_input_mode_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_input_mode_set_t);
    vl_api_snort_input_mode_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "input_mode");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->input_mode);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_input_mode_set_reply_t *vl_api_snort_input_mode_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_input_mode_set_reply_t);
    vl_api_snort_input_mode_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_get_t *vl_api_snort_instance_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_get_t);
    vl_api_snort_instance_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_get_reply_t *vl_api_snort_instance_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_get_reply_t);
    vl_api_snort_instance_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_instance_details_t *vl_api_snort_instance_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_instance_details_t);
    vl_api_snort_instance_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    item = cJSON_GetObjectItem(o, "shm_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->shm_size);

    item = cJSON_GetObjectItem(o, "shm_fd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->shm_fd);

    item = cJSON_GetObjectItem(o, "drop_on_disconnect");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->drop_on_disconnect);

    item = cJSON_GetObjectItem(o, "snort_client_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->snort_client_index);

    item = cJSON_GetObjectItem(o, "name");
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
static inline vl_api_snort_interface_get_t *vl_api_snort_interface_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_get_t);
    vl_api_snort_interface_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_interface_get_reply_t *vl_api_snort_interface_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_get_reply_t);
    vl_api_snort_interface_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_interface_details_t *vl_api_snort_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_interface_details_t);
    vl_api_snort_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_client_get_t *vl_api_snort_client_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_client_get_t);
    vl_api_snort_client_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    item = cJSON_GetObjectItem(o, "snort_client_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->snort_client_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_client_get_reply_t *vl_api_snort_client_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_client_get_reply_t);
    vl_api_snort_client_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_snort_client_details_t *vl_api_snort_client_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_snort_client_details_t);
    vl_api_snort_client_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "instance_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
