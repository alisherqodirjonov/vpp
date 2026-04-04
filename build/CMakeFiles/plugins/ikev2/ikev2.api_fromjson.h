/* Imported API files */
#include <ikev2/ikev2_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_ikev2_api_fromjson_h
#define included_ikev2_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_ikev2_plugin_get_version_t *vl_api_ikev2_plugin_get_version_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_plugin_get_version_t);
    vl_api_ikev2_plugin_get_version_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ikev2_plugin_get_version_reply_t *vl_api_ikev2_plugin_get_version_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_plugin_get_version_reply_t);
    vl_api_ikev2_plugin_get_version_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "major");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->major);

    item = cJSON_GetObjectItem(o, "minor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->minor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_plugin_set_sleep_interval_t *vl_api_ikev2_plugin_set_sleep_interval_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_plugin_set_sleep_interval_t);
    vl_api_ikev2_plugin_set_sleep_interval_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "timeout");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->timeout);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_plugin_set_sleep_interval_reply_t *vl_api_ikev2_plugin_set_sleep_interval_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_plugin_set_sleep_interval_reply_t);
    vl_api_ikev2_plugin_set_sleep_interval_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_get_sleep_interval_t *vl_api_ikev2_get_sleep_interval_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_get_sleep_interval_t);
    vl_api_ikev2_get_sleep_interval_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ikev2_get_sleep_interval_reply_t *vl_api_ikev2_get_sleep_interval_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_get_sleep_interval_reply_t);
    vl_api_ikev2_get_sleep_interval_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sleep_interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->sleep_interval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_dump_t *vl_api_ikev2_profile_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_dump_t);
    vl_api_ikev2_profile_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ikev2_profile_details_t *vl_api_ikev2_profile_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_details_t);
    vl_api_ikev2_profile_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "profile");
    if (!item) goto error;
    if (vl_api_ikev2_profile_t_fromjson((void **)&a, &l, item, &a->profile) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_sa_dump_t *vl_api_ikev2_sa_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_sa_dump_t);
    vl_api_ikev2_sa_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ikev2_sa_v2_dump_t *vl_api_ikev2_sa_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_sa_v2_dump_t);
    vl_api_ikev2_sa_v2_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ikev2_sa_v3_dump_t *vl_api_ikev2_sa_v3_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_sa_v3_dump_t);
    vl_api_ikev2_sa_v3_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ikev2_sa_details_t *vl_api_ikev2_sa_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_sa_details_t);
    vl_api_ikev2_sa_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sa");
    if (!item) goto error;
    if (vl_api_ikev2_sa_t_fromjson((void **)&a, &l, item, &a->sa) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_sa_v2_details_t *vl_api_ikev2_sa_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_sa_v2_details_t);
    vl_api_ikev2_sa_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sa");
    if (!item) goto error;
    if (vl_api_ikev2_sa_v2_t_fromjson((void **)&a, &l, item, &a->sa) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_sa_v3_details_t *vl_api_ikev2_sa_v3_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_sa_v3_details_t);
    vl_api_ikev2_sa_v3_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sa");
    if (!item) goto error;
    if (vl_api_ikev2_sa_v3_t_fromjson((void **)&a, &l, item, &a->sa) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_child_sa_dump_t *vl_api_ikev2_child_sa_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_child_sa_dump_t);
    vl_api_ikev2_child_sa_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_child_sa_details_t *vl_api_ikev2_child_sa_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_child_sa_details_t);
    vl_api_ikev2_child_sa_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "child_sa");
    if (!item) goto error;
    if (vl_api_ikev2_child_sa_t_fromjson((void **)&a, &l, item, &a->child_sa) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_child_sa_v2_dump_t *vl_api_ikev2_child_sa_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_child_sa_v2_dump_t);
    vl_api_ikev2_child_sa_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_child_sa_v2_details_t *vl_api_ikev2_child_sa_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_child_sa_v2_details_t);
    vl_api_ikev2_child_sa_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "child_sa");
    if (!item) goto error;
    if (vl_api_ikev2_child_sa_v2_t_fromjson((void **)&a, &l, item, &a->child_sa) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_nonce_get_t *vl_api_ikev2_nonce_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_nonce_get_t);
    vl_api_ikev2_nonce_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_initiator");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_initiator);

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_nonce_get_reply_t *vl_api_ikev2_nonce_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_nonce_get_reply_t);
    vl_api_ikev2_nonce_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "nonce");
    if (!item) goto error;
    s = u8string_fromjson(o, "nonce");
    if (!s) goto error;
    a->data_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_traffic_selector_dump_t *vl_api_ikev2_traffic_selector_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_traffic_selector_dump_t);
    vl_api_ikev2_traffic_selector_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_initiator");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_initiator);

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "child_sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->child_sa_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_traffic_selector_details_t *vl_api_ikev2_traffic_selector_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_traffic_selector_details_t);
    vl_api_ikev2_traffic_selector_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ts");
    if (!item) goto error;
    if (vl_api_ikev2_ts_t_fromjson((void **)&a, &l, item, &a->ts) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_add_del_t *vl_api_ikev2_profile_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_add_del_t);
    vl_api_ikev2_profile_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_add_del_reply_t *vl_api_ikev2_profile_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_add_del_reply_t);
    vl_api_ikev2_profile_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_auth_t *vl_api_ikev2_profile_set_auth_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_auth_t);
    vl_api_ikev2_profile_set_auth_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "auth_method");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->auth_method);

    item = cJSON_GetObjectItem(o, "is_hex");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_hex);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    s = u8string_fromjson(o, "data");
    if (!s) goto error;
    a->data_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_auth_reply_t *vl_api_ikev2_profile_set_auth_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_auth_reply_t);
    vl_api_ikev2_profile_set_auth_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_id_t *vl_api_ikev2_profile_set_id_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_id_t);
    vl_api_ikev2_profile_set_id_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "is_local");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_local);

    item = cJSON_GetObjectItem(o, "id_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id_type);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    s = u8string_fromjson(o, "data");
    if (!s) goto error;
    a->data_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_id_reply_t *vl_api_ikev2_profile_set_id_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_id_reply_t);
    vl_api_ikev2_profile_set_id_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_disable_natt_t *vl_api_ikev2_profile_disable_natt_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_disable_natt_t);
    vl_api_ikev2_profile_disable_natt_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_disable_natt_reply_t *vl_api_ikev2_profile_disable_natt_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_disable_natt_reply_t);
    vl_api_ikev2_profile_disable_natt_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_ts_t *vl_api_ikev2_profile_set_ts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_ts_t);
    vl_api_ikev2_profile_set_ts_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "ts");
    if (!item) goto error;
    if (vl_api_ikev2_ts_t_fromjson((void **)&a, &l, item, &a->ts) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_ts_reply_t *vl_api_ikev2_profile_set_ts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_ts_reply_t);
    vl_api_ikev2_profile_set_ts_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_local_key_t *vl_api_ikev2_set_local_key_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_local_key_t);
    vl_api_ikev2_set_local_key_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "key_file");
    if (!item) goto error;
    strncpy_s((char *)a->key_file, sizeof(a->key_file), cJSON_GetStringValue(item), sizeof(a->key_file) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_local_key_reply_t *vl_api_ikev2_set_local_key_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_local_key_reply_t);
    vl_api_ikev2_set_local_key_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_tunnel_interface_t *vl_api_ikev2_set_tunnel_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_tunnel_interface_t);
    vl_api_ikev2_set_tunnel_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_tunnel_interface_reply_t *vl_api_ikev2_set_tunnel_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_tunnel_interface_reply_t);
    vl_api_ikev2_set_tunnel_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_responder_t *vl_api_ikev2_set_responder_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_responder_t);
    vl_api_ikev2_set_responder_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "responder");
    if (!item) goto error;
    if (vl_api_ikev2_responder_t_fromjson((void **)&a, &l, item, &a->responder) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_responder_reply_t *vl_api_ikev2_set_responder_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_responder_reply_t);
    vl_api_ikev2_set_responder_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_responder_hostname_t *vl_api_ikev2_set_responder_hostname_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_responder_hostname_t);
    vl_api_ikev2_set_responder_hostname_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "hostname");
    if (!item) goto error;
    strncpy_s((char *)a->hostname, sizeof(a->hostname), cJSON_GetStringValue(item), sizeof(a->hostname) - 1);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_responder_hostname_reply_t *vl_api_ikev2_set_responder_hostname_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_responder_hostname_reply_t);
    vl_api_ikev2_set_responder_hostname_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_ike_transforms_t *vl_api_ikev2_set_ike_transforms_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_ike_transforms_t);
    vl_api_ikev2_set_ike_transforms_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "tr");
    if (!item) goto error;
    if (vl_api_ikev2_ike_transforms_t_fromjson((void **)&a, &l, item, &a->tr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_ike_transforms_reply_t *vl_api_ikev2_set_ike_transforms_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_ike_transforms_reply_t);
    vl_api_ikev2_set_ike_transforms_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_esp_transforms_t *vl_api_ikev2_set_esp_transforms_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_esp_transforms_t);
    vl_api_ikev2_set_esp_transforms_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "tr");
    if (!item) goto error;
    if (vl_api_ikev2_esp_transforms_t_fromjson((void **)&a, &l, item, &a->tr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_esp_transforms_reply_t *vl_api_ikev2_set_esp_transforms_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_esp_transforms_reply_t);
    vl_api_ikev2_set_esp_transforms_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_sa_lifetime_t *vl_api_ikev2_set_sa_lifetime_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_sa_lifetime_t);
    vl_api_ikev2_set_sa_lifetime_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "lifetime");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->lifetime);

    item = cJSON_GetObjectItem(o, "lifetime_jitter");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->lifetime_jitter);

    item = cJSON_GetObjectItem(o, "handover");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->handover);

    item = cJSON_GetObjectItem(o, "lifetime_maxdata");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->lifetime_maxdata);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_set_sa_lifetime_reply_t *vl_api_ikev2_set_sa_lifetime_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_set_sa_lifetime_reply_t);
    vl_api_ikev2_set_sa_lifetime_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_sa_init_t *vl_api_ikev2_initiate_sa_init_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_sa_init_t);
    vl_api_ikev2_initiate_sa_init_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_sa_init_reply_t *vl_api_ikev2_initiate_sa_init_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_sa_init_reply_t);
    vl_api_ikev2_initiate_sa_init_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_del_ike_sa_t *vl_api_ikev2_initiate_del_ike_sa_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_del_ike_sa_t);
    vl_api_ikev2_initiate_del_ike_sa_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ispi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->ispi);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_del_ike_sa_reply_t *vl_api_ikev2_initiate_del_ike_sa_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_del_ike_sa_reply_t);
    vl_api_ikev2_initiate_del_ike_sa_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_del_child_sa_t *vl_api_ikev2_initiate_del_child_sa_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_del_child_sa_t);
    vl_api_ikev2_initiate_del_child_sa_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ispi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ispi);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_del_child_sa_reply_t *vl_api_ikev2_initiate_del_child_sa_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_del_child_sa_reply_t);
    vl_api_ikev2_initiate_del_child_sa_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_rekey_child_sa_t *vl_api_ikev2_initiate_rekey_child_sa_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_rekey_child_sa_t);
    vl_api_ikev2_initiate_rekey_child_sa_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ispi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ispi);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_initiate_rekey_child_sa_reply_t *vl_api_ikev2_initiate_rekey_child_sa_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_initiate_rekey_child_sa_reply_t);
    vl_api_ikev2_initiate_rekey_child_sa_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_udp_encap_t *vl_api_ikev2_profile_set_udp_encap_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_udp_encap_t);
    vl_api_ikev2_profile_set_udp_encap_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_udp_encap_reply_t *vl_api_ikev2_profile_set_udp_encap_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_udp_encap_reply_t);
    vl_api_ikev2_profile_set_udp_encap_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_ipsec_udp_port_t *vl_api_ikev2_profile_set_ipsec_udp_port_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_ipsec_udp_port_t);
    vl_api_ikev2_profile_set_ipsec_udp_port_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_set");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_set);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_ipsec_udp_port_reply_t *vl_api_ikev2_profile_set_ipsec_udp_port_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_ipsec_udp_port_reply_t);
    vl_api_ikev2_profile_set_ipsec_udp_port_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_liveness_t *vl_api_ikev2_profile_set_liveness_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_liveness_t);
    vl_api_ikev2_profile_set_liveness_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "period");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->period);

    item = cJSON_GetObjectItem(o, "max_retries");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_retries);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ikev2_profile_set_liveness_reply_t *vl_api_ikev2_profile_set_liveness_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ikev2_profile_set_liveness_reply_t);
    vl_api_ikev2_profile_set_liveness_reply_t *a = cJSON_malloc(l);

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
