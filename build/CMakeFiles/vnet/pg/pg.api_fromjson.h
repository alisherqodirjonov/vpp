/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_pg_api_fromjson_h
#define included_pg_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_pg_interface_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_pg_interface_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "PG_API_MODE_ETHERNET") == 0) {*a = 0; return 0;}
    if (strcmp(p, "PG_API_MODE_IP4") == 0) {*a = 1; return 0;}
    if (strcmp(p, "PG_API_MODE_IP6") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_pg_interface_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_pg_interface_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "PG_API_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "PG_API_FLAG_CSUM_OFFLOAD") == 0) {*a = 1; return 0;}
    if (strcmp(p, "PG_API_FLAG_GSO") == 0) {*a = 2; return 0;}
    if (strcmp(p, "PG_API_FLAG_GRO_COALESCE") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_pg_create_interface_t *vl_api_pg_create_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_create_interface_t);
    vl_api_pg_create_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface_id");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->interface_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gso_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->gso_enabled);

    item = cJSON_GetObjectItem(o, "gso_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->gso_size);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_create_interface_v2_t *vl_api_pg_create_interface_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_create_interface_v2_t);
    vl_api_pg_create_interface_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface_id");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->interface_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gso_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->gso_enabled);

    item = cJSON_GetObjectItem(o, "gso_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->gso_size);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_pg_interface_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_create_interface_v3_t *vl_api_pg_create_interface_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_create_interface_v3_t);
    vl_api_pg_create_interface_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface_id");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->interface_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pg_flags");
    if (!item) goto error;
    if (vl_api_pg_interface_flags_t_fromjson((void **)&a, &l, item, &a->pg_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "gso_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->gso_size);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_pg_interface_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_create_interface_reply_t *vl_api_pg_create_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_create_interface_reply_t);
    vl_api_pg_create_interface_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pg_create_interface_v2_reply_t *vl_api_pg_create_interface_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_create_interface_v2_reply_t);
    vl_api_pg_create_interface_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pg_create_interface_v3_reply_t *vl_api_pg_create_interface_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_create_interface_v3_reply_t);
    vl_api_pg_create_interface_v3_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pg_delete_interface_t *vl_api_pg_delete_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_delete_interface_t);
    vl_api_pg_delete_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_delete_interface_reply_t *vl_api_pg_delete_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_delete_interface_reply_t);
    vl_api_pg_delete_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_interface_enable_disable_coalesce_t *vl_api_pg_interface_enable_disable_coalesce_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_interface_enable_disable_coalesce_t);
    vl_api_pg_interface_enable_disable_coalesce_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "coalesce_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->coalesce_enabled);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_interface_enable_disable_coalesce_reply_t *vl_api_pg_interface_enable_disable_coalesce_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_interface_enable_disable_coalesce_reply_t);
    vl_api_pg_interface_enable_disable_coalesce_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_capture_t *vl_api_pg_capture_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_capture_t);
    vl_api_pg_capture_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "interface_id");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->interface_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enabled);

    item = cJSON_GetObjectItem(o, "count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->count);

    item = cJSON_GetObjectItem(o, "pcap_file_name");
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
static inline vl_api_pg_capture_reply_t *vl_api_pg_capture_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_capture_reply_t);
    vl_api_pg_capture_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pg_enable_disable_t *vl_api_pg_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_enable_disable_t);
    vl_api_pg_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enabled);

    item = cJSON_GetObjectItem(o, "stream_name");
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
static inline vl_api_pg_enable_disable_reply_t *vl_api_pg_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pg_enable_disable_reply_t);
    vl_api_pg_enable_disable_reply_t *a = cJSON_malloc(l);

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
