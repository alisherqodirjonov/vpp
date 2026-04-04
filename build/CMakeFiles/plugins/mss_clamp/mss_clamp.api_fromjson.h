/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_mss_clamp_api_fromjson_h
#define included_mss_clamp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_mss_clamp_dir_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mss_clamp_dir_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "MSS_CLAMP_DIR_NONE") == 0) *a |= 0;
       if (strcmp(p, "MSS_CLAMP_DIR_RX") == 0) *a |= 1;
       if (strcmp(p, "MSS_CLAMP_DIR_TX") == 0) *a |= 2;
    }
   return 0;
}
static inline vl_api_mss_clamp_enable_disable_t *vl_api_mss_clamp_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mss_clamp_enable_disable_t);
    vl_api_mss_clamp_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ipv4_mss");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ipv4_mss);

    item = cJSON_GetObjectItem(o, "ipv6_mss");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ipv6_mss);

    item = cJSON_GetObjectItem(o, "ipv4_direction");
    if (!item) goto error;
    if (vl_api_mss_clamp_dir_t_fromjson((void **)&a, &l, item, &a->ipv4_direction) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ipv6_direction");
    if (!item) goto error;
    if (vl_api_mss_clamp_dir_t_fromjson((void **)&a, &l, item, &a->ipv6_direction) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mss_clamp_enable_disable_reply_t *vl_api_mss_clamp_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mss_clamp_enable_disable_reply_t);
    vl_api_mss_clamp_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mss_clamp_get_t *vl_api_mss_clamp_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mss_clamp_get_t);
    vl_api_mss_clamp_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_mss_clamp_get_reply_t *vl_api_mss_clamp_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mss_clamp_get_reply_t);
    vl_api_mss_clamp_get_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_mss_clamp_details_t *vl_api_mss_clamp_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_mss_clamp_details_t);
    vl_api_mss_clamp_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ipv4_mss");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ipv4_mss);

    item = cJSON_GetObjectItem(o, "ipv6_mss");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ipv6_mss);

    item = cJSON_GetObjectItem(o, "ipv4_direction");
    if (!item) goto error;
    if (vl_api_mss_clamp_dir_t_fromjson((void **)&a, &l, item, &a->ipv4_direction) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ipv6_direction");
    if (!item) goto error;
    if (vl_api_mss_clamp_dir_t_fromjson((void **)&a, &l, item, &a->ipv6_direction) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
