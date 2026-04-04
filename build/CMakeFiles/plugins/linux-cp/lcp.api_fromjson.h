/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_lcp_api_fromjson_h
#define included_lcp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_lcp_itf_host_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lcp_itf_host_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LCP_API_ITF_HOST_TAP") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LCP_API_ITF_HOST_TUN") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_lcp_default_ns_set_t *vl_api_lcp_default_ns_set_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_default_ns_set_t);
    vl_api_lcp_default_ns_set_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_default_ns_set_reply_t *vl_api_lcp_default_ns_set_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_default_ns_set_reply_t);
    vl_api_lcp_default_ns_set_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_default_ns_get_t *vl_api_lcp_default_ns_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_default_ns_get_t);
    vl_api_lcp_default_ns_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lcp_default_ns_get_reply_t *vl_api_lcp_default_ns_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_default_ns_get_reply_t);
    vl_api_lcp_default_ns_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_add_del_t *vl_api_lcp_itf_pair_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_add_del_t);
    vl_api_lcp_itf_pair_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_if_type");
    if (!item) goto error;
    if (vl_api_lcp_itf_host_type_t_fromjson((void **)&a, &l, item, &a->host_if_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_add_del_reply_t *vl_api_lcp_itf_pair_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_add_del_reply_t);
    vl_api_lcp_itf_pair_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_add_del_v2_t *vl_api_lcp_itf_pair_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_add_del_v2_t);
    vl_api_lcp_itf_pair_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_if_type");
    if (!item) goto error;
    if (vl_api_lcp_itf_host_type_t_fromjson((void **)&a, &l, item, &a->host_if_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_add_del_v2_reply_t *vl_api_lcp_itf_pair_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_add_del_v2_reply_t);
    vl_api_lcp_itf_pair_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "host_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->host_sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_add_del_v3_t *vl_api_lcp_itf_pair_add_del_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_add_del_v3_t);
    vl_api_lcp_itf_pair_add_del_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_if_type");
    if (!item) goto error;
    if (vl_api_lcp_itf_host_type_t_fromjson((void **)&a, &l, item, &a->host_if_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_add_del_v3_reply_t *vl_api_lcp_itf_pair_add_del_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_add_del_v3_reply_t);
    vl_api_lcp_itf_pair_add_del_v3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vif_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vif_index);

    item = cJSON_GetObjectItem(o, "host_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->host_sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_get_t *vl_api_lcp_itf_pair_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_get_t);
    vl_api_lcp_itf_pair_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_get_reply_t *vl_api_lcp_itf_pair_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_get_reply_t);
    vl_api_lcp_itf_pair_get_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_lcp_itf_pair_get_v2_t *vl_api_lcp_itf_pair_get_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_get_v2_t);
    vl_api_lcp_itf_pair_get_v2_t *a = cJSON_malloc(l);

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
static inline vl_api_lcp_itf_pair_get_v2_reply_t *vl_api_lcp_itf_pair_get_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_get_v2_reply_t);
    vl_api_lcp_itf_pair_get_v2_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_lcp_itf_pair_details_t *vl_api_lcp_itf_pair_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_details_t);
    vl_api_lcp_itf_pair_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "phy_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->phy_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "host_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->host_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vif_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vif_index);

    item = cJSON_GetObjectItem(o, "host_if_name");
    if (!item) goto error;
    strncpy_s((char *)a->host_if_name, sizeof(a->host_if_name), cJSON_GetStringValue(item), sizeof(a->host_if_name) - 1);

    item = cJSON_GetObjectItem(o, "host_if_type");
    if (!item) goto error;
    if (vl_api_lcp_itf_host_type_t_fromjson((void **)&a, &l, item, &a->host_if_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_ethertype_enable_t *vl_api_lcp_ethertype_enable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_ethertype_enable_t);
    vl_api_lcp_ethertype_enable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ethertype");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ethertype);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_ethertype_enable_reply_t *vl_api_lcp_ethertype_enable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_ethertype_enable_reply_t);
    vl_api_lcp_ethertype_enable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_ethertype_get_t *vl_api_lcp_ethertype_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_ethertype_get_t);
    vl_api_lcp_ethertype_get_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lcp_ethertype_get_reply_t *vl_api_lcp_ethertype_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_ethertype_get_reply_t);
    vl_api_lcp_ethertype_get_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "ethertypes");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "ethertypes");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u16) * size);
        u16 *d = (void *)a + l;
        l += sizeof(u16) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u16_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_replace_begin_t *vl_api_lcp_itf_pair_replace_begin_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_replace_begin_t);
    vl_api_lcp_itf_pair_replace_begin_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lcp_itf_pair_replace_begin_reply_t *vl_api_lcp_itf_pair_replace_begin_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_replace_begin_reply_t);
    vl_api_lcp_itf_pair_replace_begin_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lcp_itf_pair_replace_end_t *vl_api_lcp_itf_pair_replace_end_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_replace_end_t);
    vl_api_lcp_itf_pair_replace_end_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_lcp_itf_pair_replace_end_reply_t *vl_api_lcp_itf_pair_replace_end_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lcp_itf_pair_replace_end_reply_t);
    vl_api_lcp_itf_pair_replace_end_reply_t *a = cJSON_malloc(l);

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
