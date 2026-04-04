/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_nsh_api_fromjson_h
#define included_nsh_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_nsh_add_del_entry_t *vl_api_nsh_add_del_entry_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_add_del_entry_t);
    vl_api_nsh_add_del_entry_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "nsp_nsi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsp_nsi);

    item = cJSON_GetObjectItem(o, "md_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->md_type);

    item = cJSON_GetObjectItem(o, "ver_o_c");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ver_o_c);

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ttl);

    item = cJSON_GetObjectItem(o, "length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->length);

    item = cJSON_GetObjectItem(o, "next_protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->next_protocol);

    item = cJSON_GetObjectItem(o, "c1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c1);

    item = cJSON_GetObjectItem(o, "c2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c2);

    item = cJSON_GetObjectItem(o, "c3");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c3);

    item = cJSON_GetObjectItem(o, "c4");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c4);

    item = cJSON_GetObjectItem(o, "tlv_length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tlv_length);

    item = cJSON_GetObjectItem(o, "tlv");
    if (!item) goto error;
    if (u8string_fromjson2(o, "tlv", a->tlv) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_add_del_entry_reply_t *vl_api_nsh_add_del_entry_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_add_del_entry_reply_t);
    vl_api_nsh_add_del_entry_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "entry_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->entry_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_entry_dump_t *vl_api_nsh_entry_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_entry_dump_t);
    vl_api_nsh_entry_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->entry_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_entry_details_t *vl_api_nsh_entry_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_entry_details_t);
    vl_api_nsh_entry_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->entry_index);

    item = cJSON_GetObjectItem(o, "nsp_nsi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsp_nsi);

    item = cJSON_GetObjectItem(o, "md_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->md_type);

    item = cJSON_GetObjectItem(o, "ver_o_c");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ver_o_c);

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ttl);

    item = cJSON_GetObjectItem(o, "length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->length);

    item = cJSON_GetObjectItem(o, "next_protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->next_protocol);

    item = cJSON_GetObjectItem(o, "c1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c1);

    item = cJSON_GetObjectItem(o, "c2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c2);

    item = cJSON_GetObjectItem(o, "c3");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c3);

    item = cJSON_GetObjectItem(o, "c4");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->c4);

    item = cJSON_GetObjectItem(o, "tlv_length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tlv_length);

    item = cJSON_GetObjectItem(o, "tlv");
    if (!item) goto error;
    if (u8string_fromjson2(o, "tlv", a->tlv) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_add_del_map_t *vl_api_nsh_add_del_map_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_add_del_map_t);
    vl_api_nsh_add_del_map_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "nsp_nsi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsp_nsi);

    item = cJSON_GetObjectItem(o, "mapped_nsp_nsi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mapped_nsp_nsi);

    item = cJSON_GetObjectItem(o, "nsh_action");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsh_action);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "next_node");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->next_node);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_add_del_map_reply_t *vl_api_nsh_add_del_map_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_add_del_map_reply_t);
    vl_api_nsh_add_del_map_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "map_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->map_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_map_dump_t *vl_api_nsh_map_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_map_dump_t);
    vl_api_nsh_map_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "map_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->map_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nsh_map_details_t *vl_api_nsh_map_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nsh_map_details_t);
    vl_api_nsh_map_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "map_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->map_index);

    item = cJSON_GetObjectItem(o, "nsp_nsi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsp_nsi);

    item = cJSON_GetObjectItem(o, "mapped_nsp_nsi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mapped_nsp_nsi);

    item = cJSON_GetObjectItem(o, "nsh_action");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsh_action);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "next_node");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->next_node);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
