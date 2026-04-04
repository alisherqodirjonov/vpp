/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_pnat_api_fromjson_h
#define included_pnat_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_pnat_mask_t_fromjson(void **mp, int *len, cJSON *o, vl_api_pnat_mask_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "PNAT_SA") == 0) {*a = 1; return 0;}
    if (strcmp(p, "PNAT_DA") == 0) {*a = 2; return 0;}
    if (strcmp(p, "PNAT_SPORT") == 0) {*a = 4; return 0;}
    if (strcmp(p, "PNAT_DPORT") == 0) {*a = 8; return 0;}
    if (strcmp(p, "PNAT_COPY_BYTE") == 0) {*a = 16; return 0;}
    if (strcmp(p, "PNAT_CLEAR_BYTE") == 0) {*a = 32; return 0;}
    if (strcmp(p, "PNAT_PROTO") == 0) {*a = 64; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_pnat_attachment_point_t_fromjson(void **mp, int *len, cJSON *o, vl_api_pnat_attachment_point_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "PNAT_IP4_INPUT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "PNAT_IP4_OUTPUT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "PNAT_ATTACHMENT_POINT_MAX") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_pnat_match_tuple_t_fromjson (void **mp, int *len, cJSON *o, vl_api_pnat_match_tuple_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sport");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->sport);

    item = cJSON_GetObjectItem(o, "dport");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->dport);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    if (vl_api_pnat_mask_t_fromjson(mp, len, item, &a->mask) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_pnat_rewrite_tuple_t_fromjson (void **mp, int *len, cJSON *o, vl_api_pnat_rewrite_tuple_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sport");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->sport);

    item = cJSON_GetObjectItem(o, "dport");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->dport);

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    if (vl_api_pnat_mask_t_fromjson(mp, len, item, &a->mask) < 0) goto error;

    item = cJSON_GetObjectItem(o, "from_offset");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->from_offset);

    item = cJSON_GetObjectItem(o, "to_offset");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->to_offset);

    item = cJSON_GetObjectItem(o, "clear_offset");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->clear_offset);

    return 0;

  error:
    return -1;
}
static inline vl_api_pnat_binding_add_t *vl_api_pnat_binding_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_add_t);
    vl_api_pnat_binding_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (vl_api_pnat_match_tuple_t_fromjson((void **)&a, &l, item, &a->match) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rewrite");
    if (!item) goto error;
    if (vl_api_pnat_rewrite_tuple_t_fromjson((void **)&a, &l, item, &a->rewrite) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_add_reply_t *vl_api_pnat_binding_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_add_reply_t);
    vl_api_pnat_binding_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "binding_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->binding_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_add_v2_t *vl_api_pnat_binding_add_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_add_v2_t);
    vl_api_pnat_binding_add_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (vl_api_pnat_match_tuple_t_fromjson((void **)&a, &l, item, &a->match) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rewrite");
    if (!item) goto error;
    if (vl_api_pnat_rewrite_tuple_t_fromjson((void **)&a, &l, item, &a->rewrite) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_add_v2_reply_t *vl_api_pnat_binding_add_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_add_v2_reply_t);
    vl_api_pnat_binding_add_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "binding_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->binding_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_del_t *vl_api_pnat_binding_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_del_t);
    vl_api_pnat_binding_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "binding_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->binding_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_del_reply_t *vl_api_pnat_binding_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_del_reply_t);
    vl_api_pnat_binding_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_attach_t *vl_api_pnat_binding_attach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_attach_t);
    vl_api_pnat_binding_attach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "attachment");
    if (!item) goto error;
    if (vl_api_pnat_attachment_point_t_fromjson((void **)&a, &l, item, &a->attachment) < 0) goto error;

    item = cJSON_GetObjectItem(o, "binding_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->binding_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_attach_reply_t *vl_api_pnat_binding_attach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_attach_reply_t);
    vl_api_pnat_binding_attach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_detach_t *vl_api_pnat_binding_detach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_detach_t);
    vl_api_pnat_binding_detach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "attachment");
    if (!item) goto error;
    if (vl_api_pnat_attachment_point_t_fromjson((void **)&a, &l, item, &a->attachment) < 0) goto error;

    item = cJSON_GetObjectItem(o, "binding_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->binding_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_binding_detach_reply_t *vl_api_pnat_binding_detach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_binding_detach_reply_t);
    vl_api_pnat_binding_detach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_bindings_get_t *vl_api_pnat_bindings_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_bindings_get_t);
    vl_api_pnat_bindings_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_bindings_get_reply_t *vl_api_pnat_bindings_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_bindings_get_reply_t);
    vl_api_pnat_bindings_get_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pnat_bindings_details_t *vl_api_pnat_bindings_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_bindings_details_t);
    vl_api_pnat_bindings_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (vl_api_pnat_match_tuple_t_fromjson((void **)&a, &l, item, &a->match) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rewrite");
    if (!item) goto error;
    if (vl_api_pnat_rewrite_tuple_t_fromjson((void **)&a, &l, item, &a->rewrite) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_interfaces_get_t *vl_api_pnat_interfaces_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_interfaces_get_t);
    vl_api_pnat_interfaces_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_interfaces_get_reply_t *vl_api_pnat_interfaces_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_interfaces_get_reply_t);
    vl_api_pnat_interfaces_get_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_pnat_interfaces_details_t *vl_api_pnat_interfaces_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_interfaces_details_t);
    vl_api_pnat_interfaces_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enabled");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "enabled");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_bool_fromjson(e, &a->enabled[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "lookup_mask");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "lookup_mask");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_pnat_mask_t_fromjson((void **)&a, len, e, &a->lookup_mask[i]) < 0) goto error;
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_flow_lookup_t *vl_api_pnat_flow_lookup_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_flow_lookup_t);
    vl_api_pnat_flow_lookup_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "attachment");
    if (!item) goto error;
    if (vl_api_pnat_attachment_point_t_fromjson((void **)&a, &l, item, &a->attachment) < 0) goto error;

    item = cJSON_GetObjectItem(o, "match");
    if (!item) goto error;
    if (vl_api_pnat_match_tuple_t_fromjson((void **)&a, &l, item, &a->match) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pnat_flow_lookup_reply_t *vl_api_pnat_flow_lookup_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pnat_flow_lookup_reply_t);
    vl_api_pnat_flow_lookup_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "binding_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->binding_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
