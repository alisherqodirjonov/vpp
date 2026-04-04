/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/fib/fib_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip.api_fromjson.h>
#ifndef included_cnat_api_fromjson_h
#define included_cnat_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_cnat_translation_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_cnat_translation_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CNAT_TRANSLATION_ALLOC_PORT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "CNAT_TRANSLATION_NO_RETURN_SESSION") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_cnat_endpoint_tuple_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_cnat_endpoint_tuple_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CNAT_EPT_NO_NAT") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_cnat_lb_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_cnat_lb_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CNAT_LB_TYPE_DEFAULT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CNAT_LB_TYPE_MAGLEV") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_cnat_endpoint_t_fromjson (void **mp, int *len, cJSON *o, vl_api_cnat_endpoint_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "if_af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson(mp, len, item, &a->if_af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    return 0;

  error:
    return -1;
}
static inline int vl_api_cnat_endpoint_tuple_t_fromjson (void **mp, int *len, cJSON *o, vl_api_cnat_endpoint_tuple_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "dst_ep");
    if (!item) goto error;
    if (vl_api_cnat_endpoint_t_fromjson(mp, len, item, &a->dst_ep) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_ep");
    if (!item) goto error;
    if (vl_api_cnat_endpoint_t_fromjson(mp, len, item, &a->src_ep) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    return 0;

  error:
    return -1;
}
static inline int vl_api_cnat_translation_t_fromjson (void **mp, int *len, cJSON *o, vl_api_cnat_translation_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "vip");
    if (!item) goto error;
    if (vl_api_cnat_endpoint_t_fromjson(mp, len, item, &a->vip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "ip_proto");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->ip_proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_real_ip");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_real_ip);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "lb_type");
    if (!item) goto error;
    if (vl_api_cnat_lb_type_t_fromjson(mp, len, item, &a->lb_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flow_hash_config");
    if (!item) goto error;
    if (vl_api_ip_flow_hash_config_v2_t_fromjson(mp, len, item, &a->flow_hash_config) < 0) goto error;

    item = cJSON_GetObjectItem(o, "paths");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "paths");
        int size = cJSON_GetArraySize(array);
        a->n_paths = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(vl_api_cnat_endpoint_tuple_t) * size);
        vl_api_cnat_endpoint_tuple_t *d = (void *)*mp + *len;
        *len += sizeof(vl_api_cnat_endpoint_tuple_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_cnat_endpoint_tuple_t_fromjson(mp, len, e, &d[i]) < 0) goto error; 
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_cnat_session_t_fromjson (void **mp, int *len, cJSON *o, vl_api_cnat_session_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_cnat_endpoint_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_cnat_endpoint_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "new");
    if (!item) goto error;
    if (vl_api_cnat_endpoint_t_fromjson(mp, len, item, &a->new) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_proto");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->ip_proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "location");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->location);

    item = cJSON_GetObjectItem(o, "timestamp");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->timestamp);

    return 0;

  error:
    return -1;
}
static inline int vl_api_cnat_snat_policy_table_t_fromjson(void **mp, int *len, cJSON *o, vl_api_cnat_snat_policy_table_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CNAT_POLICY_INCLUDE_V4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CNAT_POLICY_INCLUDE_V6") == 0) {*a = 1; return 0;}
    if (strcmp(p, "CNAT_POLICY_POD") == 0) {*a = 2; return 0;}
    if (strcmp(p, "CNAT_POLICY_HOST") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_cnat_snat_policies_t_fromjson(void **mp, int *len, cJSON *o, vl_api_cnat_snat_policies_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CNAT_POLICY_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CNAT_POLICY_IF_PFX") == 0) {*a = 1; return 0;}
    if (strcmp(p, "CNAT_POLICY_K8S") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_cnat_translation_update_t *vl_api_cnat_translation_update_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_translation_update_t);
    vl_api_cnat_translation_update_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "translation");
    if (!item) goto error;
    if (vl_api_cnat_translation_t_fromjson((void **)&a, &l, item, &a->translation) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_translation_update_reply_t *vl_api_cnat_translation_update_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_translation_update_reply_t);
    vl_api_cnat_translation_update_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_translation_del_t *vl_api_cnat_translation_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_translation_del_t);
    vl_api_cnat_translation_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_translation_del_reply_t *vl_api_cnat_translation_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_translation_del_reply_t);
    vl_api_cnat_translation_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_translation_details_t *vl_api_cnat_translation_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_translation_details_t);
    vl_api_cnat_translation_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "translation");
    if (!item) goto error;
    if (vl_api_cnat_translation_t_fromjson((void **)&a, &l, item, &a->translation) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_translation_dump_t *vl_api_cnat_translation_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_translation_dump_t);
    vl_api_cnat_translation_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_cnat_session_purge_t *vl_api_cnat_session_purge_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_session_purge_t);
    vl_api_cnat_session_purge_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_cnat_session_purge_reply_t *vl_api_cnat_session_purge_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_session_purge_reply_t);
    vl_api_cnat_session_purge_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_session_details_t *vl_api_cnat_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_session_details_t);
    vl_api_cnat_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "session");
    if (!item) goto error;
    if (vl_api_cnat_session_t_fromjson((void **)&a, &l, item, &a->session) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_session_dump_t *vl_api_cnat_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_session_dump_t);
    vl_api_cnat_session_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_cnat_set_snat_addresses_t *vl_api_cnat_set_snat_addresses_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_set_snat_addresses_t);
    vl_api_cnat_set_snat_addresses_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "snat_ip4");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->snat_ip4) < 0) goto error;

    item = cJSON_GetObjectItem(o, "snat_ip6");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->snat_ip6) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_set_snat_addresses_reply_t *vl_api_cnat_set_snat_addresses_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_set_snat_addresses_reply_t);
    vl_api_cnat_set_snat_addresses_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_get_snat_addresses_t *vl_api_cnat_get_snat_addresses_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_get_snat_addresses_t);
    vl_api_cnat_get_snat_addresses_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_cnat_get_snat_addresses_reply_t *vl_api_cnat_get_snat_addresses_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_get_snat_addresses_reply_t);
    vl_api_cnat_get_snat_addresses_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "snat_ip4");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->snat_ip4) < 0) goto error;

    item = cJSON_GetObjectItem(o, "snat_ip6");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->snat_ip6) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_snat_policy_add_del_exclude_pfx_t *vl_api_cnat_snat_policy_add_del_exclude_pfx_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_snat_policy_add_del_exclude_pfx_t);
    vl_api_cnat_snat_policy_add_del_exclude_pfx_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t);
    vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_snat_policy_add_del_if_t *vl_api_cnat_snat_policy_add_del_if_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_snat_policy_add_del_if_t);
    vl_api_cnat_snat_policy_add_del_if_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "table");
    if (!item) goto error;
    if (vl_api_cnat_snat_policy_table_t_fromjson((void **)&a, &l, item, &a->table) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_snat_policy_add_del_if_reply_t *vl_api_cnat_snat_policy_add_del_if_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_snat_policy_add_del_if_reply_t);
    vl_api_cnat_snat_policy_add_del_if_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_set_snat_policy_t *vl_api_cnat_set_snat_policy_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_set_snat_policy_t);
    vl_api_cnat_set_snat_policy_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "policy");
    if (!item) goto error;
    if (vl_api_cnat_snat_policies_t_fromjson((void **)&a, &l, item, &a->policy) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cnat_set_snat_policy_reply_t *vl_api_cnat_set_snat_policy_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cnat_set_snat_policy_reply_t);
    vl_api_cnat_set_snat_policy_reply_t *a = cJSON_malloc(l);

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
