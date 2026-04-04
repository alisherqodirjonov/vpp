/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/srv6/sr_types.api_fromjson.h>
#ifndef included_sr_api_fromjson_h
#define included_sr_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_srv6_sid_list_t_fromjson (void **mp, int *len, cJSON *o, vl_api_srv6_sid_list_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "num_sids");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->num_sids);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "sids");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sids");
        int size = cJSON_GetArraySize(array);
        if (size != 16) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_ip6_address_t_fromjson(mp, len, e, &a->sids[i]) < 0) goto error;
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_srv6_sid_list_with_sl_index_t_fromjson (void **mp, int *len, cJSON *o, vl_api_srv6_sid_list_with_sl_index_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "num_sids");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->num_sids);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "sl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sl_index);

    item = cJSON_GetObjectItem(o, "sids");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sids");
        int size = cJSON_GetArraySize(array);
        if (size != 16) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_ip6_address_t_fromjson(mp, len, e, &a->sids[i]) < 0) goto error;
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_sr_policy_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_sr_policy_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SR_API_POLICY_TYPE_DEFAULT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SR_API_POLICY_TYPE_SPRAY") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SR_API_POLICY_TYPE_TEF") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_sr_localsid_add_del_t *vl_api_sr_localsid_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_localsid_add_del_t);
    vl_api_sr_localsid_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    item = cJSON_GetObjectItem(o, "localsid");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->localsid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "end_psp");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->end_psp);

    item = cJSON_GetObjectItem(o, "behavior");
    if (!item) goto error;
    if (vl_api_sr_behavior_t_fromjson((void **)&a, &l, item, &a->behavior) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vlan_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vlan_index);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "nh_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->nh_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_localsid_add_del_reply_t *vl_api_sr_localsid_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_localsid_add_del_reply_t);
    vl_api_sr_localsid_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_add_t *vl_api_sr_policy_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_add_t);
    vl_api_sr_policy_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "is_encap");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_encap);

    item = cJSON_GetObjectItem(o, "is_spray");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_spray);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "sids");
    if (!item) goto error;
    if (vl_api_srv6_sid_list_t_fromjson((void **)&a, &l, item, &a->sids) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_add_reply_t *vl_api_sr_policy_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_add_reply_t);
    vl_api_sr_policy_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_mod_t *vl_api_sr_policy_mod_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_mod_t);
    vl_api_sr_policy_mod_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sr_policy_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sr_policy_index);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "operation");
    if (!item) goto error;
    if (vl_api_sr_policy_op_t_fromjson((void **)&a, &l, item, &a->operation) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sl_index);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "sids");
    if (!item) goto error;
    if (vl_api_srv6_sid_list_t_fromjson((void **)&a, &l, item, &a->sids) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_mod_reply_t *vl_api_sr_policy_mod_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_mod_reply_t);
    vl_api_sr_policy_mod_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_add_v2_t *vl_api_sr_policy_add_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_add_v2_t);
    vl_api_sr_policy_add_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "is_encap");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_encap);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_sr_policy_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "sids");
    if (!item) goto error;
    if (vl_api_srv6_sid_list_t_fromjson((void **)&a, &l, item, &a->sids) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_src");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->encap_src) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_add_v2_reply_t *vl_api_sr_policy_add_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_add_v2_reply_t);
    vl_api_sr_policy_add_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_mod_v2_t *vl_api_sr_policy_mod_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_mod_v2_t);
    vl_api_sr_policy_mod_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sr_policy_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sr_policy_index);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "operation");
    if (!item) goto error;
    if (vl_api_sr_policy_op_t_fromjson((void **)&a, &l, item, &a->operation) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sl_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sl_index);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "sids");
    if (!item) goto error;
    if (vl_api_srv6_sid_list_t_fromjson((void **)&a, &l, item, &a->sids) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_src");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->encap_src) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_mod_v2_reply_t *vl_api_sr_policy_mod_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_mod_v2_reply_t);
    vl_api_sr_policy_mod_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_del_t *vl_api_sr_policy_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_del_t);
    vl_api_sr_policy_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sr_policy_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sr_policy_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policy_del_reply_t *vl_api_sr_policy_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policy_del_reply_t);
    vl_api_sr_policy_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_set_encap_source_t *vl_api_sr_set_encap_source_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_set_encap_source_t);
    vl_api_sr_set_encap_source_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "encaps_source");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->encaps_source) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_set_encap_source_reply_t *vl_api_sr_set_encap_source_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_set_encap_source_reply_t);
    vl_api_sr_set_encap_source_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_set_encap_hop_limit_t *vl_api_sr_set_encap_hop_limit_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_set_encap_hop_limit_t);
    vl_api_sr_set_encap_hop_limit_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "hop_limit");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->hop_limit);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_set_encap_hop_limit_reply_t *vl_api_sr_set_encap_hop_limit_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_set_encap_hop_limit_reply_t);
    vl_api_sr_set_encap_hop_limit_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_steering_add_del_t *vl_api_sr_steering_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_steering_add_del_t);
    vl_api_sr_steering_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_del");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_del);

    item = cJSON_GetObjectItem(o, "bsid_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sr_policy_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sr_policy_index);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "traffic_type");
    if (!item) goto error;
    if (vl_api_sr_steer_t_fromjson((void **)&a, &l, item, &a->traffic_type) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_steering_add_del_reply_t *vl_api_sr_steering_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_steering_add_del_reply_t);
    vl_api_sr_steering_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_localsids_dump_t *vl_api_sr_localsids_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_localsids_dump_t);
    vl_api_sr_localsids_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_localsids_details_t *vl_api_sr_localsids_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_localsids_details_t);
    vl_api_sr_localsids_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "end_psp");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->end_psp);

    item = cJSON_GetObjectItem(o, "behavior");
    if (!item) goto error;
    if (vl_api_sr_behavior_t_fromjson((void **)&a, &l, item, &a->behavior) < 0) goto error;

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "vlan_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vlan_index);

    item = cJSON_GetObjectItem(o, "xconnect_nh_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->xconnect_nh_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "xconnect_iface_or_vrf_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->xconnect_iface_or_vrf_table);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_localsids_with_packet_stats_dump_t *vl_api_sr_localsids_with_packet_stats_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_localsids_with_packet_stats_dump_t);
    vl_api_sr_localsids_with_packet_stats_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_localsids_with_packet_stats_details_t *vl_api_sr_localsids_with_packet_stats_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_localsids_with_packet_stats_details_t);
    vl_api_sr_localsids_with_packet_stats_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "end_psp");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->end_psp);

    item = cJSON_GetObjectItem(o, "behavior");
    if (!item) goto error;
    if (vl_api_sr_behavior_t_fromjson((void **)&a, &l, item, &a->behavior) < 0) goto error;

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "vlan_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vlan_index);

    item = cJSON_GetObjectItem(o, "xconnect_nh_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->xconnect_nh_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "xconnect_iface_or_vrf_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->xconnect_iface_or_vrf_table);

    item = cJSON_GetObjectItem(o, "good_traffic_bytes");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->good_traffic_bytes);

    item = cJSON_GetObjectItem(o, "good_traffic_pkt_count");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->good_traffic_pkt_count);

    item = cJSON_GetObjectItem(o, "bad_traffic_bytes");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bad_traffic_bytes);

    item = cJSON_GetObjectItem(o, "bad_traffic_pkt_count");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bad_traffic_pkt_count);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policies_dump_t *vl_api_sr_policies_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policies_dump_t);
    vl_api_sr_policies_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_policies_details_t *vl_api_sr_policies_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policies_details_t);
    vl_api_sr_policies_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_spray");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_spray);

    item = cJSON_GetObjectItem(o, "is_encap");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_encap);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "sid_lists");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sid_lists");
        int size = cJSON_GetArraySize(array);
        a->num_sid_lists = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_srv6_sid_list_t) * size);
        vl_api_srv6_sid_list_t *d = (void *)a + l;
        l += sizeof(vl_api_srv6_sid_list_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_srv6_sid_list_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policies_v2_dump_t *vl_api_sr_policies_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policies_v2_dump_t);
    vl_api_sr_policies_v2_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_policies_v2_details_t *vl_api_sr_policies_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policies_v2_details_t);
    vl_api_sr_policies_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encap_src");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->encap_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_sr_policy_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_encap");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_encap);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "sid_lists");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sid_lists");
        int size = cJSON_GetArraySize(array);
        a->num_sid_lists = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_srv6_sid_list_t) * size);
        vl_api_srv6_sid_list_t *d = (void *)a + l;
        l += sizeof(vl_api_srv6_sid_list_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_srv6_sid_list_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_policies_with_sl_index_dump_t *vl_api_sr_policies_with_sl_index_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policies_with_sl_index_dump_t);
    vl_api_sr_policies_with_sl_index_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_policies_with_sl_index_details_t *vl_api_sr_policies_with_sl_index_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_policies_with_sl_index_details_t);
    vl_api_sr_policies_with_sl_index_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_spray");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_spray);

    item = cJSON_GetObjectItem(o, "is_encap");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_encap);

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "sid_lists");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sid_lists");
        int size = cJSON_GetArraySize(array);
        a->num_sid_lists = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_srv6_sid_list_with_sl_index_t) * size);
        vl_api_srv6_sid_list_with_sl_index_t *d = (void *)a + l;
        l += sizeof(vl_api_srv6_sid_list_with_sl_index_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_srv6_sid_list_with_sl_index_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sr_steering_pol_dump_t *vl_api_sr_steering_pol_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_steering_pol_dump_t);
    vl_api_sr_steering_pol_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sr_steering_pol_details_t *vl_api_sr_steering_pol_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sr_steering_pol_details_t);
    vl_api_sr_steering_pol_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "traffic_type");
    if (!item) goto error;
    if (vl_api_sr_steer_t_fromjson((void **)&a, &l, item, &a->traffic_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "fib_table");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->fib_table);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bsid");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->bsid) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
