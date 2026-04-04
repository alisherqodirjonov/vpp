/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_interface_api_fromjson_h
#define included_interface_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_sw_interface_set_flags_t *vl_api_sw_interface_set_flags_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_flags_t);
    vl_api_sw_interface_set_flags_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_if_status_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_flags_reply_t *vl_api_sw_interface_set_flags_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_flags_reply_t);
    vl_api_sw_interface_set_flags_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_promisc_t *vl_api_sw_interface_set_promisc_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_promisc_t);
    vl_api_sw_interface_set_promisc_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "promisc_on");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->promisc_on);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_promisc_reply_t *vl_api_sw_interface_set_promisc_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_promisc_reply_t);
    vl_api_sw_interface_set_promisc_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_hw_interface_set_mtu_t *vl_api_hw_interface_set_mtu_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_hw_interface_set_mtu_t);
    vl_api_hw_interface_set_mtu_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mtu");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->mtu);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_hw_interface_set_mtu_reply_t *vl_api_hw_interface_set_mtu_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_hw_interface_set_mtu_reply_t);
    vl_api_hw_interface_set_mtu_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_mtu_t *vl_api_sw_interface_set_mtu_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_mtu_t);
    vl_api_sw_interface_set_mtu_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mtu");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "mtu");
        int size = cJSON_GetArraySize(array);
        if (size != 4) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &a->mtu[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_mtu_reply_t *vl_api_sw_interface_set_mtu_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_mtu_reply_t);
    vl_api_sw_interface_set_mtu_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_ip_directed_broadcast_t *vl_api_sw_interface_set_ip_directed_broadcast_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_ip_directed_broadcast_t);
    vl_api_sw_interface_set_ip_directed_broadcast_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_ip_directed_broadcast_reply_t *vl_api_sw_interface_set_ip_directed_broadcast_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_ip_directed_broadcast_reply_t);
    vl_api_sw_interface_set_ip_directed_broadcast_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_event_t *vl_api_sw_interface_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_event_t);
    vl_api_sw_interface_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_if_status_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "deleted");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->deleted);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_interface_events_t *vl_api_want_interface_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_interface_events_t);
    vl_api_want_interface_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_interface_events_reply_t *vl_api_want_interface_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_interface_events_reply_t);
    vl_api_want_interface_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_details_t *vl_api_sw_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_details_t);
    vl_api_sw_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sup_sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sup_sw_if_index);

    item = cJSON_GetObjectItem(o, "l2_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->l2_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_if_status_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_if_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "link_duplex");
    if (!item) goto error;
    if (vl_api_link_duplex_t_fromjson((void **)&a, &l, item, &a->link_duplex) < 0) goto error;

    item = cJSON_GetObjectItem(o, "link_speed");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->link_speed);

    item = cJSON_GetObjectItem(o, "link_mtu");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->link_mtu);

    item = cJSON_GetObjectItem(o, "mtu");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "mtu");
        int size = cJSON_GetArraySize(array);
        if (size != 4) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &a->mtu[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "sub_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sub_id);

    item = cJSON_GetObjectItem(o, "sub_number_of_tags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sub_number_of_tags);

    item = cJSON_GetObjectItem(o, "sub_outer_vlan_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->sub_outer_vlan_id);

    item = cJSON_GetObjectItem(o, "sub_inner_vlan_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->sub_inner_vlan_id);

    item = cJSON_GetObjectItem(o, "sub_if_flags");
    if (!item) goto error;
    if (vl_api_sub_if_flags_t_fromjson((void **)&a, &l, item, &a->sub_if_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vtr_op");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vtr_op);

    item = cJSON_GetObjectItem(o, "vtr_push_dot1q");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vtr_push_dot1q);

    item = cJSON_GetObjectItem(o, "vtr_tag1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vtr_tag1);

    item = cJSON_GetObjectItem(o, "vtr_tag2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vtr_tag2);

    item = cJSON_GetObjectItem(o, "outer_tag");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->outer_tag);

    item = cJSON_GetObjectItem(o, "b_dmac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->b_dmac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "b_smac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->b_smac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "b_vlanid");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->b_vlanid);

    item = cJSON_GetObjectItem(o, "i_sid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->i_sid);

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    item = cJSON_GetObjectItem(o, "interface_dev_type");
    if (!item) goto error;
    strncpy_s((char *)a->interface_dev_type, sizeof(a->interface_dev_type), cJSON_GetStringValue(item), sizeof(a->interface_dev_type) - 1);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_dump_t *vl_api_sw_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_dump_t);
    vl_api_sw_interface_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "name_filter_valid");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->name_filter_valid);

    item = cJSON_GetObjectItem(o, "name_filter");
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
static inline vl_api_sw_interface_add_del_address_t *vl_api_sw_interface_add_del_address_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_add_del_address_t);
    vl_api_sw_interface_add_del_address_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "del_all");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->del_all);

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_add_del_address_reply_t *vl_api_sw_interface_add_del_address_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_add_del_address_reply_t);
    vl_api_sw_interface_add_del_address_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_address_replace_begin_t *vl_api_sw_interface_address_replace_begin_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_address_replace_begin_t);
    vl_api_sw_interface_address_replace_begin_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sw_interface_address_replace_begin_reply_t *vl_api_sw_interface_address_replace_begin_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_address_replace_begin_reply_t);
    vl_api_sw_interface_address_replace_begin_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_address_replace_end_t *vl_api_sw_interface_address_replace_end_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_address_replace_end_t);
    vl_api_sw_interface_address_replace_end_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sw_interface_address_replace_end_reply_t *vl_api_sw_interface_address_replace_end_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_address_replace_end_reply_t);
    vl_api_sw_interface_address_replace_end_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_table_t *vl_api_sw_interface_set_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_table_t);
    vl_api_sw_interface_set_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_table_reply_t *vl_api_sw_interface_set_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_table_reply_t);
    vl_api_sw_interface_set_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_get_table_t *vl_api_sw_interface_get_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_get_table_t);
    vl_api_sw_interface_get_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_ipv6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_ipv6);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_get_table_reply_t *vl_api_sw_interface_get_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_get_table_reply_t);
    vl_api_sw_interface_get_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_unnumbered_t *vl_api_sw_interface_set_unnumbered_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_unnumbered_t);
    vl_api_sw_interface_set_unnumbered_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "unnumbered_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->unnumbered_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_unnumbered_reply_t *vl_api_sw_interface_set_unnumbered_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_unnumbered_reply_t);
    vl_api_sw_interface_set_unnumbered_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_clear_stats_t *vl_api_sw_interface_clear_stats_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_clear_stats_t);
    vl_api_sw_interface_clear_stats_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_clear_stats_reply_t *vl_api_sw_interface_clear_stats_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_clear_stats_reply_t);
    vl_api_sw_interface_clear_stats_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_tag_add_del_t *vl_api_sw_interface_tag_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tag_add_del_t);
    vl_api_sw_interface_tag_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_tag_add_del_reply_t *vl_api_sw_interface_tag_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tag_add_del_reply_t);
    vl_api_sw_interface_tag_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_add_del_mac_address_t *vl_api_sw_interface_add_del_mac_address_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_add_del_mac_address_t);
    vl_api_sw_interface_add_del_mac_address_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_add_del_mac_address_reply_t *vl_api_sw_interface_add_del_mac_address_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_add_del_mac_address_reply_t);
    vl_api_sw_interface_add_del_mac_address_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_mac_address_t *vl_api_sw_interface_set_mac_address_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_mac_address_t);
    vl_api_sw_interface_set_mac_address_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_mac_address_reply_t *vl_api_sw_interface_set_mac_address_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_mac_address_reply_t);
    vl_api_sw_interface_set_mac_address_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_get_mac_address_t *vl_api_sw_interface_get_mac_address_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_get_mac_address_t);
    vl_api_sw_interface_get_mac_address_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_get_mac_address_reply_t *vl_api_sw_interface_get_mac_address_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_get_mac_address_reply_t);
    vl_api_sw_interface_get_mac_address_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_rx_mode_t *vl_api_sw_interface_set_rx_mode_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_rx_mode_t);
    vl_api_sw_interface_set_rx_mode_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "queue_id_valid");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->queue_id_valid);

    item = cJSON_GetObjectItem(o, "queue_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_id);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_rx_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_rx_mode_reply_t *vl_api_sw_interface_set_rx_mode_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_rx_mode_reply_t);
    vl_api_sw_interface_set_rx_mode_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_rx_placement_t *vl_api_sw_interface_set_rx_placement_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_rx_placement_t);
    vl_api_sw_interface_set_rx_placement_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "queue_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_id);

    item = cJSON_GetObjectItem(o, "worker_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker_id);

    item = cJSON_GetObjectItem(o, "is_main");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_main);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_rx_placement_reply_t *vl_api_sw_interface_set_rx_placement_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_rx_placement_reply_t);
    vl_api_sw_interface_set_rx_placement_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_tx_placement_t *vl_api_sw_interface_set_tx_placement_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_tx_placement_t);
    vl_api_sw_interface_set_tx_placement_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "queue_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_id);

    item = cJSON_GetObjectItem(o, "threads");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "threads");
        int size = cJSON_GetArraySize(array);
        a->array_size = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_tx_placement_reply_t *vl_api_sw_interface_set_tx_placement_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_tx_placement_reply_t);
    vl_api_sw_interface_set_tx_placement_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_interface_name_t *vl_api_sw_interface_set_interface_name_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_interface_name_t);
    vl_api_sw_interface_set_interface_name_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_interface_name_reply_t *vl_api_sw_interface_set_interface_name_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_interface_name_reply_t);
    vl_api_sw_interface_set_interface_name_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_rx_placement_dump_t *vl_api_sw_interface_rx_placement_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_rx_placement_dump_t);
    vl_api_sw_interface_rx_placement_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_rx_placement_details_t *vl_api_sw_interface_rx_placement_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_rx_placement_details_t);
    vl_api_sw_interface_rx_placement_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "queue_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_id);

    item = cJSON_GetObjectItem(o, "worker_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker_id);

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_rx_mode_t_fromjson((void **)&a, &l, item, &a->mode) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_tx_placement_get_t *vl_api_sw_interface_tx_placement_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tx_placement_get_t);
    vl_api_sw_interface_tx_placement_get_t *a = cJSON_malloc(l);

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
static inline vl_api_sw_interface_tx_placement_get_reply_t *vl_api_sw_interface_tx_placement_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tx_placement_get_reply_t);
    vl_api_sw_interface_tx_placement_get_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_sw_interface_tx_placement_details_t *vl_api_sw_interface_tx_placement_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_tx_placement_details_t);
    vl_api_sw_interface_tx_placement_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "queue_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->queue_id);

    item = cJSON_GetObjectItem(o, "shared");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->shared);

    item = cJSON_GetObjectItem(o, "threads");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "threads");
        int size = cJSON_GetArraySize(array);
        a->array_size = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_interface_name_renumber_t *vl_api_interface_name_renumber_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_interface_name_renumber_t);
    vl_api_interface_name_renumber_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "new_show_dev_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->new_show_dev_instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_interface_name_renumber_reply_t *vl_api_interface_name_renumber_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_interface_name_renumber_reply_t);
    vl_api_interface_name_renumber_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_subif_t *vl_api_create_subif_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_subif_t);
    vl_api_create_subif_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sub_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sub_id);

    item = cJSON_GetObjectItem(o, "sub_if_flags");
    if (!item) goto error;
    if (vl_api_sub_if_flags_t_fromjson((void **)&a, &l, item, &a->sub_if_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "outer_vlan_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->outer_vlan_id);

    item = cJSON_GetObjectItem(o, "inner_vlan_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->inner_vlan_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_subif_reply_t *vl_api_create_subif_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_subif_reply_t);
    vl_api_create_subif_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_create_vlan_subif_t *vl_api_create_vlan_subif_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_vlan_subif_t);
    vl_api_create_vlan_subif_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vlan_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vlan_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_vlan_subif_reply_t *vl_api_create_vlan_subif_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_vlan_subif_reply_t);
    vl_api_create_vlan_subif_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_delete_subif_t *vl_api_delete_subif_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_delete_subif_t);
    vl_api_delete_subif_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_delete_subif_reply_t *vl_api_delete_subif_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_delete_subif_reply_t);
    vl_api_delete_subif_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_loopback_t *vl_api_create_loopback_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_loopback_t);
    vl_api_create_loopback_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_loopback_reply_t *vl_api_create_loopback_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_loopback_reply_t);
    vl_api_create_loopback_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_create_loopback_instance_t *vl_api_create_loopback_instance_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_loopback_instance_t);
    vl_api_create_loopback_instance_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mac_address");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_specified");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_specified);

    item = cJSON_GetObjectItem(o, "user_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_create_loopback_instance_reply_t *vl_api_create_loopback_instance_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_create_loopback_instance_reply_t);
    vl_api_create_loopback_instance_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_delete_loopback_t *vl_api_delete_loopback_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_delete_loopback_t);
    vl_api_delete_loopback_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_delete_loopback_reply_t *vl_api_delete_loopback_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_delete_loopback_reply_t);
    vl_api_delete_loopback_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_collect_detailed_interface_stats_t *vl_api_collect_detailed_interface_stats_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_collect_detailed_interface_stats_t);
    vl_api_collect_detailed_interface_stats_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_collect_detailed_interface_stats_reply_t *vl_api_collect_detailed_interface_stats_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_collect_detailed_interface_stats_reply_t);
    vl_api_collect_detailed_interface_stats_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pcap_set_filter_function_t *vl_api_pcap_set_filter_function_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pcap_set_filter_function_t);
    vl_api_pcap_set_filter_function_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "filter_function_name");
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
static inline vl_api_pcap_set_filter_function_reply_t *vl_api_pcap_set_filter_function_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pcap_set_filter_function_reply_t);
    vl_api_pcap_set_filter_function_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pcap_trace_on_t *vl_api_pcap_trace_on_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pcap_trace_on_t);
    vl_api_pcap_trace_on_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "capture_rx");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->capture_rx);

    item = cJSON_GetObjectItem(o, "capture_tx");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->capture_tx);

    item = cJSON_GetObjectItem(o, "capture_drop");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->capture_drop);

    item = cJSON_GetObjectItem(o, "filter");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->filter);

    item = cJSON_GetObjectItem(o, "preallocate_data");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->preallocate_data);

    item = cJSON_GetObjectItem(o, "free_data");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->free_data);

    item = cJSON_GetObjectItem(o, "max_packets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_packets);

    item = cJSON_GetObjectItem(o, "max_bytes_per_packet");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_bytes_per_packet);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "error");
    if (!item) goto error;
    strncpy_s((char *)a->error, sizeof(a->error), cJSON_GetStringValue(item), sizeof(a->error) - 1);

    item = cJSON_GetObjectItem(o, "filename");
    if (!item) goto error;
    strncpy_s((char *)a->filename, sizeof(a->filename), cJSON_GetStringValue(item), sizeof(a->filename) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pcap_trace_on_reply_t *vl_api_pcap_trace_on_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pcap_trace_on_reply_t);
    vl_api_pcap_trace_on_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pcap_trace_off_t *vl_api_pcap_trace_off_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pcap_trace_off_t);
    vl_api_pcap_trace_off_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_pcap_trace_off_reply_t *vl_api_pcap_trace_off_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pcap_trace_off_reply_t);
    vl_api_pcap_trace_off_reply_t *a = cJSON_malloc(l);

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
