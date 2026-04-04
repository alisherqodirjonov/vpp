/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_ip6_nd_api_fromjson_h
#define included_ip6_nd_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ip6nd_ra_prefix_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip6nd_ra_prefix_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "onlink_flag");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->onlink_flag);

    item = cJSON_GetObjectItem(o, "autonomous_flag");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->autonomous_flag);

    item = cJSON_GetObjectItem(o, "val_lifetime");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->val_lifetime);

    item = cJSON_GetObjectItem(o, "pref_lifetime");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pref_lifetime);

    item = cJSON_GetObjectItem(o, "valid_lifetime_expires");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->valid_lifetime_expires);

    item = cJSON_GetObjectItem(o, "pref_lifetime_expires");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->pref_lifetime_expires);

    item = cJSON_GetObjectItem(o, "decrement_lifetime_flag");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->decrement_lifetime_flag);

    item = cJSON_GetObjectItem(o, "no_advertise");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_advertise);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ip6_ra_prefix_info_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip6_ra_prefix_info_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "valid_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->valid_time);

    item = cJSON_GetObjectItem(o, "preferred_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->preferred_time);

    return 0;

  error:
    return -1;
}
static inline vl_api_sw_interface_ip6nd_ra_config_t *vl_api_sw_interface_ip6nd_ra_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6nd_ra_config_t);
    vl_api_sw_interface_ip6nd_ra_config_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "suppress");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->suppress);

    item = cJSON_GetObjectItem(o, "managed");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->managed);

    item = cJSON_GetObjectItem(o, "other");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->other);

    item = cJSON_GetObjectItem(o, "ll_option");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ll_option);

    item = cJSON_GetObjectItem(o, "send_unicast");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->send_unicast);

    item = cJSON_GetObjectItem(o, "cease");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->cease);

    item = cJSON_GetObjectItem(o, "is_no");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_no);

    item = cJSON_GetObjectItem(o, "default_router");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->default_router);

    item = cJSON_GetObjectItem(o, "max_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_interval);

    item = cJSON_GetObjectItem(o, "min_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->min_interval);

    item = cJSON_GetObjectItem(o, "lifetime");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->lifetime);

    item = cJSON_GetObjectItem(o, "initial_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->initial_count);

    item = cJSON_GetObjectItem(o, "initial_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->initial_interval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6nd_ra_config_reply_t *vl_api_sw_interface_ip6nd_ra_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6nd_ra_config_reply_t);
    vl_api_sw_interface_ip6nd_ra_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6nd_ra_prefix_t *vl_api_sw_interface_ip6nd_ra_prefix_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6nd_ra_prefix_t);
    vl_api_sw_interface_ip6nd_ra_prefix_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "use_default");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_default);

    item = cJSON_GetObjectItem(o, "no_advertise");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_advertise);

    item = cJSON_GetObjectItem(o, "off_link");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->off_link);

    item = cJSON_GetObjectItem(o, "no_autoconfig");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_autoconfig);

    item = cJSON_GetObjectItem(o, "no_onlink");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->no_onlink);

    item = cJSON_GetObjectItem(o, "is_no");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_no);

    item = cJSON_GetObjectItem(o, "val_lifetime");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->val_lifetime);

    item = cJSON_GetObjectItem(o, "pref_lifetime");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pref_lifetime);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6nd_ra_prefix_reply_t *vl_api_sw_interface_ip6nd_ra_prefix_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6nd_ra_prefix_reply_t);
    vl_api_sw_interface_ip6nd_ra_prefix_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6nd_ra_dump_t *vl_api_sw_interface_ip6nd_ra_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6nd_ra_dump_t);
    vl_api_sw_interface_ip6nd_ra_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_ip6nd_ra_details_t *vl_api_sw_interface_ip6nd_ra_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_ip6nd_ra_details_t);
    vl_api_sw_interface_ip6nd_ra_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "cur_hop_limit");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->cur_hop_limit);

    item = cJSON_GetObjectItem(o, "adv_managed_flag");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->adv_managed_flag);

    item = cJSON_GetObjectItem(o, "adv_other_flag");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->adv_other_flag);

    item = cJSON_GetObjectItem(o, "adv_router_lifetime");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->adv_router_lifetime);

    item = cJSON_GetObjectItem(o, "adv_neighbor_reachable_time");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->adv_neighbor_reachable_time);

    item = cJSON_GetObjectItem(o, "adv_retransmit_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->adv_retransmit_interval);

    item = cJSON_GetObjectItem(o, "adv_link_mtu");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->adv_link_mtu);

    item = cJSON_GetObjectItem(o, "send_radv");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->send_radv);

    item = cJSON_GetObjectItem(o, "cease_radv");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->cease_radv);

    item = cJSON_GetObjectItem(o, "send_unicast");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->send_unicast);

    item = cJSON_GetObjectItem(o, "adv_link_layer_address");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->adv_link_layer_address);

    item = cJSON_GetObjectItem(o, "max_radv_interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->max_radv_interval);

    item = cJSON_GetObjectItem(o, "min_radv_interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->min_radv_interval);

    item = cJSON_GetObjectItem(o, "last_radv_time");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->last_radv_time);

    item = cJSON_GetObjectItem(o, "last_multicast_time");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->last_multicast_time);

    item = cJSON_GetObjectItem(o, "next_multicast_time");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->next_multicast_time);

    item = cJSON_GetObjectItem(o, "initial_adverts_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->initial_adverts_count);

    item = cJSON_GetObjectItem(o, "initial_adverts_interval");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->initial_adverts_interval);

    item = cJSON_GetObjectItem(o, "initial_adverts_sent");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->initial_adverts_sent);

    item = cJSON_GetObjectItem(o, "n_advertisements_sent");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->n_advertisements_sent);

    item = cJSON_GetObjectItem(o, "n_solicitations_rcvd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->n_solicitations_rcvd);

    item = cJSON_GetObjectItem(o, "n_solicitations_dropped");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->n_solicitations_dropped);

    item = cJSON_GetObjectItem(o, "prefixes");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "prefixes");
        int size = cJSON_GetArraySize(array);
        a->n_prefixes = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_ip6nd_ra_prefix_t) * size);
        vl_api_ip6nd_ra_prefix_t *d = (void *)a + l;
        l += sizeof(vl_api_ip6nd_ra_prefix_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_ip6nd_ra_prefix_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_proxy_enable_disable_t *vl_api_ip6nd_proxy_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_proxy_enable_disable_t);
    vl_api_ip6nd_proxy_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_proxy_enable_disable_reply_t *vl_api_ip6nd_proxy_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_proxy_enable_disable_reply_t);
    vl_api_ip6nd_proxy_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_proxy_add_del_t *vl_api_ip6nd_proxy_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_proxy_add_del_t);
    vl_api_ip6nd_proxy_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_proxy_add_del_reply_t *vl_api_ip6nd_proxy_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_proxy_add_del_reply_t);
    vl_api_ip6nd_proxy_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_proxy_details_t *vl_api_ip6nd_proxy_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_proxy_details_t);
    vl_api_ip6nd_proxy_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_proxy_dump_t *vl_api_ip6nd_proxy_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_proxy_dump_t);
    vl_api_ip6nd_proxy_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_ip6nd_send_router_solicitation_t *vl_api_ip6nd_send_router_solicitation_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_send_router_solicitation_t);
    vl_api_ip6nd_send_router_solicitation_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "irt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->irt);

    item = cJSON_GetObjectItem(o, "mrt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrt);

    item = cJSON_GetObjectItem(o, "mrc");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrc);

    item = cJSON_GetObjectItem(o, "mrd");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mrd);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "stop");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->stop);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6nd_send_router_solicitation_reply_t *vl_api_ip6nd_send_router_solicitation_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6nd_send_router_solicitation_reply_t);
    vl_api_ip6nd_send_router_solicitation_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ip6_ra_events_t *vl_api_want_ip6_ra_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ip6_ra_events_t);
    vl_api_want_ip6_ra_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_ip6_ra_events_reply_t *vl_api_want_ip6_ra_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_ip6_ra_events_reply_t);
    vl_api_want_ip6_ra_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_ip6_ra_event_t *vl_api_ip6_ra_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_ip6_ra_event_t);
    vl_api_ip6_ra_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "router_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->router_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "current_hop_limit");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->current_hop_limit);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    item = cJSON_GetObjectItem(o, "router_lifetime_in_sec");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->router_lifetime_in_sec);

    item = cJSON_GetObjectItem(o, "neighbor_reachable_time_in_msec");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->neighbor_reachable_time_in_msec);

    item = cJSON_GetObjectItem(o, "time_in_msec_between_retransmitted_neighbor_solicitations");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->time_in_msec_between_retransmitted_neighbor_solicitations);

    item = cJSON_GetObjectItem(o, "prefixes");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "prefixes");
        int size = cJSON_GetArraySize(array);
        a->n_prefixes = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_ip6_ra_prefix_info_t) * size);
        vl_api_ip6_ra_prefix_info_t *d = (void *)a + l;
        l += sizeof(vl_api_ip6_ra_prefix_info_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_ip6_ra_prefix_info_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
