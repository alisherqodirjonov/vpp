/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_ip6_nd_api_tojson_h
#define included_ip6_nd_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ip6nd_ra_prefix_t_tojson (vl_api_ip6nd_ra_prefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddBoolToObject(o, "onlink_flag", a->onlink_flag);
    cJSON_AddBoolToObject(o, "autonomous_flag", a->autonomous_flag);
    cJSON_AddNumberToObject(o, "val_lifetime", a->val_lifetime);
    cJSON_AddNumberToObject(o, "pref_lifetime", a->pref_lifetime);
    cJSON_AddNumberToObject(o, "valid_lifetime_expires", a->valid_lifetime_expires);
    cJSON_AddNumberToObject(o, "pref_lifetime_expires", a->pref_lifetime_expires);
    cJSON_AddBoolToObject(o, "decrement_lifetime_flag", a->decrement_lifetime_flag);
    cJSON_AddBoolToObject(o, "no_advertise", a->no_advertise);
    return o;
}
static inline cJSON *vl_api_ip6_ra_prefix_info_t_tojson (vl_api_ip6_ra_prefix_info_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddNumberToObject(o, "valid_time", a->valid_time);
    cJSON_AddNumberToObject(o, "preferred_time", a->preferred_time);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6nd_ra_config_t_tojson (vl_api_sw_interface_ip6nd_ra_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6nd_ra_config");
    cJSON_AddStringToObject(o, "_crc", "3eb00b1c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "suppress", a->suppress);
    cJSON_AddNumberToObject(o, "managed", a->managed);
    cJSON_AddNumberToObject(o, "other", a->other);
    cJSON_AddNumberToObject(o, "ll_option", a->ll_option);
    cJSON_AddNumberToObject(o, "send_unicast", a->send_unicast);
    cJSON_AddNumberToObject(o, "cease", a->cease);
    cJSON_AddBoolToObject(o, "is_no", a->is_no);
    cJSON_AddNumberToObject(o, "default_router", a->default_router);
    cJSON_AddNumberToObject(o, "max_interval", a->max_interval);
    cJSON_AddNumberToObject(o, "min_interval", a->min_interval);
    cJSON_AddNumberToObject(o, "lifetime", a->lifetime);
    cJSON_AddNumberToObject(o, "initial_count", a->initial_count);
    cJSON_AddNumberToObject(o, "initial_interval", a->initial_interval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6nd_ra_config_reply_t_tojson (vl_api_sw_interface_ip6nd_ra_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6nd_ra_config_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6nd_ra_prefix_t_tojson (vl_api_sw_interface_ip6nd_ra_prefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6nd_ra_prefix");
    cJSON_AddStringToObject(o, "_crc", "82cc1b28");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddBoolToObject(o, "use_default", a->use_default);
    cJSON_AddBoolToObject(o, "no_advertise", a->no_advertise);
    cJSON_AddBoolToObject(o, "off_link", a->off_link);
    cJSON_AddBoolToObject(o, "no_autoconfig", a->no_autoconfig);
    cJSON_AddBoolToObject(o, "no_onlink", a->no_onlink);
    cJSON_AddBoolToObject(o, "is_no", a->is_no);
    cJSON_AddNumberToObject(o, "val_lifetime", a->val_lifetime);
    cJSON_AddNumberToObject(o, "pref_lifetime", a->pref_lifetime);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6nd_ra_prefix_reply_t_tojson (vl_api_sw_interface_ip6nd_ra_prefix_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6nd_ra_prefix_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6nd_ra_dump_t_tojson (vl_api_sw_interface_ip6nd_ra_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6nd_ra_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_ip6nd_ra_details_t_tojson (vl_api_sw_interface_ip6nd_ra_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_ip6nd_ra_details");
    cJSON_AddStringToObject(o, "_crc", "d3198de5");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "cur_hop_limit", a->cur_hop_limit);
    cJSON_AddBoolToObject(o, "adv_managed_flag", a->adv_managed_flag);
    cJSON_AddBoolToObject(o, "adv_other_flag", a->adv_other_flag);
    cJSON_AddNumberToObject(o, "adv_router_lifetime", a->adv_router_lifetime);
    cJSON_AddNumberToObject(o, "adv_neighbor_reachable_time", a->adv_neighbor_reachable_time);
    cJSON_AddNumberToObject(o, "adv_retransmit_interval", a->adv_retransmit_interval);
    cJSON_AddNumberToObject(o, "adv_link_mtu", a->adv_link_mtu);
    cJSON_AddBoolToObject(o, "send_radv", a->send_radv);
    cJSON_AddBoolToObject(o, "cease_radv", a->cease_radv);
    cJSON_AddBoolToObject(o, "send_unicast", a->send_unicast);
    cJSON_AddBoolToObject(o, "adv_link_layer_address", a->adv_link_layer_address);
    cJSON_AddNumberToObject(o, "max_radv_interval", a->max_radv_interval);
    cJSON_AddNumberToObject(o, "min_radv_interval", a->min_radv_interval);
    cJSON_AddNumberToObject(o, "last_radv_time", a->last_radv_time);
    cJSON_AddNumberToObject(o, "last_multicast_time", a->last_multicast_time);
    cJSON_AddNumberToObject(o, "next_multicast_time", a->next_multicast_time);
    cJSON_AddNumberToObject(o, "initial_adverts_count", a->initial_adverts_count);
    cJSON_AddNumberToObject(o, "initial_adverts_interval", a->initial_adverts_interval);
    cJSON_AddBoolToObject(o, "initial_adverts_sent", a->initial_adverts_sent);
    cJSON_AddNumberToObject(o, "n_advertisements_sent", a->n_advertisements_sent);
    cJSON_AddNumberToObject(o, "n_solicitations_rcvd", a->n_solicitations_rcvd);
    cJSON_AddNumberToObject(o, "n_solicitations_dropped", a->n_solicitations_dropped);
    cJSON_AddNumberToObject(o, "n_prefixes", a->n_prefixes);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "prefixes");
        for (i = 0; i < a->n_prefixes; i++) {
            cJSON_AddItemToArray(array, vl_api_ip6nd_ra_prefix_t_tojson(&a->prefixes[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_ip6nd_proxy_enable_disable_t_tojson (vl_api_ip6nd_proxy_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_proxy_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "7daa1e3a");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_ip6nd_proxy_enable_disable_reply_t_tojson (vl_api_ip6nd_proxy_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_proxy_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip6nd_proxy_add_del_t_tojson (vl_api_ip6nd_proxy_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_proxy_add_del");
    cJSON_AddStringToObject(o, "_crc", "c2e4a686");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "ip", vl_api_ip6_address_t_tojson(&a->ip));
    return o;
}
static inline cJSON *vl_api_ip6nd_proxy_add_del_reply_t_tojson (vl_api_ip6nd_proxy_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_proxy_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip6nd_proxy_details_t_tojson (vl_api_ip6nd_proxy_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_proxy_details");
    cJSON_AddStringToObject(o, "_crc", "30b9ff4a");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "ip", vl_api_ip6_address_t_tojson(&a->ip));
    return o;
}
static inline cJSON *vl_api_ip6nd_proxy_dump_t_tojson (vl_api_ip6nd_proxy_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_proxy_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ip6nd_send_router_solicitation_t_tojson (vl_api_ip6nd_send_router_solicitation_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_send_router_solicitation");
    cJSON_AddStringToObject(o, "_crc", "e5de609c");
    cJSON_AddNumberToObject(o, "irt", a->irt);
    cJSON_AddNumberToObject(o, "mrt", a->mrt);
    cJSON_AddNumberToObject(o, "mrc", a->mrc);
    cJSON_AddNumberToObject(o, "mrd", a->mrd);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "stop", a->stop);
    return o;
}
static inline cJSON *vl_api_ip6nd_send_router_solicitation_reply_t_tojson (vl_api_ip6nd_send_router_solicitation_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6nd_send_router_solicitation_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_ip6_ra_events_t_tojson (vl_api_want_ip6_ra_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ip6_ra_events");
    cJSON_AddStringToObject(o, "_crc", "3ec6d6c2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_ip6_ra_events_reply_t_tojson (vl_api_want_ip6_ra_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ip6_ra_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip6_ra_event_t_tojson (vl_api_ip6_ra_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip6_ra_event");
    cJSON_AddStringToObject(o, "_crc", "0364c1c5");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "router_addr", vl_api_ip6_address_t_tojson(&a->router_addr));
    cJSON_AddNumberToObject(o, "current_hop_limit", a->current_hop_limit);
    cJSON_AddNumberToObject(o, "flags", a->flags);
    cJSON_AddNumberToObject(o, "router_lifetime_in_sec", a->router_lifetime_in_sec);
    cJSON_AddNumberToObject(o, "neighbor_reachable_time_in_msec", a->neighbor_reachable_time_in_msec);
    cJSON_AddNumberToObject(o, "time_in_msec_between_retransmitted_neighbor_solicitations", a->time_in_msec_between_retransmitted_neighbor_solicitations);
    cJSON_AddNumberToObject(o, "n_prefixes", a->n_prefixes);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "prefixes");
        for (i = 0; i < a->n_prefixes; i++) {
            cJSON_AddItemToArray(array, vl_api_ip6_ra_prefix_info_t_tojson(&a->prefixes[i]));
        }
    }
    return o;
}
#endif
