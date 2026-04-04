/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <nat/lib/nat_types.api_tojson.h>
#ifndef included_nat44_ei_api_tojson_h
#define included_nat44_ei_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nat44_ei_config_flags_t_tojson (vl_api_nat44_ei_config_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("NAT44_EI_NONE");
    case 1:
        return cJSON_CreateString("NAT44_EI_STATIC_MAPPING_ONLY");
    case 2:
        return cJSON_CreateString("NAT44_EI_CONNECTION_TRACKING");
    case 4:
        return cJSON_CreateString("NAT44_EI_OUT2IN_DPO");
    case 8:
        return cJSON_CreateString("NAT44_EI_ADDR_ONLY_MAPPING");
    case 16:
        return cJSON_CreateString("NAT44_EI_IF_INSIDE");
    case 32:
        return cJSON_CreateString("NAT44_EI_IF_OUTSIDE");
    case 64:
        return cJSON_CreateString("NAT44_EI_STATIC_MAPPING");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_nat44_ei_plugin_enable_disable_t_tojson (vl_api_nat44_ei_plugin_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_plugin_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "bf692144");
    cJSON_AddNumberToObject(o, "inside_vrf", a->inside_vrf);
    cJSON_AddNumberToObject(o, "outside_vrf", a->outside_vrf);
    cJSON_AddNumberToObject(o, "users", a->users);
    cJSON_AddNumberToObject(o, "user_memory", a->user_memory);
    cJSON_AddNumberToObject(o, "sessions", a->sessions);
    cJSON_AddNumberToObject(o, "session_memory", a->session_memory);
    cJSON_AddNumberToObject(o, "user_sessions", a->user_sessions);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_ei_plugin_enable_disable_reply_t_tojson (vl_api_nat44_ei_plugin_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_plugin_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_show_running_config_t_tojson (vl_api_nat44_ei_show_running_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_show_running_config");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_show_running_config_reply_t_tojson (vl_api_nat44_ei_show_running_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_show_running_config_reply");
    cJSON_AddStringToObject(o, "_crc", "41b66a81");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "inside_vrf", a->inside_vrf);
    cJSON_AddNumberToObject(o, "outside_vrf", a->outside_vrf);
    cJSON_AddNumberToObject(o, "users", a->users);
    cJSON_AddNumberToObject(o, "sessions", a->sessions);
    cJSON_AddNumberToObject(o, "user_sessions", a->user_sessions);
    cJSON_AddNumberToObject(o, "user_buckets", a->user_buckets);
    cJSON_AddNumberToObject(o, "translation_buckets", a->translation_buckets);
    cJSON_AddBoolToObject(o, "forwarding_enabled", a->forwarding_enabled);
    cJSON_AddBoolToObject(o, "ipfix_logging_enabled", a->ipfix_logging_enabled);
    cJSON_AddItemToObject(o, "timeouts", vl_api_nat_timeouts_t_tojson(&a->timeouts));
    cJSON_AddItemToObject(o, "log_level", vl_api_nat_log_level_t_tojson(a->log_level));
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_log_level_t_tojson (vl_api_nat44_ei_set_log_level_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_log_level");
    cJSON_AddStringToObject(o, "_crc", "70076bfe");
    cJSON_AddItemToObject(o, "log_level", vl_api_nat_log_level_t_tojson(a->log_level));
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_log_level_reply_t_tojson (vl_api_nat44_ei_set_log_level_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_log_level_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_workers_t_tojson (vl_api_nat44_ei_set_workers_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_workers");
    cJSON_AddStringToObject(o, "_crc", "da926638");
    cJSON_AddNumberToObject(o, "worker_mask", a->worker_mask);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_workers_reply_t_tojson (vl_api_nat44_ei_set_workers_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_workers_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_worker_dump_t_tojson (vl_api_nat44_ei_worker_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_worker_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_worker_details_t_tojson (vl_api_nat44_ei_worker_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_worker_details");
    cJSON_AddStringToObject(o, "_crc", "84bf06fc");
    cJSON_AddNumberToObject(o, "worker_index", a->worker_index);
    cJSON_AddNumberToObject(o, "lcore_id", a->lcore_id);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ipfix_enable_disable_t_tojson (vl_api_nat44_ei_ipfix_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ipfix_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "9af4a2d2");
    cJSON_AddNumberToObject(o, "domain_id", a->domain_id);
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ipfix_enable_disable_reply_t_tojson (vl_api_nat44_ei_ipfix_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ipfix_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_timeouts_t_tojson (vl_api_nat44_ei_set_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_timeouts");
    cJSON_AddStringToObject(o, "_crc", "d4746b16");
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_timeouts_reply_t_tojson (vl_api_nat44_ei_set_timeouts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_timeouts_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_tojson (vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_addr_and_port_alloc_alg");
    cJSON_AddStringToObject(o, "_crc", "deeb746f");
    cJSON_AddNumberToObject(o, "alg", a->alg);
    cJSON_AddNumberToObject(o, "psid_offset", a->psid_offset);
    cJSON_AddNumberToObject(o, "psid_length", a->psid_length);
    cJSON_AddNumberToObject(o, "psid", a->psid);
    cJSON_AddNumberToObject(o, "start_port", a->start_port);
    cJSON_AddNumberToObject(o, "end_port", a->end_port);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t_tojson (vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_addr_and_port_alloc_alg_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_tojson (vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_get_addr_and_port_alloc_alg");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t_tojson (vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_get_addr_and_port_alloc_alg_reply");
    cJSON_AddStringToObject(o, "_crc", "3607a7d0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "alg", a->alg);
    cJSON_AddNumberToObject(o, "psid_offset", a->psid_offset);
    cJSON_AddNumberToObject(o, "psid_length", a->psid_length);
    cJSON_AddNumberToObject(o, "psid", a->psid);
    cJSON_AddNumberToObject(o, "start_port", a->start_port);
    cJSON_AddNumberToObject(o, "end_port", a->end_port);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_mss_clamping_t_tojson (vl_api_nat44_ei_set_mss_clamping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_mss_clamping");
    cJSON_AddStringToObject(o, "_crc", "25e90abb");
    cJSON_AddNumberToObject(o, "mss_value", a->mss_value);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_mss_clamping_reply_t_tojson (vl_api_nat44_ei_set_mss_clamping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_mss_clamping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_get_mss_clamping_t_tojson (vl_api_nat44_ei_get_mss_clamping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_get_mss_clamping");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_get_mss_clamping_reply_t_tojson (vl_api_nat44_ei_get_mss_clamping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_get_mss_clamping_reply");
    cJSON_AddStringToObject(o, "_crc", "1c0b2a78");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "mss_value", a->mss_value);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_set_listener_t_tojson (vl_api_nat44_ei_ha_set_listener_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_set_listener");
    cJSON_AddStringToObject(o, "_crc", "e4a8cb4e");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_set_listener_reply_t_tojson (vl_api_nat44_ei_ha_set_listener_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_set_listener_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_set_failover_t_tojson (vl_api_nat44_ei_ha_set_failover_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_set_failover");
    cJSON_AddStringToObject(o, "_crc", "718246af");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "session_refresh_interval", a->session_refresh_interval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_set_failover_reply_t_tojson (vl_api_nat44_ei_ha_set_failover_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_set_failover_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_get_listener_t_tojson (vl_api_nat44_ei_ha_get_listener_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_get_listener");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_get_listener_reply_t_tojson (vl_api_nat44_ei_ha_get_listener_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_get_listener_reply");
    cJSON_AddStringToObject(o, "_crc", "123ea41f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "path_mtu", a->path_mtu);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_get_failover_t_tojson (vl_api_nat44_ei_ha_get_failover_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_get_failover");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_get_failover_reply_t_tojson (vl_api_nat44_ei_ha_get_failover_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_get_failover_reply");
    cJSON_AddStringToObject(o, "_crc", "a67d8752");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "session_refresh_interval", a->session_refresh_interval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_flush_t_tojson (vl_api_nat44_ei_ha_flush_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_flush");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_flush_reply_t_tojson (vl_api_nat44_ei_ha_flush_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_flush_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_resync_t_tojson (vl_api_nat44_ei_ha_resync_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_resync");
    cJSON_AddStringToObject(o, "_crc", "c8ab9e03");
    cJSON_AddNumberToObject(o, "want_resync_event", a->want_resync_event);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_resync_reply_t_tojson (vl_api_nat44_ei_ha_resync_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_resync_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_ha_resync_completed_event_t_tojson (vl_api_nat44_ei_ha_resync_completed_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_ha_resync_completed_event");
    cJSON_AddStringToObject(o, "_crc", "fdc598fb");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "missed_count", a->missed_count);
    return o;
}
static inline cJSON *vl_api_nat44_ei_del_user_t_tojson (vl_api_nat44_ei_del_user_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_del_user");
    cJSON_AddStringToObject(o, "_crc", "99a9f998");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "fib_index", a->fib_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_del_user_reply_t_tojson (vl_api_nat44_ei_del_user_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_del_user_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_address_range_t_tojson (vl_api_nat44_ei_add_del_address_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_address_range");
    cJSON_AddStringToObject(o, "_crc", "35f21abc");
    cJSON_AddItemToObject(o, "first_ip_address", vl_api_ip4_address_t_tojson(&a->first_ip_address));
    cJSON_AddItemToObject(o, "last_ip_address", vl_api_ip4_address_t_tojson(&a->last_ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_address_range_reply_t_tojson (vl_api_nat44_ei_add_del_address_range_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_address_range_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_address_dump_t_tojson (vl_api_nat44_ei_address_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_address_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_address_details_t_tojson (vl_api_nat44_ei_address_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_address_details");
    cJSON_AddStringToObject(o, "_crc", "318f1202");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_add_del_feature_t_tojson (vl_api_nat44_ei_interface_add_del_feature_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_add_del_feature");
    cJSON_AddStringToObject(o, "_crc", "63a2db8b");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_add_del_feature_reply_t_tojson (vl_api_nat44_ei_interface_add_del_feature_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_add_del_feature_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_dump_t_tojson (vl_api_nat44_ei_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_details_t_tojson (vl_api_nat44_ei_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_details");
    cJSON_AddStringToObject(o, "_crc", "f446e508");
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_add_del_output_feature_t_tojson (vl_api_nat44_ei_interface_add_del_output_feature_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_add_del_output_feature");
    cJSON_AddStringToObject(o, "_crc", "63a2db8b");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_add_del_output_feature_reply_t_tojson (vl_api_nat44_ei_interface_add_del_output_feature_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_add_del_output_feature_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_output_feature_dump_t_tojson (vl_api_nat44_ei_interface_output_feature_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_output_feature_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_output_feature_details_t_tojson (vl_api_nat44_ei_interface_output_feature_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_output_feature_details");
    cJSON_AddStringToObject(o, "_crc", "f446e508");
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_output_interface_t_tojson (vl_api_nat44_ei_add_del_output_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_output_interface");
    cJSON_AddStringToObject(o, "_crc", "47d6e753");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_output_interface_reply_t_tojson (vl_api_nat44_ei_add_del_output_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_output_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_output_interface_get_t_tojson (vl_api_nat44_ei_output_interface_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_output_interface_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_nat44_ei_output_interface_get_reply_t_tojson (vl_api_nat44_ei_output_interface_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_output_interface_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_nat44_ei_output_interface_details_t_tojson (vl_api_nat44_ei_output_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_output_interface_details");
    cJSON_AddStringToObject(o, "_crc", "0b45011c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_static_mapping_t_tojson (vl_api_nat44_ei_add_del_static_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_static_mapping");
    cJSON_AddStringToObject(o, "_crc", "b404b7fe");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "local_ip_address", vl_api_ip4_address_t_tojson(&a->local_ip_address));
    cJSON_AddItemToObject(o, "external_ip_address", vl_api_ip4_address_t_tojson(&a->external_ip_address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "local_port", a->local_port);
    cJSON_AddNumberToObject(o, "external_port", a->external_port);
    cJSON_AddNumberToObject(o, "external_sw_if_index", a->external_sw_if_index);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_static_mapping_reply_t_tojson (vl_api_nat44_ei_add_del_static_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_static_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_static_mapping_dump_t_tojson (vl_api_nat44_ei_static_mapping_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_static_mapping_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_static_mapping_details_t_tojson (vl_api_nat44_ei_static_mapping_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_static_mapping_details");
    cJSON_AddStringToObject(o, "_crc", "6b51ca6e");
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "local_ip_address", vl_api_ip4_address_t_tojson(&a->local_ip_address));
    cJSON_AddItemToObject(o, "external_ip_address", vl_api_ip4_address_t_tojson(&a->external_ip_address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "local_port", a->local_port);
    cJSON_AddNumberToObject(o, "external_port", a->external_port);
    cJSON_AddNumberToObject(o, "external_sw_if_index", a->external_sw_if_index);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_identity_mapping_t_tojson (vl_api_nat44_ei_add_del_identity_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_identity_mapping");
    cJSON_AddStringToObject(o, "_crc", "cb8606b9");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_identity_mapping_reply_t_tojson (vl_api_nat44_ei_add_del_identity_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_identity_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_identity_mapping_dump_t_tojson (vl_api_nat44_ei_identity_mapping_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_identity_mapping_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_identity_mapping_details_t_tojson (vl_api_nat44_ei_identity_mapping_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_identity_mapping_details");
    cJSON_AddStringToObject(o, "_crc", "30d53e26");
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_interface_addr_t_tojson (vl_api_nat44_ei_add_del_interface_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_interface_addr");
    cJSON_AddStringToObject(o, "_crc", "883abbcc");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_ei_add_del_interface_addr_reply_t_tojson (vl_api_nat44_ei_add_del_interface_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_add_del_interface_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_addr_dump_t_tojson (vl_api_nat44_ei_interface_addr_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_addr_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_interface_addr_details_t_tojson (vl_api_nat44_ei_interface_addr_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_interface_addr_details");
    cJSON_AddStringToObject(o, "_crc", "0b45011c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ei_user_dump_t_tojson (vl_api_nat44_ei_user_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_user_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_user_details_t_tojson (vl_api_nat44_ei_user_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_user_details");
    cJSON_AddStringToObject(o, "_crc", "355896c2");
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "nsessions", a->nsessions);
    cJSON_AddNumberToObject(o, "nstaticsessions", a->nstaticsessions);
    return o;
}
static inline cJSON *vl_api_nat44_ei_user_session_dump_t_tojson (vl_api_nat44_ei_user_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_user_session_dump");
    cJSON_AddStringToObject(o, "_crc", "e1899c98");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_ei_user_session_details_t_tojson (vl_api_nat44_ei_user_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_user_session_details");
    cJSON_AddStringToObject(o, "_crc", "19b7c0ac");
    cJSON_AddItemToObject(o, "outside_ip_address", vl_api_ip4_address_t_tojson(&a->outside_ip_address));
    cJSON_AddNumberToObject(o, "outside_port", a->outside_port);
    cJSON_AddItemToObject(o, "inside_ip_address", vl_api_ip4_address_t_tojson(&a->inside_ip_address));
    cJSON_AddNumberToObject(o, "inside_port", a->inside_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "last_heard", a->last_heard);
    cJSON_AddNumberToObject(o, "total_bytes", a->total_bytes);
    cJSON_AddNumberToObject(o, "total_pkts", a->total_pkts);
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    return o;
}
static inline cJSON *vl_api_nat44_ei_user_session_v2_dump_t_tojson (vl_api_nat44_ei_user_session_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_user_session_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "e1899c98");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_ei_user_session_v2_details_t_tojson (vl_api_nat44_ei_user_session_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_user_session_v2_details");
    cJSON_AddStringToObject(o, "_crc", "5bd3e9d6");
    cJSON_AddItemToObject(o, "outside_ip_address", vl_api_ip4_address_t_tojson(&a->outside_ip_address));
    cJSON_AddNumberToObject(o, "outside_port", a->outside_port);
    cJSON_AddItemToObject(o, "inside_ip_address", vl_api_ip4_address_t_tojson(&a->inside_ip_address));
    cJSON_AddNumberToObject(o, "inside_port", a->inside_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "last_heard", a->last_heard);
    cJSON_AddNumberToObject(o, "time_since_last_heard", a->time_since_last_heard);
    cJSON_AddNumberToObject(o, "total_bytes", a->total_bytes);
    cJSON_AddNumberToObject(o, "total_pkts", a->total_pkts);
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    return o;
}
static inline cJSON *vl_api_nat44_ei_del_session_t_tojson (vl_api_nat44_ei_del_session_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_del_session");
    cJSON_AddStringToObject(o, "_crc", "74969ffe");
    cJSON_AddItemToObject(o, "address", vl_api_ip4_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_ei_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    return o;
}
static inline cJSON *vl_api_nat44_ei_del_session_reply_t_tojson (vl_api_nat44_ei_del_session_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_del_session_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_forwarding_enable_disable_t_tojson (vl_api_nat44_ei_forwarding_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_forwarding_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "b3e225d2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat44_ei_forwarding_enable_disable_reply_t_tojson (vl_api_nat44_ei_forwarding_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_forwarding_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_fq_options_t_tojson (vl_api_nat44_ei_set_fq_options_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_fq_options");
    cJSON_AddStringToObject(o, "_crc", "2399bd71");
    cJSON_AddNumberToObject(o, "frame_queue_nelts", a->frame_queue_nelts);
    return o;
}
static inline cJSON *vl_api_nat44_ei_set_fq_options_reply_t_tojson (vl_api_nat44_ei_set_fq_options_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_set_fq_options_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ei_show_fq_options_t_tojson (vl_api_nat44_ei_show_fq_options_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_show_fq_options");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ei_show_fq_options_reply_t_tojson (vl_api_nat44_ei_show_fq_options_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ei_show_fq_options_reply");
    cJSON_AddStringToObject(o, "_crc", "7213b545");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "frame_queue_nelts", a->frame_queue_nelts);
    return o;
}
#endif
