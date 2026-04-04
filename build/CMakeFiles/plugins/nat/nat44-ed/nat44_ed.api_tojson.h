/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <nat/lib/nat_types.api_tojson.h>
#ifndef included_nat44_ed_api_tojson_h
#define included_nat44_ed_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nat44_config_flags_t_tojson (vl_api_nat44_config_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("NAT44_IS_ENDPOINT_INDEPENDENT");
    case 1:
        return cJSON_CreateString("NAT44_IS_ENDPOINT_DEPENDENT");
    case 2:
        return cJSON_CreateString("NAT44_IS_STATIC_MAPPING_ONLY");
    case 4:
        return cJSON_CreateString("NAT44_IS_CONNECTION_TRACKING");
    case 8:
        return cJSON_CreateString("NAT44_IS_OUT2IN_DPO");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_nat44_lb_addr_port_t_tojson (vl_api_nat44_lb_addr_port_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "addr", vl_api_ip4_address_t_tojson(&a->addr));
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "probability", a->probability);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_ed_plugin_enable_disable_t_tojson (vl_api_nat44_ed_plugin_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_plugin_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "be17f8dd");
    cJSON_AddNumberToObject(o, "inside_vrf", a->inside_vrf);
    cJSON_AddNumberToObject(o, "outside_vrf", a->outside_vrf);
    cJSON_AddNumberToObject(o, "sessions", a->sessions);
    cJSON_AddNumberToObject(o, "session_memory", a->session_memory);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_ed_plugin_enable_disable_reply_t_tojson (vl_api_nat44_ed_plugin_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_plugin_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_forwarding_enable_disable_t_tojson (vl_api_nat44_forwarding_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_forwarding_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "b3e225d2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat44_forwarding_enable_disable_reply_t_tojson (vl_api_nat44_forwarding_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_forwarding_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_ipfix_enable_disable_t_tojson (vl_api_nat_ipfix_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_ipfix_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "9af4a2d2");
    cJSON_AddNumberToObject(o, "domain_id", a->domain_id);
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat_ipfix_enable_disable_reply_t_tojson (vl_api_nat_ipfix_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_ipfix_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_set_timeouts_t_tojson (vl_api_nat_set_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_set_timeouts");
    cJSON_AddStringToObject(o, "_crc", "d4746b16");
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_nat_set_timeouts_reply_t_tojson (vl_api_nat_set_timeouts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_set_timeouts_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_set_session_limit_t_tojson (vl_api_nat44_set_session_limit_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_set_session_limit");
    cJSON_AddStringToObject(o, "_crc", "8899bbb1");
    cJSON_AddNumberToObject(o, "session_limit", a->session_limit);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_set_session_limit_reply_t_tojson (vl_api_nat44_set_session_limit_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_set_session_limit_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_show_running_config_t_tojson (vl_api_nat44_show_running_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_show_running_config");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_show_running_config_reply_t_tojson (vl_api_nat44_show_running_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_show_running_config_reply");
    cJSON_AddStringToObject(o, "_crc", "93d8e267");
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
    cJSON_AddItemToObject(o, "flags", vl_api_nat44_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat_set_workers_t_tojson (vl_api_nat_set_workers_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_set_workers");
    cJSON_AddStringToObject(o, "_crc", "da926638");
    cJSON_AddNumberToObject(o, "worker_mask", a->worker_mask);
    return o;
}
static inline cJSON *vl_api_nat_set_workers_reply_t_tojson (vl_api_nat_set_workers_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_set_workers_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_worker_dump_t_tojson (vl_api_nat_worker_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_worker_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat_worker_details_t_tojson (vl_api_nat_worker_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_worker_details");
    cJSON_AddStringToObject(o, "_crc", "84bf06fc");
    cJSON_AddNumberToObject(o, "worker_index", a->worker_index);
    cJSON_AddNumberToObject(o, "lcore_id", a->lcore_id);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_nat44_ed_add_del_vrf_table_t_tojson (vl_api_nat44_ed_add_del_vrf_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_add_del_vrf_table");
    cJSON_AddStringToObject(o, "_crc", "08330904");
    cJSON_AddNumberToObject(o, "table_vrf_id", a->table_vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_nat44_ed_add_del_vrf_table_reply_t_tojson (vl_api_nat44_ed_add_del_vrf_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_add_del_vrf_table_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ed_add_del_vrf_route_t_tojson (vl_api_nat44_ed_add_del_vrf_route_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_add_del_vrf_route");
    cJSON_AddStringToObject(o, "_crc", "59187407");
    cJSON_AddNumberToObject(o, "table_vrf_id", a->table_vrf_id);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_nat44_ed_add_del_vrf_route_reply_t_tojson (vl_api_nat44_ed_add_del_vrf_route_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_add_del_vrf_route_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ed_vrf_tables_dump_t_tojson (vl_api_nat44_ed_vrf_tables_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_vrf_tables_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ed_vrf_tables_details_t_tojson (vl_api_nat44_ed_vrf_tables_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_vrf_tables_details");
    cJSON_AddStringToObject(o, "_crc", "7b264e4f");
    cJSON_AddNumberToObject(o, "table_vrf_id", a->table_vrf_id);
    cJSON_AddNumberToObject(o, "n_vrf_ids", a->n_vrf_ids);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "vrf_ids");
        for (i = 0; i < a->n_vrf_ids; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->vrf_ids[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_nat44_ed_vrf_tables_v2_dump_t_tojson (vl_api_nat44_ed_vrf_tables_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_vrf_tables_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ed_vrf_tables_v2_details_t_tojson (vl_api_nat44_ed_vrf_tables_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_vrf_tables_v2_details");
    cJSON_AddStringToObject(o, "_crc", "7b264e4f");
    cJSON_AddNumberToObject(o, "table_vrf_id", a->table_vrf_id);
    cJSON_AddNumberToObject(o, "n_vrf_ids", a->n_vrf_ids);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "vrf_ids");
        for (i = 0; i < a->n_vrf_ids; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->vrf_ids[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_nat_set_mss_clamping_t_tojson (vl_api_nat_set_mss_clamping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_set_mss_clamping");
    cJSON_AddStringToObject(o, "_crc", "25e90abb");
    cJSON_AddNumberToObject(o, "mss_value", a->mss_value);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat_set_mss_clamping_reply_t_tojson (vl_api_nat_set_mss_clamping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_set_mss_clamping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_get_mss_clamping_t_tojson (vl_api_nat_get_mss_clamping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_get_mss_clamping");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat_get_mss_clamping_reply_t_tojson (vl_api_nat_get_mss_clamping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_get_mss_clamping_reply");
    cJSON_AddStringToObject(o, "_crc", "1c0b2a78");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "mss_value", a->mss_value);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_nat44_ed_set_fq_options_t_tojson (vl_api_nat44_ed_set_fq_options_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_set_fq_options");
    cJSON_AddStringToObject(o, "_crc", "2399bd71");
    cJSON_AddNumberToObject(o, "frame_queue_nelts", a->frame_queue_nelts);
    return o;
}
static inline cJSON *vl_api_nat44_ed_set_fq_options_reply_t_tojson (vl_api_nat44_ed_set_fq_options_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_set_fq_options_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ed_show_fq_options_t_tojson (vl_api_nat44_ed_show_fq_options_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_show_fq_options");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_ed_show_fq_options_reply_t_tojson (vl_api_nat44_ed_show_fq_options_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_show_fq_options_reply");
    cJSON_AddStringToObject(o, "_crc", "7213b545");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "frame_queue_nelts", a->frame_queue_nelts);
    return o;
}
static inline cJSON *vl_api_nat44_add_del_interface_addr_t_tojson (vl_api_nat44_add_del_interface_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_interface_addr");
    cJSON_AddStringToObject(o, "_crc", "4aed50c0");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_add_del_interface_addr_reply_t_tojson (vl_api_nat44_add_del_interface_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_interface_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_interface_addr_dump_t_tojson (vl_api_nat44_interface_addr_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_interface_addr_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_interface_addr_details_t_tojson (vl_api_nat44_interface_addr_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_interface_addr_details");
    cJSON_AddStringToObject(o, "_crc", "e4aca9ca");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_add_del_address_range_t_tojson (vl_api_nat44_add_del_address_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_address_range");
    cJSON_AddStringToObject(o, "_crc", "6f2b8055");
    cJSON_AddItemToObject(o, "first_ip_address", vl_api_ip4_address_t_tojson(&a->first_ip_address));
    cJSON_AddItemToObject(o, "last_ip_address", vl_api_ip4_address_t_tojson(&a->last_ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_nat44_add_del_address_range_reply_t_tojson (vl_api_nat44_add_del_address_range_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_address_range_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_address_dump_t_tojson (vl_api_nat44_address_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_address_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_address_details_t_tojson (vl_api_nat44_address_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_address_details");
    cJSON_AddStringToObject(o, "_crc", "0d1beac1");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_interface_add_del_feature_t_tojson (vl_api_nat44_interface_add_del_feature_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_interface_add_del_feature");
    cJSON_AddStringToObject(o, "_crc", "f3699b83");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_interface_add_del_feature_reply_t_tojson (vl_api_nat44_interface_add_del_feature_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_interface_add_del_feature_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_interface_dump_t_tojson (vl_api_nat44_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_interface_details_t_tojson (vl_api_nat44_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_interface_details");
    cJSON_AddStringToObject(o, "_crc", "5d286289");
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ed_add_del_output_interface_t_tojson (vl_api_nat44_ed_add_del_output_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_add_del_output_interface");
    cJSON_AddStringToObject(o, "_crc", "47d6e753");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_ed_add_del_output_interface_reply_t_tojson (vl_api_nat44_ed_add_del_output_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_add_del_output_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_ed_output_interface_get_t_tojson (vl_api_nat44_ed_output_interface_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_output_interface_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_nat44_ed_output_interface_get_reply_t_tojson (vl_api_nat44_ed_output_interface_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_output_interface_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_nat44_ed_output_interface_details_t_tojson (vl_api_nat44_ed_output_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_ed_output_interface_details");
    cJSON_AddStringToObject(o, "_crc", "0b45011c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nat44_add_del_static_mapping_t_tojson (vl_api_nat44_add_del_static_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_static_mapping");
    cJSON_AddStringToObject(o, "_crc", "5ae5f03e");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
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
static inline cJSON *vl_api_nat44_add_del_static_mapping_reply_t_tojson (vl_api_nat44_add_del_static_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_static_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_add_del_static_mapping_v2_t_tojson (vl_api_nat44_add_del_static_mapping_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_static_mapping_v2");
    cJSON_AddStringToObject(o, "_crc", "5e205f1a");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "match_pool", a->match_pool);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "pool_ip_address", vl_api_ip4_address_t_tojson(&a->pool_ip_address));
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
static inline cJSON *vl_api_nat44_add_del_static_mapping_v2_reply_t_tojson (vl_api_nat44_add_del_static_mapping_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_static_mapping_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_static_mapping_dump_t_tojson (vl_api_nat44_static_mapping_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_static_mapping_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_static_mapping_details_t_tojson (vl_api_nat44_static_mapping_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_static_mapping_details");
    cJSON_AddStringToObject(o, "_crc", "06cb40b2");
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
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
static inline cJSON *vl_api_nat44_add_del_identity_mapping_t_tojson (vl_api_nat44_add_del_identity_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_identity_mapping");
    cJSON_AddStringToObject(o, "_crc", "02faaa22");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_nat44_add_del_identity_mapping_reply_t_tojson (vl_api_nat44_add_del_identity_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_identity_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_identity_mapping_dump_t_tojson (vl_api_nat44_identity_mapping_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_identity_mapping_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_identity_mapping_details_t_tojson (vl_api_nat44_identity_mapping_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_identity_mapping_details");
    cJSON_AddStringToObject(o, "_crc", "2a52a030");
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_nat44_add_del_lb_static_mapping_t_tojson (vl_api_nat44_add_del_lb_static_mapping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_lb_static_mapping");
    cJSON_AddStringToObject(o, "_crc", "4f68ee9d");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "external_addr", vl_api_ip4_address_t_tojson(&a->external_addr));
    cJSON_AddNumberToObject(o, "external_port", a->external_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "affinity", a->affinity);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "local_num", a->local_num);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "locals");
        for (i = 0; i < a->local_num; i++) {
            cJSON_AddItemToArray(array, vl_api_nat44_lb_addr_port_t_tojson(&a->locals[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_nat44_add_del_lb_static_mapping_reply_t_tojson (vl_api_nat44_add_del_lb_static_mapping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_add_del_lb_static_mapping_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_lb_static_mapping_add_del_local_t_tojson (vl_api_nat44_lb_static_mapping_add_del_local_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_lb_static_mapping_add_del_local");
    cJSON_AddStringToObject(o, "_crc", "7ca47547");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "external_addr", vl_api_ip4_address_t_tojson(&a->external_addr));
    cJSON_AddNumberToObject(o, "external_port", a->external_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "local", vl_api_nat44_lb_addr_port_t_tojson(&a->local));
    return o;
}
static inline cJSON *vl_api_nat44_lb_static_mapping_add_del_local_reply_t_tojson (vl_api_nat44_lb_static_mapping_add_del_local_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_lb_static_mapping_add_del_local_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_lb_static_mapping_dump_t_tojson (vl_api_nat44_lb_static_mapping_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_lb_static_mapping_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_lb_static_mapping_details_t_tojson (vl_api_nat44_lb_static_mapping_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_lb_static_mapping_details");
    cJSON_AddStringToObject(o, "_crc", "ed5ce876");
    cJSON_AddItemToObject(o, "external_addr", vl_api_ip4_address_t_tojson(&a->external_addr));
    cJSON_AddNumberToObject(o, "external_port", a->external_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "affinity", a->affinity);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "local_num", a->local_num);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "locals");
        for (i = 0; i < a->local_num; i++) {
            cJSON_AddItemToArray(array, vl_api_nat44_lb_addr_port_t_tojson(&a->locals[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_nat44_del_session_t_tojson (vl_api_nat44_del_session_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_del_session");
    cJSON_AddStringToObject(o, "_crc", "15a5bf8c");
    cJSON_AddItemToObject(o, "address", vl_api_ip4_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    return o;
}
static inline cJSON *vl_api_nat44_del_session_reply_t_tojson (vl_api_nat44_del_session_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_del_session_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat44_user_dump_t_tojson (vl_api_nat44_user_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat44_user_details_t_tojson (vl_api_nat44_user_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_details");
    cJSON_AddStringToObject(o, "_crc", "355896c2");
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "nsessions", a->nsessions);
    cJSON_AddNumberToObject(o, "nstaticsessions", a->nstaticsessions);
    return o;
}
static inline cJSON *vl_api_nat44_user_session_dump_t_tojson (vl_api_nat44_user_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_session_dump");
    cJSON_AddStringToObject(o, "_crc", "e1899c98");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_user_session_details_t_tojson (vl_api_nat44_user_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_session_details");
    cJSON_AddStringToObject(o, "_crc", "2cf6e16d");
    cJSON_AddItemToObject(o, "outside_ip_address", vl_api_ip4_address_t_tojson(&a->outside_ip_address));
    cJSON_AddNumberToObject(o, "outside_port", a->outside_port);
    cJSON_AddItemToObject(o, "inside_ip_address", vl_api_ip4_address_t_tojson(&a->inside_ip_address));
    cJSON_AddNumberToObject(o, "inside_port", a->inside_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "last_heard", a->last_heard);
    cJSON_AddNumberToObject(o, "total_bytes", a->total_bytes);
    cJSON_AddNumberToObject(o, "total_pkts", a->total_pkts);
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    cJSON_AddItemToObject(o, "ext_host_nat_address", vl_api_ip4_address_t_tojson(&a->ext_host_nat_address));
    cJSON_AddNumberToObject(o, "ext_host_nat_port", a->ext_host_nat_port);
    return o;
}
static inline cJSON *vl_api_nat44_user_session_v2_dump_t_tojson (vl_api_nat44_user_session_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_session_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "e1899c98");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_nat44_user_session_v2_details_t_tojson (vl_api_nat44_user_session_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_session_v2_details");
    cJSON_AddStringToObject(o, "_crc", "fd42b729");
    cJSON_AddItemToObject(o, "outside_ip_address", vl_api_ip4_address_t_tojson(&a->outside_ip_address));
    cJSON_AddNumberToObject(o, "outside_port", a->outside_port);
    cJSON_AddItemToObject(o, "inside_ip_address", vl_api_ip4_address_t_tojson(&a->inside_ip_address));
    cJSON_AddNumberToObject(o, "inside_port", a->inside_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "last_heard", a->last_heard);
    cJSON_AddNumberToObject(o, "total_bytes", a->total_bytes);
    cJSON_AddNumberToObject(o, "total_pkts", a->total_pkts);
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    cJSON_AddItemToObject(o, "ext_host_nat_address", vl_api_ip4_address_t_tojson(&a->ext_host_nat_address));
    cJSON_AddNumberToObject(o, "ext_host_nat_port", a->ext_host_nat_port);
    cJSON_AddBoolToObject(o, "is_timed_out", a->is_timed_out);
    return o;
}
static inline cJSON *vl_api_nat44_user_session_v3_details_t_tojson (vl_api_nat44_user_session_v3_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_session_v3_details");
    cJSON_AddStringToObject(o, "_crc", "edae926e");
    cJSON_AddItemToObject(o, "outside_ip_address", vl_api_ip4_address_t_tojson(&a->outside_ip_address));
    cJSON_AddNumberToObject(o, "outside_port", a->outside_port);
    cJSON_AddItemToObject(o, "inside_ip_address", vl_api_ip4_address_t_tojson(&a->inside_ip_address));
    cJSON_AddNumberToObject(o, "inside_port", a->inside_port);
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "flags", vl_api_nat_config_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "last_heard", a->last_heard);
    cJSON_AddNumberToObject(o, "time_since_last_heard", a->time_since_last_heard);
    cJSON_AddNumberToObject(o, "total_bytes", a->total_bytes);
    cJSON_AddNumberToObject(o, "total_pkts", a->total_pkts);
    cJSON_AddItemToObject(o, "ext_host_address", vl_api_ip4_address_t_tojson(&a->ext_host_address));
    cJSON_AddNumberToObject(o, "ext_host_port", a->ext_host_port);
    cJSON_AddItemToObject(o, "ext_host_nat_address", vl_api_ip4_address_t_tojson(&a->ext_host_nat_address));
    cJSON_AddNumberToObject(o, "ext_host_nat_port", a->ext_host_nat_port);
    cJSON_AddBoolToObject(o, "is_timed_out", a->is_timed_out);
    return o;
}
static inline cJSON *vl_api_nat44_user_session_v3_dump_t_tojson (vl_api_nat44_user_session_v3_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat44_user_session_v3_dump");
    cJSON_AddStringToObject(o, "_crc", "e1899c98");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
#endif
