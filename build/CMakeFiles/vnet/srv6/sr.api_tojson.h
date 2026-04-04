/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/srv6/sr_types.api_tojson.h>
#ifndef included_sr_api_tojson_h
#define included_sr_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_srv6_sid_list_t_tojson (vl_api_srv6_sid_list_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "num_sids", a->num_sids);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sids");
        for (i = 0; i < 16; i++) {
            cJSON_AddItemToArray(array, vl_api_ip6_address_t_tojson(&a->sids[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_srv6_sid_list_with_sl_index_t_tojson (vl_api_srv6_sid_list_with_sl_index_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "num_sids", a->num_sids);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddNumberToObject(o, "sl_index", a->sl_index);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sids");
        for (i = 0; i < 16; i++) {
            cJSON_AddItemToArray(array, vl_api_ip6_address_t_tojson(&a->sids[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sr_policy_type_t_tojson (vl_api_sr_policy_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SR_API_POLICY_TYPE_DEFAULT");
    case 1:
        return cJSON_CreateString("SR_API_POLICY_TYPE_SPRAY");
    case 2:
        return cJSON_CreateString("SR_API_POLICY_TYPE_TEF");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_sr_localsid_add_del_t_tojson (vl_api_sr_localsid_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_localsid_add_del");
    cJSON_AddStringToObject(o, "_crc", "5a36c324");
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    cJSON_AddItemToObject(o, "localsid", vl_api_ip6_address_t_tojson(&a->localsid));
    cJSON_AddBoolToObject(o, "end_psp", a->end_psp);
    cJSON_AddItemToObject(o, "behavior", vl_api_sr_behavior_t_tojson(a->behavior));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vlan_index", a->vlan_index);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddItemToObject(o, "nh_addr", vl_api_address_t_tojson(&a->nh_addr));
    return o;
}
static inline cJSON *vl_api_sr_localsid_add_del_reply_t_tojson (vl_api_sr_localsid_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_localsid_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_policy_add_t_tojson (vl_api_sr_policy_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_add");
    cJSON_AddStringToObject(o, "_crc", "44ac92e8");
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddBoolToObject(o, "is_encap", a->is_encap);
    cJSON_AddBoolToObject(o, "is_spray", a->is_spray);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddItemToObject(o, "sids", vl_api_srv6_sid_list_t_tojson(&a->sids));
    return o;
}
static inline cJSON *vl_api_sr_policy_add_reply_t_tojson (vl_api_sr_policy_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_policy_mod_t_tojson (vl_api_sr_policy_mod_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_mod");
    cJSON_AddStringToObject(o, "_crc", "b97bb56e");
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddNumberToObject(o, "sr_policy_index", a->sr_policy_index);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddItemToObject(o, "operation", vl_api_sr_policy_op_t_tojson(a->operation));
    cJSON_AddNumberToObject(o, "sl_index", a->sl_index);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddItemToObject(o, "sids", vl_api_srv6_sid_list_t_tojson(&a->sids));
    return o;
}
static inline cJSON *vl_api_sr_policy_mod_reply_t_tojson (vl_api_sr_policy_mod_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_mod_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_policy_add_v2_t_tojson (vl_api_sr_policy_add_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_add_v2");
    cJSON_AddStringToObject(o, "_crc", "f6297f36");
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddBoolToObject(o, "is_encap", a->is_encap);
    cJSON_AddItemToObject(o, "type", vl_api_sr_policy_type_t_tojson(a->type));
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddItemToObject(o, "sids", vl_api_srv6_sid_list_t_tojson(&a->sids));
    cJSON_AddItemToObject(o, "encap_src", vl_api_ip6_address_t_tojson(&a->encap_src));
    return o;
}
static inline cJSON *vl_api_sr_policy_add_v2_reply_t_tojson (vl_api_sr_policy_add_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_add_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_policy_mod_v2_t_tojson (vl_api_sr_policy_mod_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_mod_v2");
    cJSON_AddStringToObject(o, "_crc", "c0544823");
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddNumberToObject(o, "sr_policy_index", a->sr_policy_index);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddItemToObject(o, "operation", vl_api_sr_policy_op_t_tojson(a->operation));
    cJSON_AddNumberToObject(o, "sl_index", a->sl_index);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddItemToObject(o, "sids", vl_api_srv6_sid_list_t_tojson(&a->sids));
    cJSON_AddItemToObject(o, "encap_src", vl_api_ip6_address_t_tojson(&a->encap_src));
    return o;
}
static inline cJSON *vl_api_sr_policy_mod_v2_reply_t_tojson (vl_api_sr_policy_mod_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_mod_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_policy_del_t_tojson (vl_api_sr_policy_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_del");
    cJSON_AddStringToObject(o, "_crc", "cb4d48d5");
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddNumberToObject(o, "sr_policy_index", a->sr_policy_index);
    return o;
}
static inline cJSON *vl_api_sr_policy_del_reply_t_tojson (vl_api_sr_policy_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policy_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_set_encap_source_t_tojson (vl_api_sr_set_encap_source_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_set_encap_source");
    cJSON_AddStringToObject(o, "_crc", "d3bad5e1");
    cJSON_AddItemToObject(o, "encaps_source", vl_api_ip6_address_t_tojson(&a->encaps_source));
    return o;
}
static inline cJSON *vl_api_sr_set_encap_source_reply_t_tojson (vl_api_sr_set_encap_source_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_set_encap_source_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_set_encap_hop_limit_t_tojson (vl_api_sr_set_encap_hop_limit_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_set_encap_hop_limit");
    cJSON_AddStringToObject(o, "_crc", "aa75d7d0");
    cJSON_AddNumberToObject(o, "hop_limit", a->hop_limit);
    return o;
}
static inline cJSON *vl_api_sr_set_encap_hop_limit_reply_t_tojson (vl_api_sr_set_encap_hop_limit_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_set_encap_hop_limit_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_steering_add_del_t_tojson (vl_api_sr_steering_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_steering_add_del");
    cJSON_AddStringToObject(o, "_crc", "e46b0a0f");
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddNumberToObject(o, "sr_policy_index", a->sr_policy_index);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "traffic_type", vl_api_sr_steer_t_tojson(a->traffic_type));
    return o;
}
static inline cJSON *vl_api_sr_steering_add_del_reply_t_tojson (vl_api_sr_steering_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_steering_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_localsids_dump_t_tojson (vl_api_sr_localsids_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_localsids_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_localsids_details_t_tojson (vl_api_sr_localsids_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_localsids_details");
    cJSON_AddStringToObject(o, "_crc", "2e9221b9");
    cJSON_AddItemToObject(o, "addr", vl_api_ip6_address_t_tojson(&a->addr));
    cJSON_AddBoolToObject(o, "end_psp", a->end_psp);
    cJSON_AddItemToObject(o, "behavior", vl_api_sr_behavior_t_tojson(a->behavior));
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "vlan_index", a->vlan_index);
    cJSON_AddItemToObject(o, "xconnect_nh_addr", vl_api_address_t_tojson(&a->xconnect_nh_addr));
    cJSON_AddNumberToObject(o, "xconnect_iface_or_vrf_table", a->xconnect_iface_or_vrf_table);
    return o;
}
static inline cJSON *vl_api_sr_localsids_with_packet_stats_dump_t_tojson (vl_api_sr_localsids_with_packet_stats_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_localsids_with_packet_stats_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_localsids_with_packet_stats_details_t_tojson (vl_api_sr_localsids_with_packet_stats_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_localsids_with_packet_stats_details");
    cJSON_AddStringToObject(o, "_crc", "ce0b1ce0");
    cJSON_AddItemToObject(o, "addr", vl_api_ip6_address_t_tojson(&a->addr));
    cJSON_AddBoolToObject(o, "end_psp", a->end_psp);
    cJSON_AddItemToObject(o, "behavior", vl_api_sr_behavior_t_tojson(a->behavior));
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "vlan_index", a->vlan_index);
    cJSON_AddItemToObject(o, "xconnect_nh_addr", vl_api_address_t_tojson(&a->xconnect_nh_addr));
    cJSON_AddNumberToObject(o, "xconnect_iface_or_vrf_table", a->xconnect_iface_or_vrf_table);
    cJSON_AddNumberToObject(o, "good_traffic_bytes", a->good_traffic_bytes);
    cJSON_AddNumberToObject(o, "good_traffic_pkt_count", a->good_traffic_pkt_count);
    cJSON_AddNumberToObject(o, "bad_traffic_bytes", a->bad_traffic_bytes);
    cJSON_AddNumberToObject(o, "bad_traffic_pkt_count", a->bad_traffic_pkt_count);
    return o;
}
static inline cJSON *vl_api_sr_policies_dump_t_tojson (vl_api_sr_policies_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policies_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_policies_details_t_tojson (vl_api_sr_policies_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policies_details");
    cJSON_AddStringToObject(o, "_crc", "db6ff2a1");
    cJSON_AddItemToObject(o, "bsid", vl_api_ip6_address_t_tojson(&a->bsid));
    cJSON_AddBoolToObject(o, "is_spray", a->is_spray);
    cJSON_AddBoolToObject(o, "is_encap", a->is_encap);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "num_sid_lists", a->num_sid_lists);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sid_lists");
        for (i = 0; i < a->num_sid_lists; i++) {
            cJSON_AddItemToArray(array, vl_api_srv6_sid_list_t_tojson(&a->sid_lists[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sr_policies_v2_dump_t_tojson (vl_api_sr_policies_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policies_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_policies_v2_details_t_tojson (vl_api_sr_policies_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policies_v2_details");
    cJSON_AddStringToObject(o, "_crc", "96dcb699");
    cJSON_AddItemToObject(o, "bsid", vl_api_ip6_address_t_tojson(&a->bsid));
    cJSON_AddItemToObject(o, "encap_src", vl_api_ip6_address_t_tojson(&a->encap_src));
    cJSON_AddItemToObject(o, "type", vl_api_sr_policy_type_t_tojson(a->type));
    cJSON_AddBoolToObject(o, "is_encap", a->is_encap);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "num_sid_lists", a->num_sid_lists);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sid_lists");
        for (i = 0; i < a->num_sid_lists; i++) {
            cJSON_AddItemToArray(array, vl_api_srv6_sid_list_t_tojson(&a->sid_lists[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sr_policies_with_sl_index_dump_t_tojson (vl_api_sr_policies_with_sl_index_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policies_with_sl_index_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_policies_with_sl_index_details_t_tojson (vl_api_sr_policies_with_sl_index_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_policies_with_sl_index_details");
    cJSON_AddStringToObject(o, "_crc", "ca2e9bc8");
    cJSON_AddItemToObject(o, "bsid", vl_api_ip6_address_t_tojson(&a->bsid));
    cJSON_AddBoolToObject(o, "is_spray", a->is_spray);
    cJSON_AddBoolToObject(o, "is_encap", a->is_encap);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "num_sid_lists", a->num_sid_lists);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sid_lists");
        for (i = 0; i < a->num_sid_lists; i++) {
            cJSON_AddItemToArray(array, vl_api_srv6_sid_list_with_sl_index_t_tojson(&a->sid_lists[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sr_steering_pol_dump_t_tojson (vl_api_sr_steering_pol_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_steering_pol_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_steering_pol_details_t_tojson (vl_api_sr_steering_pol_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_steering_pol_details");
    cJSON_AddStringToObject(o, "_crc", "d41258c9");
    cJSON_AddItemToObject(o, "traffic_type", vl_api_sr_steer_t_tojson(a->traffic_type));
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "bsid", vl_api_ip6_address_t_tojson(&a->bsid));
    return o;
}
#endif
