/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_l2_api_tojson_h
#define included_l2_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_mac_event_action_t_tojson (vl_api_mac_event_action_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("MAC_EVENT_ACTION_API_ADD");
    case 1:
        return cJSON_CreateString("MAC_EVENT_ACTION_API_DELETE");
    case 2:
        return cJSON_CreateString("MAC_EVENT_ACTION_API_MOVE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_mac_entry_t_tojson (vl_api_mac_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "mac_addr", vl_api_mac_address_t_tojson(&a->mac_addr));
    cJSON_AddItemToObject(o, "action", vl_api_mac_event_action_t_tojson(a->action));
    cJSON_AddNumberToObject(o, "flags", a->flags);
    return o;
}
static inline cJSON *vl_api_bridge_domain_sw_if_t_tojson (vl_api_bridge_domain_sw_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "shg", a->shg);
    return o;
}
static inline cJSON *vl_api_bd_flags_t_tojson (vl_api_bd_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("BRIDGE_API_FLAG_NONE");
    case 1:
        return cJSON_CreateString("BRIDGE_API_FLAG_LEARN");
    case 2:
        return cJSON_CreateString("BRIDGE_API_FLAG_FWD");
    case 4:
        return cJSON_CreateString("BRIDGE_API_FLAG_FLOOD");
    case 8:
        return cJSON_CreateString("BRIDGE_API_FLAG_UU_FLOOD");
    case 16:
        return cJSON_CreateString("BRIDGE_API_FLAG_ARP_TERM");
    case 32:
        return cJSON_CreateString("BRIDGE_API_FLAG_ARP_UFWD");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_l2_port_type_t_tojson (vl_api_l2_port_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("L2_API_PORT_TYPE_NORMAL");
    case 1:
        return cJSON_CreateString("L2_API_PORT_TYPE_BVI");
    case 2:
        return cJSON_CreateString("L2_API_PORT_TYPE_UU_FWD");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_bd_ip_mac_t_tojson (vl_api_bd_ip_mac_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddItemToObject(o, "ip", vl_api_address_t_tojson(&a->ip));
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    return o;
}
static inline cJSON *vl_api_l2_xconnect_details_t_tojson (vl_api_l2_xconnect_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_xconnect_details");
    cJSON_AddStringToObject(o, "_crc", "472b6b67");
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "tx_sw_if_index", a->tx_sw_if_index);
    return o;
}
static inline cJSON *vl_api_l2_xconnect_dump_t_tojson (vl_api_l2_xconnect_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_xconnect_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_l2_fib_table_details_t_tojson (vl_api_l2_fib_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_fib_table_details");
    cJSON_AddStringToObject(o, "_crc", "a44ef6b8");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "static_mac", a->static_mac);
    cJSON_AddBoolToObject(o, "filter_mac", a->filter_mac);
    cJSON_AddBoolToObject(o, "bvi_mac", a->bvi_mac);
    return o;
}
static inline cJSON *vl_api_l2_fib_table_dump_t_tojson (vl_api_l2_fib_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_fib_table_dump");
    cJSON_AddStringToObject(o, "_crc", "c25fdce6");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    return o;
}
static inline cJSON *vl_api_l2_fib_clear_table_t_tojson (vl_api_l2_fib_clear_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_fib_clear_table");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_l2_fib_clear_table_reply_t_tojson (vl_api_l2_fib_clear_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_fib_clear_table_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2fib_flush_all_t_tojson (vl_api_l2fib_flush_all_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_flush_all");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_l2fib_flush_all_reply_t_tojson (vl_api_l2fib_flush_all_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_flush_all_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2fib_flush_bd_t_tojson (vl_api_l2fib_flush_bd_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_flush_bd");
    cJSON_AddStringToObject(o, "_crc", "c25fdce6");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    return o;
}
static inline cJSON *vl_api_l2fib_flush_bd_reply_t_tojson (vl_api_l2fib_flush_bd_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_flush_bd_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2fib_flush_int_t_tojson (vl_api_l2fib_flush_int_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_flush_int");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_l2fib_flush_int_reply_t_tojson (vl_api_l2fib_flush_int_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_flush_int_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2fib_add_del_t_tojson (vl_api_l2fib_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_add_del");
    cJSON_AddStringToObject(o, "_crc", "eddda487");
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "static_mac", a->static_mac);
    cJSON_AddBoolToObject(o, "filter_mac", a->filter_mac);
    cJSON_AddBoolToObject(o, "bvi_mac", a->bvi_mac);
    return o;
}
static inline cJSON *vl_api_l2fib_add_del_reply_t_tojson (vl_api_l2fib_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_l2_macs_events_t_tojson (vl_api_want_l2_macs_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_l2_macs_events");
    cJSON_AddStringToObject(o, "_crc", "9aabdfde");
    cJSON_AddNumberToObject(o, "learn_limit", a->learn_limit);
    cJSON_AddNumberToObject(o, "scan_delay", a->scan_delay);
    cJSON_AddNumberToObject(o, "max_macs_in_event", a->max_macs_in_event);
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_l2_macs_events_reply_t_tojson (vl_api_want_l2_macs_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_l2_macs_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_l2_macs_events2_t_tojson (vl_api_want_l2_macs_events2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_l2_macs_events2");
    cJSON_AddStringToObject(o, "_crc", "cc1377b0");
    cJSON_AddNumberToObject(o, "max_macs_in_event", a->max_macs_in_event);
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_l2_macs_events2_reply_t_tojson (vl_api_want_l2_macs_events2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_l2_macs_events2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2fib_set_scan_delay_t_tojson (vl_api_l2fib_set_scan_delay_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_set_scan_delay");
    cJSON_AddStringToObject(o, "_crc", "a3b968a4");
    cJSON_AddNumberToObject(o, "scan_delay", a->scan_delay);
    return o;
}
static inline cJSON *vl_api_l2fib_set_scan_delay_reply_t_tojson (vl_api_l2fib_set_scan_delay_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2fib_set_scan_delay_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2_macs_event_t_tojson (vl_api_l2_macs_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_macs_event");
    cJSON_AddStringToObject(o, "_crc", "44b8fd64");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "n_macs", a->n_macs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "mac");
        for (i = 0; i < a->n_macs; i++) {
            cJSON_AddItemToArray(array, vl_api_mac_entry_t_tojson(&a->mac[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_l2_flags_t_tojson (vl_api_l2_flags_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_flags");
    cJSON_AddStringToObject(o, "_crc", "fc41cfe8");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_set", a->is_set);
    cJSON_AddNumberToObject(o, "feature_bitmap", a->feature_bitmap);
    return o;
}
static inline cJSON *vl_api_l2_flags_reply_t_tojson (vl_api_l2_flags_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_flags_reply");
    cJSON_AddStringToObject(o, "_crc", "29b2a2b3");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "resulting_feature_bitmap", a->resulting_feature_bitmap);
    return o;
}
static inline cJSON *vl_api_bridge_domain_set_mac_age_t_tojson (vl_api_bridge_domain_set_mac_age_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_set_mac_age");
    cJSON_AddStringToObject(o, "_crc", "b537ad7b");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddNumberToObject(o, "mac_age", a->mac_age);
    return o;
}
static inline cJSON *vl_api_bridge_domain_set_mac_age_reply_t_tojson (vl_api_bridge_domain_set_mac_age_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_set_mac_age_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bridge_domain_set_default_learn_limit_t_tojson (vl_api_bridge_domain_set_default_learn_limit_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_set_default_learn_limit");
    cJSON_AddStringToObject(o, "_crc", "f097ffce");
    cJSON_AddNumberToObject(o, "learn_limit", a->learn_limit);
    return o;
}
static inline cJSON *vl_api_bridge_domain_set_default_learn_limit_reply_t_tojson (vl_api_bridge_domain_set_default_learn_limit_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_set_default_learn_limit_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bridge_domain_set_learn_limit_t_tojson (vl_api_bridge_domain_set_learn_limit_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_set_learn_limit");
    cJSON_AddStringToObject(o, "_crc", "89c52b5f");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddNumberToObject(o, "learn_limit", a->learn_limit);
    return o;
}
static inline cJSON *vl_api_bridge_domain_set_learn_limit_reply_t_tojson (vl_api_bridge_domain_set_learn_limit_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_set_learn_limit_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bridge_domain_add_del_t_tojson (vl_api_bridge_domain_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_add_del");
    cJSON_AddStringToObject(o, "_crc", "600b7170");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddBoolToObject(o, "flood", a->flood);
    cJSON_AddBoolToObject(o, "uu_flood", a->uu_flood);
    cJSON_AddBoolToObject(o, "forward", a->forward);
    cJSON_AddBoolToObject(o, "learn", a->learn);
    cJSON_AddBoolToObject(o, "arp_term", a->arp_term);
    cJSON_AddBoolToObject(o, "arp_ufwd", a->arp_ufwd);
    cJSON_AddNumberToObject(o, "mac_age", a->mac_age);
    cJSON_AddStringToObject(o, "bd_tag", (char *)a->bd_tag);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_bridge_domain_add_del_reply_t_tojson (vl_api_bridge_domain_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bridge_domain_add_del_v2_t_tojson (vl_api_bridge_domain_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "600b7170");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddBoolToObject(o, "flood", a->flood);
    cJSON_AddBoolToObject(o, "uu_flood", a->uu_flood);
    cJSON_AddBoolToObject(o, "forward", a->forward);
    cJSON_AddBoolToObject(o, "learn", a->learn);
    cJSON_AddBoolToObject(o, "arp_term", a->arp_term);
    cJSON_AddBoolToObject(o, "arp_ufwd", a->arp_ufwd);
    cJSON_AddNumberToObject(o, "mac_age", a->mac_age);
    cJSON_AddStringToObject(o, "bd_tag", (char *)a->bd_tag);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_bridge_domain_add_del_v2_reply_t_tojson (vl_api_bridge_domain_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "fcb1e980");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    return o;
}
static inline cJSON *vl_api_bridge_domain_dump_t_tojson (vl_api_bridge_domain_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_dump");
    cJSON_AddStringToObject(o, "_crc", "74396a43");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bridge_domain_details_t_tojson (vl_api_bridge_domain_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_domain_details");
    cJSON_AddStringToObject(o, "_crc", "0fa506fd");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddBoolToObject(o, "flood", a->flood);
    cJSON_AddBoolToObject(o, "uu_flood", a->uu_flood);
    cJSON_AddBoolToObject(o, "forward", a->forward);
    cJSON_AddBoolToObject(o, "learn", a->learn);
    cJSON_AddBoolToObject(o, "arp_term", a->arp_term);
    cJSON_AddBoolToObject(o, "arp_ufwd", a->arp_ufwd);
    cJSON_AddNumberToObject(o, "mac_age", a->mac_age);
    cJSON_AddStringToObject(o, "bd_tag", (char *)a->bd_tag);
    cJSON_AddNumberToObject(o, "bvi_sw_if_index", a->bvi_sw_if_index);
    cJSON_AddNumberToObject(o, "uu_fwd_sw_if_index", a->uu_fwd_sw_if_index);
    cJSON_AddNumberToObject(o, "n_sw_ifs", a->n_sw_ifs);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sw_if_details");
        for (i = 0; i < a->n_sw_ifs; i++) {
            cJSON_AddItemToArray(array, vl_api_bridge_domain_sw_if_t_tojson(&a->sw_if_details[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_bridge_flags_t_tojson (vl_api_bridge_flags_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_flags");
    cJSON_AddStringToObject(o, "_crc", "1b0c5fbd");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddBoolToObject(o, "is_set", a->is_set);
    cJSON_AddItemToObject(o, "flags", vl_api_bd_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_bridge_flags_reply_t_tojson (vl_api_bridge_flags_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bridge_flags_reply");
    cJSON_AddStringToObject(o, "_crc", "29b2a2b3");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "resulting_feature_bitmap", a->resulting_feature_bitmap);
    return o;
}
static inline cJSON *vl_api_l2_interface_vlan_tag_rewrite_t_tojson (vl_api_l2_interface_vlan_tag_rewrite_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_interface_vlan_tag_rewrite");
    cJSON_AddStringToObject(o, "_crc", "62cc0bbc");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vtr_op", a->vtr_op);
    cJSON_AddNumberToObject(o, "push_dot1q", a->push_dot1q);
    cJSON_AddNumberToObject(o, "tag1", a->tag1);
    cJSON_AddNumberToObject(o, "tag2", a->tag2);
    return o;
}
static inline cJSON *vl_api_l2_interface_vlan_tag_rewrite_reply_t_tojson (vl_api_l2_interface_vlan_tag_rewrite_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_interface_vlan_tag_rewrite_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2_interface_pbb_tag_rewrite_t_tojson (vl_api_l2_interface_pbb_tag_rewrite_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_interface_pbb_tag_rewrite");
    cJSON_AddStringToObject(o, "_crc", "38e802a8");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vtr_op", a->vtr_op);
    cJSON_AddNumberToObject(o, "outer_tag", a->outer_tag);
    cJSON_AddItemToObject(o, "b_dmac", vl_api_mac_address_t_tojson(&a->b_dmac));
    cJSON_AddItemToObject(o, "b_smac", vl_api_mac_address_t_tojson(&a->b_smac));
    cJSON_AddNumberToObject(o, "b_vlanid", a->b_vlanid);
    cJSON_AddNumberToObject(o, "i_sid", a->i_sid);
    return o;
}
static inline cJSON *vl_api_l2_interface_pbb_tag_rewrite_reply_t_tojson (vl_api_l2_interface_pbb_tag_rewrite_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_interface_pbb_tag_rewrite_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2_patch_add_del_t_tojson (vl_api_l2_patch_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_patch_add_del");
    cJSON_AddStringToObject(o, "_crc", "a1f6a6f3");
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "tx_sw_if_index", a->tx_sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_l2_patch_add_del_reply_t_tojson (vl_api_l2_patch_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_patch_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_l2_xconnect_t_tojson (vl_api_sw_interface_set_l2_xconnect_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_l2_xconnect");
    cJSON_AddStringToObject(o, "_crc", "4fa28a85");
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "tx_sw_if_index", a->tx_sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_l2_xconnect_reply_t_tojson (vl_api_sw_interface_set_l2_xconnect_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_l2_xconnect_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_l2_bridge_t_tojson (vl_api_sw_interface_set_l2_bridge_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_l2_bridge");
    cJSON_AddStringToObject(o, "_crc", "d0678b13");
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    cJSON_AddItemToObject(o, "port_type", vl_api_l2_port_type_t_tojson(a->port_type));
    cJSON_AddNumberToObject(o, "shg", a->shg);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_l2_bridge_reply_t_tojson (vl_api_sw_interface_set_l2_bridge_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_l2_bridge_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bd_ip_mac_add_del_t_tojson (vl_api_bd_ip_mac_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bd_ip_mac_add_del");
    cJSON_AddStringToObject(o, "_crc", "0257c869");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_bd_ip_mac_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_bd_ip_mac_add_del_reply_t_tojson (vl_api_bd_ip_mac_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bd_ip_mac_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bd_ip_mac_flush_t_tojson (vl_api_bd_ip_mac_flush_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bd_ip_mac_flush");
    cJSON_AddStringToObject(o, "_crc", "c25fdce6");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    return o;
}
static inline cJSON *vl_api_bd_ip_mac_flush_reply_t_tojson (vl_api_bd_ip_mac_flush_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bd_ip_mac_flush_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bd_ip_mac_details_t_tojson (vl_api_bd_ip_mac_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bd_ip_mac_details");
    cJSON_AddStringToObject(o, "_crc", "545af86a");
    cJSON_AddItemToObject(o, "entry", vl_api_bd_ip_mac_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_bd_ip_mac_dump_t_tojson (vl_api_bd_ip_mac_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bd_ip_mac_dump");
    cJSON_AddStringToObject(o, "_crc", "c25fdce6");
    cJSON_AddNumberToObject(o, "bd_id", a->bd_id);
    return o;
}
static inline cJSON *vl_api_l2_interface_efp_filter_t_tojson (vl_api_l2_interface_efp_filter_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_interface_efp_filter");
    cJSON_AddStringToObject(o, "_crc", "5501adee");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    return o;
}
static inline cJSON *vl_api_l2_interface_efp_filter_reply_t_tojson (vl_api_l2_interface_efp_filter_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_interface_efp_filter_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_vpath_t_tojson (vl_api_sw_interface_set_vpath_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_vpath");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_vpath_reply_t_tojson (vl_api_sw_interface_set_vpath_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_vpath_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bvi_create_t_tojson (vl_api_bvi_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bvi_create");
    cJSON_AddStringToObject(o, "_crc", "f5398559");
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    cJSON_AddNumberToObject(o, "user_instance", a->user_instance);
    return o;
}
static inline cJSON *vl_api_bvi_create_reply_t_tojson (vl_api_bvi_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bvi_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bvi_delete_t_tojson (vl_api_bvi_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bvi_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bvi_delete_reply_t_tojson (vl_api_bvi_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bvi_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_l2_arp_term_events_t_tojson (vl_api_want_l2_arp_term_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_l2_arp_term_events");
    cJSON_AddStringToObject(o, "_crc", "3ec6d6c2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_l2_arp_term_events_reply_t_tojson (vl_api_want_l2_arp_term_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_l2_arp_term_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_l2_arp_term_event_t_tojson (vl_api_l2_arp_term_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "l2_arp_term_event");
    cJSON_AddStringToObject(o, "_crc", "6963e07a");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddItemToObject(o, "ip", vl_api_address_t_tojson(&a->ip));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    return o;
}
#endif
