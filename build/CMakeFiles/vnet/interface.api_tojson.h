/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_interface_api_tojson_h
#define included_interface_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sw_interface_set_flags_t_tojson (vl_api_sw_interface_set_flags_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_flags");
    cJSON_AddStringToObject(o, "_crc", "f5aec1b8");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_if_status_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_sw_interface_set_flags_reply_t_tojson (vl_api_sw_interface_set_flags_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_flags_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_promisc_t_tojson (vl_api_sw_interface_set_promisc_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_promisc");
    cJSON_AddStringToObject(o, "_crc", "d40860d4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "promisc_on", a->promisc_on);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_promisc_reply_t_tojson (vl_api_sw_interface_set_promisc_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_promisc_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_hw_interface_set_mtu_t_tojson (vl_api_hw_interface_set_mtu_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "hw_interface_set_mtu");
    cJSON_AddStringToObject(o, "_crc", "e6746899");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "mtu", a->mtu);
    return o;
}
static inline cJSON *vl_api_hw_interface_set_mtu_reply_t_tojson (vl_api_hw_interface_set_mtu_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "hw_interface_set_mtu_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_mtu_t_tojson (vl_api_sw_interface_set_mtu_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_mtu");
    cJSON_AddStringToObject(o, "_crc", "5cbe85e5");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "mtu");
        for (i = 0; i < 4; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->mtu[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sw_interface_set_mtu_reply_t_tojson (vl_api_sw_interface_set_mtu_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_mtu_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_ip_directed_broadcast_t_tojson (vl_api_sw_interface_set_ip_directed_broadcast_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_ip_directed_broadcast");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_ip_directed_broadcast_reply_t_tojson (vl_api_sw_interface_set_ip_directed_broadcast_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_ip_directed_broadcast_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_event_t_tojson (vl_api_sw_interface_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_event");
    cJSON_AddStringToObject(o, "_crc", "2d3d95a7");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_if_status_flags_t_tojson(a->flags));
    cJSON_AddBoolToObject(o, "deleted", a->deleted);
    return o;
}
static inline cJSON *vl_api_want_interface_events_t_tojson (vl_api_want_interface_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_interface_events");
    cJSON_AddStringToObject(o, "_crc", "476f5a08");
    cJSON_AddNumberToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_interface_events_reply_t_tojson (vl_api_want_interface_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_interface_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_details_t_tojson (vl_api_sw_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_details");
    cJSON_AddStringToObject(o, "_crc", "6c221fc7");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "sup_sw_if_index", a->sup_sw_if_index);
    cJSON_AddItemToObject(o, "l2_address", vl_api_mac_address_t_tojson(&a->l2_address));
    cJSON_AddItemToObject(o, "flags", vl_api_if_status_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "type", vl_api_if_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "link_duplex", vl_api_link_duplex_t_tojson(a->link_duplex));
    cJSON_AddNumberToObject(o, "link_speed", a->link_speed);
    cJSON_AddNumberToObject(o, "link_mtu", a->link_mtu);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "mtu");
        for (i = 0; i < 4; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->mtu[i]));
        }
    }
    cJSON_AddNumberToObject(o, "sub_id", a->sub_id);
    cJSON_AddNumberToObject(o, "sub_number_of_tags", a->sub_number_of_tags);
    cJSON_AddNumberToObject(o, "sub_outer_vlan_id", a->sub_outer_vlan_id);
    cJSON_AddNumberToObject(o, "sub_inner_vlan_id", a->sub_inner_vlan_id);
    cJSON_AddItemToObject(o, "sub_if_flags", vl_api_sub_if_flags_t_tojson(a->sub_if_flags));
    cJSON_AddNumberToObject(o, "vtr_op", a->vtr_op);
    cJSON_AddNumberToObject(o, "vtr_push_dot1q", a->vtr_push_dot1q);
    cJSON_AddNumberToObject(o, "vtr_tag1", a->vtr_tag1);
    cJSON_AddNumberToObject(o, "vtr_tag2", a->vtr_tag2);
    cJSON_AddNumberToObject(o, "outer_tag", a->outer_tag);
    cJSON_AddItemToObject(o, "b_dmac", vl_api_mac_address_t_tojson(&a->b_dmac));
    cJSON_AddItemToObject(o, "b_smac", vl_api_mac_address_t_tojson(&a->b_smac));
    cJSON_AddNumberToObject(o, "b_vlanid", a->b_vlanid);
    cJSON_AddNumberToObject(o, "i_sid", a->i_sid);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    cJSON_AddStringToObject(o, "interface_dev_type", (char *)a->interface_dev_type);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_sw_interface_dump_t_tojson (vl_api_sw_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "aa610c27");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "name_filter_valid", a->name_filter_valid);
    vl_api_string_cJSON_AddToObject(o, "name_filter", &a->name_filter);
    return o;
}
static inline cJSON *vl_api_sw_interface_add_del_address_t_tojson (vl_api_sw_interface_add_del_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_add_del_address");
    cJSON_AddStringToObject(o, "_crc", "5463d73b");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "del_all", a->del_all);
    cJSON_AddItemToObject(o, "prefix", vl_api_address_with_prefix_t_tojson(&a->prefix));
    return o;
}
static inline cJSON *vl_api_sw_interface_add_del_address_reply_t_tojson (vl_api_sw_interface_add_del_address_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_add_del_address_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_address_replace_begin_t_tojson (vl_api_sw_interface_address_replace_begin_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_address_replace_begin");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sw_interface_address_replace_begin_reply_t_tojson (vl_api_sw_interface_address_replace_begin_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_address_replace_begin_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_address_replace_end_t_tojson (vl_api_sw_interface_address_replace_end_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_address_replace_end");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sw_interface_address_replace_end_reply_t_tojson (vl_api_sw_interface_address_replace_end_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_address_replace_end_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_table_t_tojson (vl_api_sw_interface_set_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_table");
    cJSON_AddStringToObject(o, "_crc", "df42a577");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_table_reply_t_tojson (vl_api_sw_interface_set_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_table_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_get_table_t_tojson (vl_api_sw_interface_get_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_get_table");
    cJSON_AddStringToObject(o, "_crc", "2d033de4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_ipv6", a->is_ipv6);
    return o;
}
static inline cJSON *vl_api_sw_interface_get_table_reply_t_tojson (vl_api_sw_interface_get_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_get_table_reply");
    cJSON_AddStringToObject(o, "_crc", "a6eb0109");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_unnumbered_t_tojson (vl_api_sw_interface_set_unnumbered_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_unnumbered");
    cJSON_AddStringToObject(o, "_crc", "154a6439");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "unnumbered_sw_if_index", a->unnumbered_sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_unnumbered_reply_t_tojson (vl_api_sw_interface_set_unnumbered_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_unnumbered_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_clear_stats_t_tojson (vl_api_sw_interface_clear_stats_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_clear_stats");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_clear_stats_reply_t_tojson (vl_api_sw_interface_clear_stats_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_clear_stats_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_tag_add_del_t_tojson (vl_api_sw_interface_tag_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tag_add_del");
    cJSON_AddStringToObject(o, "_crc", "426f8bc1");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_sw_interface_tag_add_del_reply_t_tojson (vl_api_sw_interface_tag_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tag_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_add_del_mac_address_t_tojson (vl_api_sw_interface_add_del_mac_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_add_del_mac_address");
    cJSON_AddStringToObject(o, "_crc", "638bb9f4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "addr", vl_api_mac_address_t_tojson(&a->addr));
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_sw_interface_add_del_mac_address_reply_t_tojson (vl_api_sw_interface_add_del_mac_address_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_add_del_mac_address_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_mac_address_t_tojson (vl_api_sw_interface_set_mac_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_mac_address");
    cJSON_AddStringToObject(o, "_crc", "c536e7eb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    return o;
}
static inline cJSON *vl_api_sw_interface_set_mac_address_reply_t_tojson (vl_api_sw_interface_set_mac_address_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_mac_address_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_get_mac_address_t_tojson (vl_api_sw_interface_get_mac_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_get_mac_address");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_get_mac_address_reply_t_tojson (vl_api_sw_interface_get_mac_address_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_get_mac_address_reply");
    cJSON_AddStringToObject(o, "_crc", "40ef2c08");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    return o;
}
static inline cJSON *vl_api_sw_interface_set_rx_mode_t_tojson (vl_api_sw_interface_set_rx_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_rx_mode");
    cJSON_AddStringToObject(o, "_crc", "b04d1cfe");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "queue_id_valid", a->queue_id_valid);
    cJSON_AddNumberToObject(o, "queue_id", a->queue_id);
    cJSON_AddItemToObject(o, "mode", vl_api_rx_mode_t_tojson(a->mode));
    return o;
}
static inline cJSON *vl_api_sw_interface_set_rx_mode_reply_t_tojson (vl_api_sw_interface_set_rx_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_rx_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_rx_placement_t_tojson (vl_api_sw_interface_set_rx_placement_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_rx_placement");
    cJSON_AddStringToObject(o, "_crc", "db65f3c9");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "queue_id", a->queue_id);
    cJSON_AddNumberToObject(o, "worker_id", a->worker_id);
    cJSON_AddBoolToObject(o, "is_main", a->is_main);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_rx_placement_reply_t_tojson (vl_api_sw_interface_set_rx_placement_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_rx_placement_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_tx_placement_t_tojson (vl_api_sw_interface_set_tx_placement_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_tx_placement");
    cJSON_AddStringToObject(o, "_crc", "4e0cd5ff");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "queue_id", a->queue_id);
    cJSON_AddNumberToObject(o, "array_size", a->array_size);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "threads");
        for (i = 0; i < a->array_size; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->threads[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sw_interface_set_tx_placement_reply_t_tojson (vl_api_sw_interface_set_tx_placement_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_tx_placement_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_interface_name_t_tojson (vl_api_sw_interface_set_interface_name_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_interface_name");
    cJSON_AddStringToObject(o, "_crc", "45a1d548");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_interface_name_reply_t_tojson (vl_api_sw_interface_set_interface_name_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_interface_name_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_rx_placement_dump_t_tojson (vl_api_sw_interface_rx_placement_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_rx_placement_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_rx_placement_details_t_tojson (vl_api_sw_interface_rx_placement_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_rx_placement_details");
    cJSON_AddStringToObject(o, "_crc", "9e44a7ce");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "queue_id", a->queue_id);
    cJSON_AddNumberToObject(o, "worker_id", a->worker_id);
    cJSON_AddItemToObject(o, "mode", vl_api_rx_mode_t_tojson(a->mode));
    return o;
}
static inline cJSON *vl_api_sw_interface_tx_placement_get_t_tojson (vl_api_sw_interface_tx_placement_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tx_placement_get");
    cJSON_AddStringToObject(o, "_crc", "47250981");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sw_interface_tx_placement_get_reply_t_tojson (vl_api_sw_interface_tx_placement_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tx_placement_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_sw_interface_tx_placement_details_t_tojson (vl_api_sw_interface_tx_placement_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_tx_placement_details");
    cJSON_AddStringToObject(o, "_crc", "00381a2e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "queue_id", a->queue_id);
    cJSON_AddNumberToObject(o, "shared", a->shared);
    cJSON_AddNumberToObject(o, "array_size", a->array_size);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "threads");
        for (i = 0; i < a->array_size; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->threads[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_interface_name_renumber_t_tojson (vl_api_interface_name_renumber_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "interface_name_renumber");
    cJSON_AddStringToObject(o, "_crc", "2b8858b8");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "new_show_dev_instance", a->new_show_dev_instance);
    return o;
}
static inline cJSON *vl_api_interface_name_renumber_reply_t_tojson (vl_api_interface_name_renumber_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "interface_name_renumber_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_create_subif_t_tojson (vl_api_create_subif_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_subif");
    cJSON_AddStringToObject(o, "_crc", "790ca755");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "sub_id", a->sub_id);
    cJSON_AddItemToObject(o, "sub_if_flags", vl_api_sub_if_flags_t_tojson(a->sub_if_flags));
    cJSON_AddNumberToObject(o, "outer_vlan_id", a->outer_vlan_id);
    cJSON_AddNumberToObject(o, "inner_vlan_id", a->inner_vlan_id);
    return o;
}
static inline cJSON *vl_api_create_subif_reply_t_tojson (vl_api_create_subif_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_subif_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_create_vlan_subif_t_tojson (vl_api_create_vlan_subif_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_vlan_subif");
    cJSON_AddStringToObject(o, "_crc", "af34ac8b");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "vlan_id", a->vlan_id);
    return o;
}
static inline cJSON *vl_api_create_vlan_subif_reply_t_tojson (vl_api_create_vlan_subif_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_vlan_subif_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_delete_subif_t_tojson (vl_api_delete_subif_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "delete_subif");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_delete_subif_reply_t_tojson (vl_api_delete_subif_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "delete_subif_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_create_loopback_t_tojson (vl_api_create_loopback_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_loopback");
    cJSON_AddStringToObject(o, "_crc", "42bb5d22");
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    return o;
}
static inline cJSON *vl_api_create_loopback_reply_t_tojson (vl_api_create_loopback_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_loopback_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_create_loopback_instance_t_tojson (vl_api_create_loopback_instance_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_loopback_instance");
    cJSON_AddStringToObject(o, "_crc", "d36a3ee2");
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    cJSON_AddBoolToObject(o, "is_specified", a->is_specified);
    cJSON_AddNumberToObject(o, "user_instance", a->user_instance);
    return o;
}
static inline cJSON *vl_api_create_loopback_instance_reply_t_tojson (vl_api_create_loopback_instance_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "create_loopback_instance_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_delete_loopback_t_tojson (vl_api_delete_loopback_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "delete_loopback");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_delete_loopback_reply_t_tojson (vl_api_delete_loopback_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "delete_loopback_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_collect_detailed_interface_stats_t_tojson (vl_api_collect_detailed_interface_stats_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "collect_detailed_interface_stats");
    cJSON_AddStringToObject(o, "_crc", "5501adee");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    return o;
}
static inline cJSON *vl_api_collect_detailed_interface_stats_reply_t_tojson (vl_api_collect_detailed_interface_stats_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "collect_detailed_interface_stats_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pcap_set_filter_function_t_tojson (vl_api_pcap_set_filter_function_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pcap_set_filter_function");
    cJSON_AddStringToObject(o, "_crc", "616abb92");
    vl_api_string_cJSON_AddToObject(o, "filter_function_name", &a->filter_function_name);
    return o;
}
static inline cJSON *vl_api_pcap_set_filter_function_reply_t_tojson (vl_api_pcap_set_filter_function_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pcap_set_filter_function_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pcap_trace_on_t_tojson (vl_api_pcap_trace_on_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pcap_trace_on");
    cJSON_AddStringToObject(o, "_crc", "cb39e968");
    cJSON_AddBoolToObject(o, "capture_rx", a->capture_rx);
    cJSON_AddBoolToObject(o, "capture_tx", a->capture_tx);
    cJSON_AddBoolToObject(o, "capture_drop", a->capture_drop);
    cJSON_AddBoolToObject(o, "filter", a->filter);
    cJSON_AddBoolToObject(o, "preallocate_data", a->preallocate_data);
    cJSON_AddBoolToObject(o, "free_data", a->free_data);
    cJSON_AddNumberToObject(o, "max_packets", a->max_packets);
    cJSON_AddNumberToObject(o, "max_bytes_per_packet", a->max_bytes_per_packet);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "error", (char *)a->error);
    cJSON_AddStringToObject(o, "filename", (char *)a->filename);
    return o;
}
static inline cJSON *vl_api_pcap_trace_on_reply_t_tojson (vl_api_pcap_trace_on_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pcap_trace_on_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pcap_trace_off_t_tojson (vl_api_pcap_trace_off_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pcap_trace_off");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_pcap_trace_off_reply_t_tojson (vl_api_pcap_trace_off_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pcap_trace_off_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
