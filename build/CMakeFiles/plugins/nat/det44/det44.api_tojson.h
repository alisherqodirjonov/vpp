/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <nat/lib/nat_types.api_tojson.h>
#ifndef included_det44_api_tojson_h
#define included_det44_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_det44_plugin_enable_disable_t_tojson (vl_api_det44_plugin_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_plugin_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "617b6bf8");
    cJSON_AddNumberToObject(o, "inside_vrf", a->inside_vrf);
    cJSON_AddNumberToObject(o, "outside_vrf", a->outside_vrf);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_det44_plugin_enable_disable_reply_t_tojson (vl_api_det44_plugin_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_plugin_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_det44_interface_add_del_feature_t_tojson (vl_api_det44_interface_add_del_feature_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_interface_add_del_feature");
    cJSON_AddStringToObject(o, "_crc", "dc17a836");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_inside", a->is_inside);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_det44_interface_add_del_feature_reply_t_tojson (vl_api_det44_interface_add_del_feature_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_interface_add_del_feature_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_det44_interface_dump_t_tojson (vl_api_det44_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_det44_interface_details_t_tojson (vl_api_det44_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_interface_details");
    cJSON_AddStringToObject(o, "_crc", "e60cc5be");
    cJSON_AddBoolToObject(o, "is_inside", a->is_inside);
    cJSON_AddBoolToObject(o, "is_outside", a->is_outside);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_det44_add_del_map_t_tojson (vl_api_det44_add_del_map_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_add_del_map");
    cJSON_AddStringToObject(o, "_crc", "1150a190");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    cJSON_AddNumberToObject(o, "in_plen", a->in_plen);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    cJSON_AddNumberToObject(o, "out_plen", a->out_plen);
    return o;
}
static inline cJSON *vl_api_det44_add_del_map_reply_t_tojson (vl_api_det44_add_del_map_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_add_del_map_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_det44_forward_t_tojson (vl_api_det44_forward_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_forward");
    cJSON_AddStringToObject(o, "_crc", "7f8a89cd");
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    return o;
}
static inline cJSON *vl_api_det44_forward_reply_t_tojson (vl_api_det44_forward_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_forward_reply");
    cJSON_AddStringToObject(o, "_crc", "a8ccbdc0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "out_port_lo", a->out_port_lo);
    cJSON_AddNumberToObject(o, "out_port_hi", a->out_port_hi);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    return o;
}
static inline cJSON *vl_api_det44_reverse_t_tojson (vl_api_det44_reverse_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_reverse");
    cJSON_AddStringToObject(o, "_crc", "a7573fe1");
    cJSON_AddNumberToObject(o, "out_port", a->out_port);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    return o;
}
static inline cJSON *vl_api_det44_reverse_reply_t_tojson (vl_api_det44_reverse_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_reverse_reply");
    cJSON_AddStringToObject(o, "_crc", "34066d48");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    return o;
}
static inline cJSON *vl_api_det44_map_dump_t_tojson (vl_api_det44_map_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_map_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_det44_map_details_t_tojson (vl_api_det44_map_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_map_details");
    cJSON_AddStringToObject(o, "_crc", "ad91dc83");
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    cJSON_AddNumberToObject(o, "in_plen", a->in_plen);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    cJSON_AddNumberToObject(o, "out_plen", a->out_plen);
    cJSON_AddNumberToObject(o, "sharing_ratio", a->sharing_ratio);
    cJSON_AddNumberToObject(o, "ports_per_host", a->ports_per_host);
    cJSON_AddNumberToObject(o, "ses_num", a->ses_num);
    return o;
}
static inline cJSON *vl_api_det44_close_session_out_t_tojson (vl_api_det44_close_session_out_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_close_session_out");
    cJSON_AddStringToObject(o, "_crc", "f6b259d1");
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    cJSON_AddNumberToObject(o, "out_port", a->out_port);
    cJSON_AddItemToObject(o, "ext_addr", vl_api_ip4_address_t_tojson(&a->ext_addr));
    cJSON_AddNumberToObject(o, "ext_port", a->ext_port);
    return o;
}
static inline cJSON *vl_api_det44_close_session_out_reply_t_tojson (vl_api_det44_close_session_out_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_close_session_out_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_det44_close_session_in_t_tojson (vl_api_det44_close_session_in_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_close_session_in");
    cJSON_AddStringToObject(o, "_crc", "3c68e073");
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    cJSON_AddNumberToObject(o, "in_port", a->in_port);
    cJSON_AddItemToObject(o, "ext_addr", vl_api_ip4_address_t_tojson(&a->ext_addr));
    cJSON_AddNumberToObject(o, "ext_port", a->ext_port);
    return o;
}
static inline cJSON *vl_api_det44_close_session_in_reply_t_tojson (vl_api_det44_close_session_in_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_close_session_in_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_det44_session_dump_t_tojson (vl_api_det44_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_session_dump");
    cJSON_AddStringToObject(o, "_crc", "e45a3af7");
    cJSON_AddItemToObject(o, "user_addr", vl_api_ip4_address_t_tojson(&a->user_addr));
    return o;
}
static inline cJSON *vl_api_det44_session_details_t_tojson (vl_api_det44_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_session_details");
    cJSON_AddStringToObject(o, "_crc", "27f3c171");
    cJSON_AddNumberToObject(o, "in_port", a->in_port);
    cJSON_AddItemToObject(o, "ext_addr", vl_api_ip4_address_t_tojson(&a->ext_addr));
    cJSON_AddNumberToObject(o, "ext_port", a->ext_port);
    cJSON_AddNumberToObject(o, "out_port", a->out_port);
    cJSON_AddNumberToObject(o, "state", a->state);
    cJSON_AddNumberToObject(o, "expire", a->expire);
    return o;
}
static inline cJSON *vl_api_det44_set_timeouts_t_tojson (vl_api_det44_set_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_set_timeouts");
    cJSON_AddStringToObject(o, "_crc", "d4746b16");
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_det44_set_timeouts_reply_t_tojson (vl_api_det44_set_timeouts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_set_timeouts_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_det44_get_timeouts_t_tojson (vl_api_det44_get_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_get_timeouts");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_det44_get_timeouts_reply_t_tojson (vl_api_det44_get_timeouts_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "det44_get_timeouts_reply");
    cJSON_AddStringToObject(o, "_crc", "3c4df4e1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_nat_det_add_del_map_t_tojson (vl_api_nat_det_add_del_map_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_add_del_map");
    cJSON_AddStringToObject(o, "_crc", "1150a190");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    cJSON_AddNumberToObject(o, "in_plen", a->in_plen);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    cJSON_AddNumberToObject(o, "out_plen", a->out_plen);
    return o;
}
static inline cJSON *vl_api_nat_det_add_del_map_reply_t_tojson (vl_api_nat_det_add_del_map_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_add_del_map_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_det_forward_t_tojson (vl_api_nat_det_forward_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_forward");
    cJSON_AddStringToObject(o, "_crc", "7f8a89cd");
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    return o;
}
static inline cJSON *vl_api_nat_det_forward_reply_t_tojson (vl_api_nat_det_forward_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_forward_reply");
    cJSON_AddStringToObject(o, "_crc", "a8ccbdc0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "out_port_lo", a->out_port_lo);
    cJSON_AddNumberToObject(o, "out_port_hi", a->out_port_hi);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    return o;
}
static inline cJSON *vl_api_nat_det_reverse_t_tojson (vl_api_nat_det_reverse_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_reverse");
    cJSON_AddStringToObject(o, "_crc", "a7573fe1");
    cJSON_AddNumberToObject(o, "out_port", a->out_port);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    return o;
}
static inline cJSON *vl_api_nat_det_reverse_reply_t_tojson (vl_api_nat_det_reverse_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_reverse_reply");
    cJSON_AddStringToObject(o, "_crc", "34066d48");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    return o;
}
static inline cJSON *vl_api_nat_det_map_dump_t_tojson (vl_api_nat_det_map_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_map_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_nat_det_map_details_t_tojson (vl_api_nat_det_map_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_map_details");
    cJSON_AddStringToObject(o, "_crc", "ad91dc83");
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    cJSON_AddNumberToObject(o, "in_plen", a->in_plen);
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    cJSON_AddNumberToObject(o, "out_plen", a->out_plen);
    cJSON_AddNumberToObject(o, "sharing_ratio", a->sharing_ratio);
    cJSON_AddNumberToObject(o, "ports_per_host", a->ports_per_host);
    cJSON_AddNumberToObject(o, "ses_num", a->ses_num);
    return o;
}
static inline cJSON *vl_api_nat_det_close_session_out_t_tojson (vl_api_nat_det_close_session_out_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_close_session_out");
    cJSON_AddStringToObject(o, "_crc", "f6b259d1");
    cJSON_AddItemToObject(o, "out_addr", vl_api_ip4_address_t_tojson(&a->out_addr));
    cJSON_AddNumberToObject(o, "out_port", a->out_port);
    cJSON_AddItemToObject(o, "ext_addr", vl_api_ip4_address_t_tojson(&a->ext_addr));
    cJSON_AddNumberToObject(o, "ext_port", a->ext_port);
    return o;
}
static inline cJSON *vl_api_nat_det_close_session_out_reply_t_tojson (vl_api_nat_det_close_session_out_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_close_session_out_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_det_close_session_in_t_tojson (vl_api_nat_det_close_session_in_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_close_session_in");
    cJSON_AddStringToObject(o, "_crc", "3c68e073");
    cJSON_AddItemToObject(o, "in_addr", vl_api_ip4_address_t_tojson(&a->in_addr));
    cJSON_AddNumberToObject(o, "in_port", a->in_port);
    cJSON_AddItemToObject(o, "ext_addr", vl_api_ip4_address_t_tojson(&a->ext_addr));
    cJSON_AddNumberToObject(o, "ext_port", a->ext_port);
    return o;
}
static inline cJSON *vl_api_nat_det_close_session_in_reply_t_tojson (vl_api_nat_det_close_session_in_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_close_session_in_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nat_det_session_dump_t_tojson (vl_api_nat_det_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_session_dump");
    cJSON_AddStringToObject(o, "_crc", "e45a3af7");
    cJSON_AddItemToObject(o, "user_addr", vl_api_ip4_address_t_tojson(&a->user_addr));
    return o;
}
static inline cJSON *vl_api_nat_det_session_details_t_tojson (vl_api_nat_det_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nat_det_session_details");
    cJSON_AddStringToObject(o, "_crc", "27f3c171");
    cJSON_AddNumberToObject(o, "in_port", a->in_port);
    cJSON_AddItemToObject(o, "ext_addr", vl_api_ip4_address_t_tojson(&a->ext_addr));
    cJSON_AddNumberToObject(o, "ext_port", a->ext_port);
    cJSON_AddNumberToObject(o, "out_port", a->out_port);
    cJSON_AddNumberToObject(o, "state", a->state);
    cJSON_AddNumberToObject(o, "expire", a->expire);
    return o;
}
#endif
