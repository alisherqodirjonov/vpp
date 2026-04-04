/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_bfd_api_tojson_h
#define included_bfd_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_bfd_state_t_tojson (vl_api_bfd_state_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("BFD_STATE_API_ADMIN_DOWN");
    case 1:
        return cJSON_CreateString("BFD_STATE_API_DOWN");
    case 2:
        return cJSON_CreateString("BFD_STATE_API_INIT");
    case 3:
        return cJSON_CreateString("BFD_STATE_API_UP");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_bfd_udp_set_echo_source_t_tojson (vl_api_bfd_udp_set_echo_source_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_set_echo_source");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_bfd_udp_set_echo_source_reply_t_tojson (vl_api_bfd_udp_set_echo_source_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_set_echo_source_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_del_echo_source_t_tojson (vl_api_bfd_udp_del_echo_source_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_del_echo_source");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bfd_udp_del_echo_source_reply_t_tojson (vl_api_bfd_udp_del_echo_source_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_del_echo_source_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_get_echo_source_t_tojson (vl_api_bfd_udp_get_echo_source_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_get_echo_source");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bfd_udp_get_echo_source_reply_t_tojson (vl_api_bfd_udp_get_echo_source_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_get_echo_source_reply");
    cJSON_AddStringToObject(o, "_crc", "e3d736a1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_set", a->is_set);
    cJSON_AddBoolToObject(o, "have_usable_ip4", a->have_usable_ip4);
    cJSON_AddItemToObject(o, "ip4_addr", vl_api_ip4_address_t_tojson(&a->ip4_addr));
    cJSON_AddBoolToObject(o, "have_usable_ip6", a->have_usable_ip6);
    cJSON_AddItemToObject(o, "ip6_addr", vl_api_ip6_address_t_tojson(&a->ip6_addr));
    return o;
}
static inline cJSON *vl_api_bfd_udp_add_t_tojson (vl_api_bfd_udp_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_add");
    cJSON_AddStringToObject(o, "_crc", "939cd26a");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "desired_min_tx", a->desired_min_tx);
    cJSON_AddNumberToObject(o, "required_min_rx", a->required_min_rx);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddNumberToObject(o, "detect_mult", a->detect_mult);
    cJSON_AddBoolToObject(o, "is_authenticated", a->is_authenticated);
    cJSON_AddNumberToObject(o, "bfd_key_id", a->bfd_key_id);
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    return o;
}
static inline cJSON *vl_api_bfd_udp_add_reply_t_tojson (vl_api_bfd_udp_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_upd_t_tojson (vl_api_bfd_udp_upd_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_upd");
    cJSON_AddStringToObject(o, "_crc", "939cd26a");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "desired_min_tx", a->desired_min_tx);
    cJSON_AddNumberToObject(o, "required_min_rx", a->required_min_rx);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddNumberToObject(o, "detect_mult", a->detect_mult);
    cJSON_AddBoolToObject(o, "is_authenticated", a->is_authenticated);
    cJSON_AddNumberToObject(o, "bfd_key_id", a->bfd_key_id);
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    return o;
}
static inline cJSON *vl_api_bfd_udp_upd_reply_t_tojson (vl_api_bfd_udp_upd_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_upd_reply");
    cJSON_AddStringToObject(o, "_crc", "1992deab");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stats_index", a->stats_index);
    return o;
}
static inline cJSON *vl_api_bfd_udp_mod_t_tojson (vl_api_bfd_udp_mod_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_mod");
    cJSON_AddStringToObject(o, "_crc", "913df085");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "desired_min_tx", a->desired_min_tx);
    cJSON_AddNumberToObject(o, "required_min_rx", a->required_min_rx);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddNumberToObject(o, "detect_mult", a->detect_mult);
    return o;
}
static inline cJSON *vl_api_bfd_udp_mod_reply_t_tojson (vl_api_bfd_udp_mod_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_mod_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_del_t_tojson (vl_api_bfd_udp_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_del");
    cJSON_AddStringToObject(o, "_crc", "dcb13a89");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    return o;
}
static inline cJSON *vl_api_bfd_udp_del_reply_t_tojson (vl_api_bfd_udp_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_session_dump_t_tojson (vl_api_bfd_udp_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_session_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bfd_udp_session_details_t_tojson (vl_api_bfd_udp_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_session_details");
    cJSON_AddStringToObject(o, "_crc", "09fb2f2d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddItemToObject(o, "state", vl_api_bfd_state_t_tojson(a->state));
    cJSON_AddBoolToObject(o, "is_authenticated", a->is_authenticated);
    cJSON_AddNumberToObject(o, "bfd_key_id", a->bfd_key_id);
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    cJSON_AddNumberToObject(o, "required_min_rx", a->required_min_rx);
    cJSON_AddNumberToObject(o, "desired_min_tx", a->desired_min_tx);
    cJSON_AddNumberToObject(o, "detect_mult", a->detect_mult);
    return o;
}
static inline cJSON *vl_api_bfd_udp_session_set_flags_t_tojson (vl_api_bfd_udp_session_set_flags_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_session_set_flags");
    cJSON_AddStringToObject(o, "_crc", "04b4bdfd");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddItemToObject(o, "flags", vl_api_if_status_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_bfd_udp_session_set_flags_reply_t_tojson (vl_api_bfd_udp_session_set_flags_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_session_set_flags_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_want_bfd_events_t_tojson (vl_api_want_bfd_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_bfd_events");
    cJSON_AddStringToObject(o, "_crc", "c5e2af94");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_bfd_events_reply_t_tojson (vl_api_want_bfd_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_bfd_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_session_event_t_tojson (vl_api_bfd_udp_session_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_session_event");
    cJSON_AddStringToObject(o, "_crc", "8eaaf062");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddItemToObject(o, "state", vl_api_bfd_state_t_tojson(a->state));
    cJSON_AddBoolToObject(o, "is_authenticated", a->is_authenticated);
    cJSON_AddNumberToObject(o, "bfd_key_id", a->bfd_key_id);
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    cJSON_AddNumberToObject(o, "required_min_rx", a->required_min_rx);
    cJSON_AddNumberToObject(o, "desired_min_tx", a->desired_min_tx);
    cJSON_AddNumberToObject(o, "detect_mult", a->detect_mult);
    return o;
}
static inline cJSON *vl_api_bfd_auth_set_key_t_tojson (vl_api_bfd_auth_set_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_auth_set_key");
    cJSON_AddStringToObject(o, "_crc", "690b8877");
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    cJSON_AddNumberToObject(o, "key_len", a->key_len);
    cJSON_AddNumberToObject(o, "auth_type", a->auth_type);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->key, 20);
    cJSON_AddStringToObject(o, "key", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_bfd_auth_set_key_reply_t_tojson (vl_api_bfd_auth_set_key_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_auth_set_key_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_auth_del_key_t_tojson (vl_api_bfd_auth_del_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_auth_del_key");
    cJSON_AddStringToObject(o, "_crc", "65310b22");
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    return o;
}
static inline cJSON *vl_api_bfd_auth_del_key_reply_t_tojson (vl_api_bfd_auth_del_key_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_auth_del_key_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_auth_keys_dump_t_tojson (vl_api_bfd_auth_keys_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_auth_keys_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bfd_auth_keys_details_t_tojson (vl_api_bfd_auth_keys_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_auth_keys_details");
    cJSON_AddStringToObject(o, "_crc", "84130e9f");
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    cJSON_AddNumberToObject(o, "use_count", a->use_count);
    cJSON_AddNumberToObject(o, "auth_type", a->auth_type);
    return o;
}
static inline cJSON *vl_api_bfd_udp_auth_activate_t_tojson (vl_api_bfd_udp_auth_activate_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_auth_activate");
    cJSON_AddStringToObject(o, "_crc", "21fd1bdb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddBoolToObject(o, "is_delayed", a->is_delayed);
    cJSON_AddNumberToObject(o, "bfd_key_id", a->bfd_key_id);
    cJSON_AddNumberToObject(o, "conf_key_id", a->conf_key_id);
    return o;
}
static inline cJSON *vl_api_bfd_udp_auth_activate_reply_t_tojson (vl_api_bfd_udp_auth_activate_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_auth_activate_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_auth_deactivate_t_tojson (vl_api_bfd_udp_auth_deactivate_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_auth_deactivate");
    cJSON_AddStringToObject(o, "_crc", "9a05e2e0");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_addr", vl_api_address_t_tojson(&a->local_addr));
    cJSON_AddItemToObject(o, "peer_addr", vl_api_address_t_tojson(&a->peer_addr));
    cJSON_AddBoolToObject(o, "is_delayed", a->is_delayed);
    return o;
}
static inline cJSON *vl_api_bfd_udp_auth_deactivate_reply_t_tojson (vl_api_bfd_udp_auth_deactivate_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_auth_deactivate_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_enable_multihop_t_tojson (vl_api_bfd_udp_enable_multihop_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_enable_multihop");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bfd_udp_enable_multihop_reply_t_tojson (vl_api_bfd_udp_enable_multihop_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_enable_multihop_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_set_tos_t_tojson (vl_api_bfd_udp_set_tos_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_set_tos");
    cJSON_AddStringToObject(o, "_crc", "00fe25ce");
    cJSON_AddNumberToObject(o, "tos", a->tos);
    return o;
}
static inline cJSON *vl_api_bfd_udp_set_tos_reply_t_tojson (vl_api_bfd_udp_set_tos_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_set_tos_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bfd_udp_get_tos_t_tojson (vl_api_bfd_udp_get_tos_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_get_tos");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bfd_udp_get_tos_reply_t_tojson (vl_api_bfd_udp_get_tos_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bfd_udp_get_tos_reply");
    cJSON_AddStringToObject(o, "_crc", "d8931abf");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "tos", a->tos);
    return o;
}
#endif
