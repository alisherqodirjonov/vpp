/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_wireguard_api_tojson_h
#define included_wireguard_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_wireguard_interface_t_tojson (vl_api_wireguard_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "user_instance", a->user_instance);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->private_key, 32);
    cJSON_AddStringToObject(o, "private_key", s);
    vec_free(s);
    }
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->public_key, 32);
    cJSON_AddStringToObject(o, "public_key", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddItemToObject(o, "src_ip", vl_api_address_t_tojson(&a->src_ip));
    return o;
}
static inline cJSON *vl_api_wireguard_peer_flags_t_tojson (vl_api_wireguard_peer_flags_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("WIREGUARD_PEER_STATUS_DEAD");
    case 2:
        return cJSON_CreateString("WIREGUARD_PEER_ESTABLISHED");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_wireguard_peer_t_tojson (vl_api_wireguard_peer_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "peer_index", a->peer_index);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->public_key, 32);
    cJSON_AddStringToObject(o, "public_key", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddNumberToObject(o, "persistent_keepalive", a->persistent_keepalive);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "endpoint", vl_api_address_t_tojson(&a->endpoint));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "flags", vl_api_wireguard_peer_flags_t_tojson(a->flags));
    cJSON_AddNumberToObject(o, "n_allowed_ips", a->n_allowed_ips);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "allowed_ips");
        for (i = 0; i < a->n_allowed_ips; i++) {
            cJSON_AddItemToArray(array, vl_api_prefix_t_tojson(&a->allowed_ips[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_wireguard_interface_create_t_tojson (vl_api_wireguard_interface_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_interface_create");
    cJSON_AddStringToObject(o, "_crc", "a530137e");
    cJSON_AddItemToObject(o, "interface", vl_api_wireguard_interface_t_tojson(&a->interface));
    cJSON_AddBoolToObject(o, "generate_key", a->generate_key);
    return o;
}
static inline cJSON *vl_api_wireguard_interface_create_reply_t_tojson (vl_api_wireguard_interface_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_interface_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_wireguard_interface_delete_t_tojson (vl_api_wireguard_interface_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_interface_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_wireguard_interface_delete_reply_t_tojson (vl_api_wireguard_interface_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_interface_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_wireguard_interface_dump_t_tojson (vl_api_wireguard_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "2c954158");
    cJSON_AddBoolToObject(o, "show_private_key", a->show_private_key);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_wireguard_interface_details_t_tojson (vl_api_wireguard_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_interface_details");
    cJSON_AddStringToObject(o, "_crc", "0dd4865d");
    cJSON_AddItemToObject(o, "interface", vl_api_wireguard_interface_t_tojson(&a->interface));
    return o;
}
static inline cJSON *vl_api_want_wireguard_peer_events_t_tojson (vl_api_want_wireguard_peer_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_wireguard_peer_events");
    cJSON_AddStringToObject(o, "_crc", "3bc666c8");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "peer_index", a->peer_index);
    cJSON_AddNumberToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    return o;
}
static inline cJSON *vl_api_want_wireguard_peer_events_reply_t_tojson (vl_api_want_wireguard_peer_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_wireguard_peer_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_wireguard_peer_event_t_tojson (vl_api_wireguard_peer_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peer_event");
    cJSON_AddStringToObject(o, "_crc", "4e1b5d67");
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "peer_index", a->peer_index);
    cJSON_AddItemToObject(o, "flags", vl_api_wireguard_peer_flags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_wireguard_peer_add_t_tojson (vl_api_wireguard_peer_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peer_add");
    cJSON_AddStringToObject(o, "_crc", "9b8aad61");
    cJSON_AddItemToObject(o, "peer", vl_api_wireguard_peer_t_tojson(&a->peer));
    return o;
}
static inline cJSON *vl_api_wireguard_peer_add_reply_t_tojson (vl_api_wireguard_peer_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peer_add_reply");
    cJSON_AddStringToObject(o, "_crc", "084a0cd3");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "peer_index", a->peer_index);
    return o;
}
static inline cJSON *vl_api_wireguard_peer_remove_t_tojson (vl_api_wireguard_peer_remove_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peer_remove");
    cJSON_AddStringToObject(o, "_crc", "3b74607a");
    cJSON_AddNumberToObject(o, "peer_index", a->peer_index);
    return o;
}
static inline cJSON *vl_api_wireguard_peer_remove_reply_t_tojson (vl_api_wireguard_peer_remove_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peer_remove_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_wireguard_peers_dump_t_tojson (vl_api_wireguard_peers_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peers_dump");
    cJSON_AddStringToObject(o, "_crc", "3b74607a");
    cJSON_AddNumberToObject(o, "peer_index", a->peer_index);
    return o;
}
static inline cJSON *vl_api_wireguard_peers_details_t_tojson (vl_api_wireguard_peers_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wireguard_peers_details");
    cJSON_AddStringToObject(o, "_crc", "6a9f6bc3");
    cJSON_AddItemToObject(o, "peer", vl_api_wireguard_peer_t_tojson(&a->peer));
    return o;
}
static inline cJSON *vl_api_wg_set_async_mode_t_tojson (vl_api_wg_set_async_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wg_set_async_mode");
    cJSON_AddStringToObject(o, "_crc", "a6465f7c");
    cJSON_AddBoolToObject(o, "async_enable", a->async_enable);
    return o;
}
static inline cJSON *vl_api_wg_set_async_mode_reply_t_tojson (vl_api_wg_set_async_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "wg_set_async_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
