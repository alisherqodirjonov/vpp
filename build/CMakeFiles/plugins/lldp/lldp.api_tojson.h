/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_lldp_api_tojson_h
#define included_lldp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_port_id_subtype_t_tojson (vl_api_port_id_subtype_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("PORT_ID_SUBTYPE_RESERVED");
    case 1:
        return cJSON_CreateString("PORT_ID_SUBTYPE_INTF_ALIAS");
    case 2:
        return cJSON_CreateString("PORT_ID_SUBTYPE_PORT_COMP");
    case 3:
        return cJSON_CreateString("PORT_ID_SUBTYPE_MAC_ADDR");
    case 4:
        return cJSON_CreateString("PORT_ID_SUBTYPE_NET_ADDR");
    case 5:
        return cJSON_CreateString("PORT_ID_SUBTYPE_INTF_NAME");
    case 6:
        return cJSON_CreateString("PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID");
    case 7:
        return cJSON_CreateString("PORT_ID_SUBTYPE_LOCAL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_chassis_id_subtype_t_tojson (vl_api_chassis_id_subtype_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_RESERVED");
    case 1:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_CHASSIS_COMP");
    case 2:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_INTF_ALIAS");
    case 3:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_PORT_COMP");
    case 4:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_MAC_ADDR");
    case 5:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_NET_ADDR");
    case 6:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_INTF_NAME");
    case 7:
        return cJSON_CreateString("CHASSIS_ID_SUBTYPE_LOCAL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_lldp_config_t_tojson (vl_api_lldp_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lldp_config");
    cJSON_AddStringToObject(o, "_crc", "c14445df");
    cJSON_AddNumberToObject(o, "tx_hold", a->tx_hold);
    cJSON_AddNumberToObject(o, "tx_interval", a->tx_interval);
    vl_api_string_cJSON_AddToObject(o, "system_name", &a->system_name);
    return o;
}
static inline cJSON *vl_api_lldp_config_reply_t_tojson (vl_api_lldp_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lldp_config_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_lldp_t_tojson (vl_api_sw_interface_set_lldp_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_lldp");
    cJSON_AddStringToObject(o, "_crc", "57afbcd4");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "mgmt_ip4", vl_api_ip4_address_t_tojson(&a->mgmt_ip4));
    cJSON_AddItemToObject(o, "mgmt_ip6", vl_api_ip6_address_t_tojson(&a->mgmt_ip6));
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->mgmt_oid, 128);
    cJSON_AddStringToObject(o, "mgmt_oid", s);
    vec_free(s);
    }
    cJSON_AddBoolToObject(o, "enable", a->enable);
    vl_api_string_cJSON_AddToObject(o, "port_desc", &a->port_desc);
    return o;
}
static inline cJSON *vl_api_sw_interface_set_lldp_reply_t_tojson (vl_api_sw_interface_set_lldp_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_set_lldp_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_lldp_dump_t_tojson (vl_api_lldp_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lldp_dump");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_lldp_dump_reply_t_tojson (vl_api_lldp_dump_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lldp_dump_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_lldp_details_t_tojson (vl_api_lldp_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "lldp_details");
    cJSON_AddStringToObject(o, "_crc", "c2d226cd");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "last_heard", a->last_heard);
    cJSON_AddNumberToObject(o, "last_sent", a->last_sent);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->chassis_id, 64);
    cJSON_AddStringToObject(o, "chassis_id", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "chassis_id_len", a->chassis_id_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->port_id, 64);
    cJSON_AddStringToObject(o, "port_id", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "port_id_len", a->port_id_len);
    cJSON_AddNumberToObject(o, "ttl", a->ttl);
    cJSON_AddItemToObject(o, "port_id_subtype", vl_api_port_id_subtype_t_tojson(a->port_id_subtype));
    cJSON_AddItemToObject(o, "chassis_id_subtype", vl_api_chassis_id_subtype_t_tojson(a->chassis_id_subtype));
    return o;
}
#endif
