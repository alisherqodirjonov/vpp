/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_lacp_api_tojson_h
#define included_lacp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sw_interface_lacp_dump_t_tojson (vl_api_sw_interface_lacp_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_lacp_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sw_interface_lacp_details_t_tojson (vl_api_sw_interface_lacp_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sw_interface_lacp_details");
    cJSON_AddStringToObject(o, "_crc", "d9a83d2f");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddStringToObject(o, "interface_name", (char *)a->interface_name);
    cJSON_AddNumberToObject(o, "rx_state", a->rx_state);
    cJSON_AddNumberToObject(o, "tx_state", a->tx_state);
    cJSON_AddNumberToObject(o, "mux_state", a->mux_state);
    cJSON_AddNumberToObject(o, "ptx_state", a->ptx_state);
    cJSON_AddStringToObject(o, "bond_interface_name", (char *)a->bond_interface_name);
    cJSON_AddNumberToObject(o, "actor_system_priority", a->actor_system_priority);
    cJSON_AddItemToObject(o, "actor_system", vl_api_mac_address_t_tojson(&a->actor_system));
    cJSON_AddNumberToObject(o, "actor_key", a->actor_key);
    cJSON_AddNumberToObject(o, "actor_port_priority", a->actor_port_priority);
    cJSON_AddNumberToObject(o, "actor_port_number", a->actor_port_number);
    cJSON_AddNumberToObject(o, "actor_state", a->actor_state);
    cJSON_AddNumberToObject(o, "partner_system_priority", a->partner_system_priority);
    cJSON_AddItemToObject(o, "partner_system", vl_api_mac_address_t_tojson(&a->partner_system));
    cJSON_AddNumberToObject(o, "partner_key", a->partner_key);
    cJSON_AddNumberToObject(o, "partner_port_priority", a->partner_port_priority);
    cJSON_AddNumberToObject(o, "partner_port_number", a->partner_port_number);
    cJSON_AddNumberToObject(o, "partner_state", a->partner_state);
    return o;
}
#endif
