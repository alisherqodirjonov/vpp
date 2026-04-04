/* Imported API files */
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_lacp_api_fromjson_h
#define included_lacp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_sw_interface_lacp_dump_t *vl_api_sw_interface_lacp_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_lacp_dump_t);
    vl_api_sw_interface_lacp_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_sw_interface_lacp_details_t *vl_api_sw_interface_lacp_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_lacp_details_t);
    vl_api_sw_interface_lacp_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->interface_name, sizeof(a->interface_name), cJSON_GetStringValue(item), sizeof(a->interface_name) - 1);

    item = cJSON_GetObjectItem(o, "rx_state");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rx_state);

    item = cJSON_GetObjectItem(o, "tx_state");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_state);

    item = cJSON_GetObjectItem(o, "mux_state");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->mux_state);

    item = cJSON_GetObjectItem(o, "ptx_state");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ptx_state);

    item = cJSON_GetObjectItem(o, "bond_interface_name");
    if (!item) goto error;
    strncpy_s((char *)a->bond_interface_name, sizeof(a->bond_interface_name), cJSON_GetStringValue(item), sizeof(a->bond_interface_name) - 1);

    item = cJSON_GetObjectItem(o, "actor_system_priority");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->actor_system_priority);

    item = cJSON_GetObjectItem(o, "actor_system");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->actor_system) < 0) goto error;

    item = cJSON_GetObjectItem(o, "actor_key");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->actor_key);

    item = cJSON_GetObjectItem(o, "actor_port_priority");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->actor_port_priority);

    item = cJSON_GetObjectItem(o, "actor_port_number");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->actor_port_number);

    item = cJSON_GetObjectItem(o, "actor_state");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->actor_state);

    item = cJSON_GetObjectItem(o, "partner_system_priority");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->partner_system_priority);

    item = cJSON_GetObjectItem(o, "partner_system");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->partner_system) < 0) goto error;

    item = cJSON_GetObjectItem(o, "partner_key");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->partner_key);

    item = cJSON_GetObjectItem(o, "partner_port_priority");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->partner_port_priority);

    item = cJSON_GetObjectItem(o, "partner_port_number");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->partner_port_number);

    item = cJSON_GetObjectItem(o, "partner_state");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->partner_state);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
