/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_p2p_ethernet_api_tojson_h
#define included_p2p_ethernet_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_p2p_ethernet_add_t_tojson (vl_api_p2p_ethernet_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "p2p_ethernet_add");
    cJSON_AddStringToObject(o, "_crc", "36a1a6dc");
    cJSON_AddNumberToObject(o, "parent_if_index", a->parent_if_index);
    cJSON_AddNumberToObject(o, "subif_id", a->subif_id);
    cJSON_AddItemToObject(o, "remote_mac", vl_api_mac_address_t_tojson(&a->remote_mac));
    return o;
}
static inline cJSON *vl_api_p2p_ethernet_add_reply_t_tojson (vl_api_p2p_ethernet_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "p2p_ethernet_add_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_p2p_ethernet_del_t_tojson (vl_api_p2p_ethernet_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "p2p_ethernet_del");
    cJSON_AddStringToObject(o, "_crc", "62f81c8c");
    cJSON_AddNumberToObject(o, "parent_if_index", a->parent_if_index);
    cJSON_AddItemToObject(o, "remote_mac", vl_api_mac_address_t_tojson(&a->remote_mac));
    return o;
}
static inline cJSON *vl_api_p2p_ethernet_del_reply_t_tojson (vl_api_p2p_ethernet_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "p2p_ethernet_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
