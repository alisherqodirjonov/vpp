/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_pppoe_api_tojson_h
#define included_pppoe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pppoe_add_del_session_t_tojson (vl_api_pppoe_add_del_session_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pppoe_add_del_session");
    cJSON_AddStringToObject(o, "_crc", "f6fd759e");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "session_id", a->session_id);
    cJSON_AddItemToObject(o, "client_ip", vl_api_address_t_tojson(&a->client_ip));
    cJSON_AddNumberToObject(o, "decap_vrf_id", a->decap_vrf_id);
    cJSON_AddItemToObject(o, "client_mac", vl_api_mac_address_t_tojson(&a->client_mac));
    return o;
}
static inline cJSON *vl_api_pppoe_add_del_session_reply_t_tojson (vl_api_pppoe_add_del_session_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pppoe_add_del_session_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pppoe_session_dump_t_tojson (vl_api_pppoe_session_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pppoe_session_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pppoe_session_details_t_tojson (vl_api_pppoe_session_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pppoe_session_details");
    cJSON_AddStringToObject(o, "_crc", "4b8e8a4a");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "session_id", a->session_id);
    cJSON_AddItemToObject(o, "client_ip", vl_api_address_t_tojson(&a->client_ip));
    cJSON_AddNumberToObject(o, "encap_if_index", a->encap_if_index);
    cJSON_AddNumberToObject(o, "decap_vrf_id", a->decap_vrf_id);
    cJSON_AddItemToObject(o, "local_mac", vl_api_mac_address_t_tojson(&a->local_mac));
    cJSON_AddItemToObject(o, "client_mac", vl_api_mac_address_t_tojson(&a->client_mac));
    return o;
}
static inline cJSON *vl_api_pppoe_add_del_cp_t_tojson (vl_api_pppoe_add_del_cp_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pppoe_add_del_cp");
    cJSON_AddStringToObject(o, "_crc", "eacd9aaa");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_pppoe_add_del_cp_reply_t_tojson (vl_api_pppoe_add_del_cp_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pppoe_add_del_cp_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
