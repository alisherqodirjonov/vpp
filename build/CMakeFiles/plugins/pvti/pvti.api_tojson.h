/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_pvti_api_tojson_h
#define included_pvti_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pvti_tunnel_t_tojson (vl_api_pvti_tunnel_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "local_ip", vl_api_address_t_tojson(&a->local_ip));
    cJSON_AddNumberToObject(o, "local_port", a->local_port);
    cJSON_AddItemToObject(o, "remote_ip", vl_api_address_t_tojson(&a->remote_ip));
    cJSON_AddBoolToObject(o, "peer_address_from_payload", a->peer_address_from_payload);
    cJSON_AddNumberToObject(o, "remote_port", a->remote_port);
    cJSON_AddNumberToObject(o, "underlay_mtu", a->underlay_mtu);
    cJSON_AddNumberToObject(o, "underlay_fib_index", a->underlay_fib_index);
    return o;
}
static inline cJSON *vl_api_pvti_interface_create_t_tojson (vl_api_pvti_interface_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pvti_interface_create");
    cJSON_AddStringToObject(o, "_crc", "a1e95595");
    cJSON_AddItemToObject(o, "interface", vl_api_pvti_tunnel_t_tojson(&a->interface));
    return o;
}
static inline cJSON *vl_api_pvti_interface_create_reply_t_tojson (vl_api_pvti_interface_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pvti_interface_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pvti_interface_delete_t_tojson (vl_api_pvti_interface_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pvti_interface_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pvti_interface_delete_reply_t_tojson (vl_api_pvti_interface_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pvti_interface_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pvti_interface_dump_t_tojson (vl_api_pvti_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pvti_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pvti_interface_details_t_tojson (vl_api_pvti_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pvti_interface_details");
    cJSON_AddStringToObject(o, "_crc", "a26072b7");
    cJSON_AddItemToObject(o, "interface", vl_api_pvti_tunnel_t_tojson(&a->interface));
    return o;
}
#endif
