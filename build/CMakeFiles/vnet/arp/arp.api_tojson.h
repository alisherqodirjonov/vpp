/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_arp_api_tojson_h
#define included_arp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_proxy_arp_t_tojson (vl_api_proxy_arp_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "low", vl_api_ip4_address_t_tojson(&a->low));
    cJSON_AddItemToObject(o, "hi", vl_api_ip4_address_t_tojson(&a->hi));
    return o;
}
static inline cJSON *vl_api_proxy_arp_add_del_t_tojson (vl_api_proxy_arp_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_add_del");
    cJSON_AddStringToObject(o, "_crc", "1823c3e7");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "proxy", vl_api_proxy_arp_t_tojson(&a->proxy));
    return o;
}
static inline cJSON *vl_api_proxy_arp_add_del_reply_t_tojson (vl_api_proxy_arp_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_proxy_arp_dump_t_tojson (vl_api_proxy_arp_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_proxy_arp_details_t_tojson (vl_api_proxy_arp_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_details");
    cJSON_AddStringToObject(o, "_crc", "5b948673");
    cJSON_AddItemToObject(o, "proxy", vl_api_proxy_arp_t_tojson(&a->proxy));
    return o;
}
static inline cJSON *vl_api_proxy_arp_intfc_enable_disable_t_tojson (vl_api_proxy_arp_intfc_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_intfc_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_proxy_arp_intfc_enable_disable_reply_t_tojson (vl_api_proxy_arp_intfc_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_intfc_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_proxy_arp_intfc_dump_t_tojson (vl_api_proxy_arp_intfc_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_intfc_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_proxy_arp_intfc_details_t_tojson (vl_api_proxy_arp_intfc_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "proxy_arp_intfc_details");
    cJSON_AddStringToObject(o, "_crc", "f6458e5f");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
#endif
