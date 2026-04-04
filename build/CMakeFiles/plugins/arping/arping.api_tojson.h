/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_arping_api_tojson_h
#define included_arping_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_arping_t_tojson (vl_api_arping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "arping");
    cJSON_AddStringToObject(o, "_crc", "48817482");
    cJSON_AddItemToObject(o, "address", vl_api_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_garp", a->is_garp);
    cJSON_AddNumberToObject(o, "repeat", a->repeat);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    return o;
}
static inline cJSON *vl_api_arping_reply_t_tojson (vl_api_arping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "arping_reply");
    cJSON_AddStringToObject(o, "_crc", "bb9d1cbd");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "reply_count", a->reply_count);
    return o;
}
static inline cJSON *vl_api_arping_acd_t_tojson (vl_api_arping_acd_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "arping_acd");
    cJSON_AddStringToObject(o, "_crc", "48817482");
    cJSON_AddItemToObject(o, "address", vl_api_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_garp", a->is_garp);
    cJSON_AddNumberToObject(o, "repeat", a->repeat);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    return o;
}
static inline cJSON *vl_api_arping_acd_reply_t_tojson (vl_api_arping_acd_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "arping_acd_reply");
    cJSON_AddStringToObject(o, "_crc", "e08c3b05");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "reply_count", a->reply_count);
    cJSON_AddItemToObject(o, "mac_address", vl_api_mac_address_t_tojson(&a->mac_address));
    return o;
}
#endif
