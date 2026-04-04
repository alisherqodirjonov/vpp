/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_stn_api_tojson_h
#define included_stn_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_stn_add_del_rule_t_tojson (vl_api_stn_add_del_rule_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "stn_add_del_rule");
    cJSON_AddStringToObject(o, "_crc", "224c6edd");
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_stn_add_del_rule_reply_t_tojson (vl_api_stn_add_del_rule_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "stn_add_del_rule_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_stn_rules_dump_t_tojson (vl_api_stn_rules_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "stn_rules_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_stn_rules_details_t_tojson (vl_api_stn_rules_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "stn_rules_details");
    cJSON_AddStringToObject(o, "_crc", "a51935a6");
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
#endif
