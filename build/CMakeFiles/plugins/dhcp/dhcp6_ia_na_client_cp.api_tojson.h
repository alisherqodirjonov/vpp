/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_dhcp6_ia_na_client_cp_api_tojson_h
#define included_dhcp6_ia_na_client_cp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_dhcp6_client_enable_disable_t_tojson (vl_api_dhcp6_client_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_client_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "ae6cfcfb");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_dhcp6_client_enable_disable_reply_t_tojson (vl_api_dhcp6_client_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dhcp6_client_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
