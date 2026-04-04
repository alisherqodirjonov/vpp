/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_npt66_api_tojson_h
#define included_npt66_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_npt66_binding_add_del_t_tojson (vl_api_npt66_binding_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "npt66_binding_add_del");
    cJSON_AddStringToObject(o, "_crc", "8aa10a52");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "internal", vl_api_ip6_prefix_t_tojson(&a->internal));
    cJSON_AddItemToObject(o, "external", vl_api_ip6_prefix_t_tojson(&a->external));
    return o;
}
static inline cJSON *vl_api_npt66_binding_add_del_reply_t_tojson (vl_api_npt66_binding_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "npt66_binding_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
