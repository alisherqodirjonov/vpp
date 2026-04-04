/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_tcp_api_tojson_h
#define included_tcp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_tcp_configure_src_addresses_t_tojson (vl_api_tcp_configure_src_addresses_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tcp_configure_src_addresses");
    cJSON_AddStringToObject(o, "_crc", "67eede0d");
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddItemToObject(o, "first_address", vl_api_address_t_tojson(&a->first_address));
    cJSON_AddItemToObject(o, "last_address", vl_api_address_t_tojson(&a->last_address));
    return o;
}
static inline cJSON *vl_api_tcp_configure_src_addresses_reply_t_tojson (vl_api_tcp_configure_src_addresses_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tcp_configure_src_addresses_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
