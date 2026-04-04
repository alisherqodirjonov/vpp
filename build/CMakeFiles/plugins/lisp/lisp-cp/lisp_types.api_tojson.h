/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_lisp_types_api_tojson_h
#define included_lisp_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_local_locator_t_tojson (vl_api_local_locator_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    return o;
}
static inline cJSON *vl_api_remote_locator_t_tojson (vl_api_remote_locator_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddItemToObject(o, "ip_address", vl_api_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_eid_type_t_tojson (vl_api_eid_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("EID_TYPE_API_PREFIX");
    case 1:
        return cJSON_CreateString("EID_TYPE_API_MAC");
    case 2:
        return cJSON_CreateString("EID_TYPE_API_NSH");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_nsh_t_tojson (vl_api_nsh_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "spi", a->spi);
    cJSON_AddNumberToObject(o, "si", a->si);
    return o;
}
static inline cJSON *vl_api_eid_address_t_tojson (vl_api_eid_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddItemToObject(o, "mac", vl_api_mac_address_t_tojson(&a->mac));
    cJSON_AddItemToObject(o, "nsh", vl_api_nsh_t_tojson(&a->nsh));
    return o;
}
static inline cJSON *vl_api_eid_t_tojson (vl_api_eid_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_eid_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "address", vl_api_eid_address_t_tojson(&a->address));
    return o;
}
static inline cJSON *vl_api_hmac_key_id_t_tojson (vl_api_hmac_key_id_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("KEY_ID_API_HMAC_NO_KEY");
    case 1:
        return cJSON_CreateString("KEY_ID_API_HMAC_SHA_1_96");
    case 2:
        return cJSON_CreateString("KEY_ID_API_HMAC_SHA_256_128");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_hmac_key_t_tojson (vl_api_hmac_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "id", vl_api_hmac_key_id_t_tojson(a->id));
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->key, 64);
    cJSON_AddStringToObject(o, "key", s);
    vec_free(s);
    }
    return o;
}
#endif
