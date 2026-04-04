/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_dslite_api_tojson_h
#define included_dslite_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_dslite_add_del_pool_addr_range_t_tojson (vl_api_dslite_add_del_pool_addr_range_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_add_del_pool_addr_range");
    cJSON_AddStringToObject(o, "_crc", "de2a5b02");
    cJSON_AddItemToObject(o, "start_addr", vl_api_ip4_address_t_tojson(&a->start_addr));
    cJSON_AddItemToObject(o, "end_addr", vl_api_ip4_address_t_tojson(&a->end_addr));
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_dslite_add_del_pool_addr_range_reply_t_tojson (vl_api_dslite_add_del_pool_addr_range_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_add_del_pool_addr_range_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dslite_address_dump_t_tojson (vl_api_dslite_address_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_address_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_dslite_address_details_t_tojson (vl_api_dslite_address_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_address_details");
    cJSON_AddStringToObject(o, "_crc", "ec26d648");
    cJSON_AddItemToObject(o, "ip_address", vl_api_ip4_address_t_tojson(&a->ip_address));
    return o;
}
static inline cJSON *vl_api_dslite_set_aftr_addr_t_tojson (vl_api_dslite_set_aftr_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_set_aftr_addr");
    cJSON_AddStringToObject(o, "_crc", "78b50fdf");
    cJSON_AddItemToObject(o, "ip4_addr", vl_api_ip4_address_t_tojson(&a->ip4_addr));
    cJSON_AddItemToObject(o, "ip6_addr", vl_api_ip6_address_t_tojson(&a->ip6_addr));
    return o;
}
static inline cJSON *vl_api_dslite_set_aftr_addr_reply_t_tojson (vl_api_dslite_set_aftr_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_set_aftr_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dslite_get_aftr_addr_t_tojson (vl_api_dslite_get_aftr_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_get_aftr_addr");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_dslite_get_aftr_addr_reply_t_tojson (vl_api_dslite_get_aftr_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_get_aftr_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "8e23608e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "ip4_addr", vl_api_ip4_address_t_tojson(&a->ip4_addr));
    cJSON_AddItemToObject(o, "ip6_addr", vl_api_ip6_address_t_tojson(&a->ip6_addr));
    return o;
}
static inline cJSON *vl_api_dslite_set_b4_addr_t_tojson (vl_api_dslite_set_b4_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_set_b4_addr");
    cJSON_AddStringToObject(o, "_crc", "78b50fdf");
    cJSON_AddItemToObject(o, "ip4_addr", vl_api_ip4_address_t_tojson(&a->ip4_addr));
    cJSON_AddItemToObject(o, "ip6_addr", vl_api_ip6_address_t_tojson(&a->ip6_addr));
    return o;
}
static inline cJSON *vl_api_dslite_set_b4_addr_reply_t_tojson (vl_api_dslite_set_b4_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_set_b4_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dslite_get_b4_addr_t_tojson (vl_api_dslite_get_b4_addr_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_get_b4_addr");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_dslite_get_b4_addr_reply_t_tojson (vl_api_dslite_get_b4_addr_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dslite_get_b4_addr_reply");
    cJSON_AddStringToObject(o, "_crc", "8e23608e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "ip4_addr", vl_api_ip4_address_t_tojson(&a->ip4_addr));
    cJSON_AddItemToObject(o, "ip6_addr", vl_api_ip6_address_t_tojson(&a->ip6_addr));
    return o;
}
#endif
