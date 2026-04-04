/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/srv6/sr_types.api_tojson.h>
#include <vnet/srv6/sr.api_tojson.h>
#include <srv6-mobile/sr_mobile_types.api_tojson.h>
#ifndef included_sr_mobile_api_tojson_h
#define included_sr_mobile_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sr_mobile_localsid_add_del_t_tojson (vl_api_sr_mobile_localsid_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mobile_localsid_add_del");
    cJSON_AddStringToObject(o, "_crc", "b85a7ed7");
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    cJSON_AddItemToObject(o, "localsid_prefix", vl_api_ip6_prefix_t_tojson(&a->localsid_prefix));
    cJSON_AddStringToObject(o, "behavior", (char *)a->behavior);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "local_fib_table", a->local_fib_table);
    cJSON_AddBoolToObject(o, "drop_in", a->drop_in);
    cJSON_AddItemToObject(o, "nhtype", vl_api_sr_mobile_nhtype_t_tojson(a->nhtype));
    cJSON_AddItemToObject(o, "sr_prefix", vl_api_ip6_prefix_t_tojson(&a->sr_prefix));
    cJSON_AddItemToObject(o, "v4src_addr", vl_api_ip4_address_t_tojson(&a->v4src_addr));
    cJSON_AddNumberToObject(o, "v4src_position", a->v4src_position);
    return o;
}
static inline cJSON *vl_api_sr_mobile_localsid_add_del_reply_t_tojson (vl_api_sr_mobile_localsid_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mobile_localsid_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_mobile_policy_add_t_tojson (vl_api_sr_mobile_policy_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mobile_policy_add");
    cJSON_AddStringToObject(o, "_crc", "8f051658");
    cJSON_AddItemToObject(o, "bsid_addr", vl_api_ip6_address_t_tojson(&a->bsid_addr));
    cJSON_AddItemToObject(o, "sr_prefix", vl_api_ip6_prefix_t_tojson(&a->sr_prefix));
    cJSON_AddItemToObject(o, "v6src_prefix", vl_api_ip6_prefix_t_tojson(&a->v6src_prefix));
    cJSON_AddStringToObject(o, "behavior", (char *)a->behavior);
    cJSON_AddNumberToObject(o, "fib_table", a->fib_table);
    cJSON_AddNumberToObject(o, "local_fib_table", a->local_fib_table);
    cJSON_AddItemToObject(o, "encap_src", vl_api_ip6_address_t_tojson(&a->encap_src));
    cJSON_AddBoolToObject(o, "drop_in", a->drop_in);
    cJSON_AddItemToObject(o, "nhtype", vl_api_sr_mobile_nhtype_t_tojson(a->nhtype));
    return o;
}
static inline cJSON *vl_api_sr_mobile_policy_add_reply_t_tojson (vl_api_sr_mobile_policy_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mobile_policy_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
