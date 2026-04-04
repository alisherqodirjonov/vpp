/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/srv6/sr_types.api_tojson.h>
#ifndef included_sr_mpls_api_tojson_h
#define included_sr_mpls_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sr_mpls_policy_add_t_tojson (vl_api_sr_mpls_policy_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_add");
    cJSON_AddStringToObject(o, "_crc", "a1a70c70");
    cJSON_AddNumberToObject(o, "bsid", a->bsid);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddBoolToObject(o, "is_spray", a->is_spray);
    cJSON_AddNumberToObject(o, "n_segments", a->n_segments);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "segments");
        for (i = 0; i < a->n_segments; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->segments[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_add_reply_t_tojson (vl_api_sr_mpls_policy_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_mod_t_tojson (vl_api_sr_mpls_policy_mod_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_mod");
    cJSON_AddStringToObject(o, "_crc", "88482c17");
    cJSON_AddNumberToObject(o, "bsid", a->bsid);
    cJSON_AddItemToObject(o, "operation", vl_api_sr_policy_op_t_tojson(a->operation));
    cJSON_AddNumberToObject(o, "sl_index", a->sl_index);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddNumberToObject(o, "n_segments", a->n_segments);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "segments");
        for (i = 0; i < a->n_segments; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->segments[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_mod_reply_t_tojson (vl_api_sr_mpls_policy_mod_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_mod_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_del_t_tojson (vl_api_sr_mpls_policy_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_del");
    cJSON_AddStringToObject(o, "_crc", "e29d34fa");
    cJSON_AddNumberToObject(o, "bsid", a->bsid);
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_del_reply_t_tojson (vl_api_sr_mpls_policy_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_mpls_steering_add_del_t_tojson (vl_api_sr_mpls_steering_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_steering_add_del");
    cJSON_AddStringToObject(o, "_crc", "64acff63");
    cJSON_AddBoolToObject(o, "is_del", a->is_del);
    cJSON_AddNumberToObject(o, "bsid", a->bsid);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddItemToObject(o, "prefix", vl_api_prefix_t_tojson(&a->prefix));
    cJSON_AddNumberToObject(o, "mask_width", a->mask_width);
    cJSON_AddItemToObject(o, "next_hop", vl_api_address_t_tojson(&a->next_hop));
    cJSON_AddNumberToObject(o, "color", a->color);
    cJSON_AddNumberToObject(o, "co_bits", a->co_bits);
    cJSON_AddNumberToObject(o, "vpn_label", a->vpn_label);
    return o;
}
static inline cJSON *vl_api_sr_mpls_steering_add_del_reply_t_tojson (vl_api_sr_mpls_steering_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_steering_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_assign_endpoint_color_t_tojson (vl_api_sr_mpls_policy_assign_endpoint_color_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_assign_endpoint_color");
    cJSON_AddStringToObject(o, "_crc", "0e7eb978");
    cJSON_AddNumberToObject(o, "bsid", a->bsid);
    cJSON_AddItemToObject(o, "endpoint", vl_api_address_t_tojson(&a->endpoint));
    cJSON_AddNumberToObject(o, "color", a->color);
    return o;
}
static inline cJSON *vl_api_sr_mpls_policy_assign_endpoint_color_reply_t_tojson (vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_mpls_policy_assign_endpoint_color_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
