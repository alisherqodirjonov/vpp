/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_pnat_api_tojson_h
#define included_pnat_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pnat_mask_t_tojson (vl_api_pnat_mask_t a) {
    switch(a) {
    case 1:
        return cJSON_CreateString("PNAT_SA");
    case 2:
        return cJSON_CreateString("PNAT_DA");
    case 4:
        return cJSON_CreateString("PNAT_SPORT");
    case 8:
        return cJSON_CreateString("PNAT_DPORT");
    case 16:
        return cJSON_CreateString("PNAT_COPY_BYTE");
    case 32:
        return cJSON_CreateString("PNAT_CLEAR_BYTE");
    case 64:
        return cJSON_CreateString("PNAT_PROTO");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_pnat_attachment_point_t_tojson (vl_api_pnat_attachment_point_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("PNAT_IP4_INPUT");
    case 1:
        return cJSON_CreateString("PNAT_IP4_OUTPUT");
    case 2:
        return cJSON_CreateString("PNAT_ATTACHMENT_POINT_MAX");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_pnat_match_tuple_t_tojson (vl_api_pnat_match_tuple_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "src", vl_api_ip4_address_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_ip4_address_t_tojson(&a->dst));
    cJSON_AddItemToObject(o, "proto", vl_api_ip_proto_t_tojson(a->proto));
    cJSON_AddNumberToObject(o, "sport", a->sport);
    cJSON_AddNumberToObject(o, "dport", a->dport);
    cJSON_AddItemToObject(o, "mask", vl_api_pnat_mask_t_tojson(a->mask));
    return o;
}
static inline cJSON *vl_api_pnat_rewrite_tuple_t_tojson (vl_api_pnat_rewrite_tuple_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "src", vl_api_ip4_address_t_tojson(&a->src));
    cJSON_AddItemToObject(o, "dst", vl_api_ip4_address_t_tojson(&a->dst));
    cJSON_AddNumberToObject(o, "sport", a->sport);
    cJSON_AddNumberToObject(o, "dport", a->dport);
    cJSON_AddItemToObject(o, "mask", vl_api_pnat_mask_t_tojson(a->mask));
    cJSON_AddNumberToObject(o, "from_offset", a->from_offset);
    cJSON_AddNumberToObject(o, "to_offset", a->to_offset);
    cJSON_AddNumberToObject(o, "clear_offset", a->clear_offset);
    return o;
}
static inline cJSON *vl_api_pnat_binding_add_t_tojson (vl_api_pnat_binding_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_add");
    cJSON_AddStringToObject(o, "_crc", "946ee0b7");
    cJSON_AddItemToObject(o, "match", vl_api_pnat_match_tuple_t_tojson(&a->match));
    cJSON_AddItemToObject(o, "rewrite", vl_api_pnat_rewrite_tuple_t_tojson(&a->rewrite));
    return o;
}
static inline cJSON *vl_api_pnat_binding_add_reply_t_tojson (vl_api_pnat_binding_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_add_reply");
    cJSON_AddStringToObject(o, "_crc", "4cd980a7");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "binding_index", a->binding_index);
    return o;
}
static inline cJSON *vl_api_pnat_binding_add_v2_t_tojson (vl_api_pnat_binding_add_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_add_v2");
    cJSON_AddStringToObject(o, "_crc", "946ee0b7");
    cJSON_AddItemToObject(o, "match", vl_api_pnat_match_tuple_t_tojson(&a->match));
    cJSON_AddItemToObject(o, "rewrite", vl_api_pnat_rewrite_tuple_t_tojson(&a->rewrite));
    return o;
}
static inline cJSON *vl_api_pnat_binding_add_v2_reply_t_tojson (vl_api_pnat_binding_add_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_add_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "4cd980a7");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "binding_index", a->binding_index);
    return o;
}
static inline cJSON *vl_api_pnat_binding_del_t_tojson (vl_api_pnat_binding_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_del");
    cJSON_AddStringToObject(o, "_crc", "9259df7b");
    cJSON_AddNumberToObject(o, "binding_index", a->binding_index);
    return o;
}
static inline cJSON *vl_api_pnat_binding_del_reply_t_tojson (vl_api_pnat_binding_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pnat_binding_attach_t_tojson (vl_api_pnat_binding_attach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_attach");
    cJSON_AddStringToObject(o, "_crc", "6e074232");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "attachment", vl_api_pnat_attachment_point_t_tojson(a->attachment));
    cJSON_AddNumberToObject(o, "binding_index", a->binding_index);
    return o;
}
static inline cJSON *vl_api_pnat_binding_attach_reply_t_tojson (vl_api_pnat_binding_attach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_attach_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pnat_binding_detach_t_tojson (vl_api_pnat_binding_detach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_detach");
    cJSON_AddStringToObject(o, "_crc", "6e074232");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "attachment", vl_api_pnat_attachment_point_t_tojson(a->attachment));
    cJSON_AddNumberToObject(o, "binding_index", a->binding_index);
    return o;
}
static inline cJSON *vl_api_pnat_binding_detach_reply_t_tojson (vl_api_pnat_binding_detach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_binding_detach_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pnat_bindings_get_t_tojson (vl_api_pnat_bindings_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_bindings_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_pnat_bindings_get_reply_t_tojson (vl_api_pnat_bindings_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_bindings_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_pnat_bindings_details_t_tojson (vl_api_pnat_bindings_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_bindings_details");
    cJSON_AddStringToObject(o, "_crc", "08fb2815");
    cJSON_AddItemToObject(o, "match", vl_api_pnat_match_tuple_t_tojson(&a->match));
    cJSON_AddItemToObject(o, "rewrite", vl_api_pnat_rewrite_tuple_t_tojson(&a->rewrite));
    return o;
}
static inline cJSON *vl_api_pnat_interfaces_get_t_tojson (vl_api_pnat_interfaces_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_interfaces_get");
    cJSON_AddStringToObject(o, "_crc", "f75ba505");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_pnat_interfaces_get_reply_t_tojson (vl_api_pnat_interfaces_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_interfaces_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_pnat_interfaces_details_t_tojson (vl_api_pnat_interfaces_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_interfaces_details");
    cJSON_AddStringToObject(o, "_crc", "4cb09493");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "enabled");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateBool(a->enabled[i]));
        }
    }
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "lookup_mask");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, vl_api_pnat_mask_t_tojson(a->lookup_mask[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_pnat_flow_lookup_t_tojson (vl_api_pnat_flow_lookup_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_flow_lookup");
    cJSON_AddStringToObject(o, "_crc", "1ef8747c");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "attachment", vl_api_pnat_attachment_point_t_tojson(a->attachment));
    cJSON_AddItemToObject(o, "match", vl_api_pnat_match_tuple_t_tojson(&a->match));
    return o;
}
static inline cJSON *vl_api_pnat_flow_lookup_reply_t_tojson (vl_api_pnat_flow_lookup_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pnat_flow_lookup_reply");
    cJSON_AddStringToObject(o, "_crc", "4cd980a7");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "binding_index", a->binding_index);
    return o;
}
#endif
