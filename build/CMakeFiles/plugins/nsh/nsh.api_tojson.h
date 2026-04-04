/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_nsh_api_tojson_h
#define included_nsh_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nsh_add_del_entry_t_tojson (vl_api_nsh_add_del_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_add_del_entry");
    cJSON_AddStringToObject(o, "_crc", "7dea480b");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "nsp_nsi", a->nsp_nsi);
    cJSON_AddNumberToObject(o, "md_type", a->md_type);
    cJSON_AddNumberToObject(o, "ver_o_c", a->ver_o_c);
    cJSON_AddNumberToObject(o, "ttl", a->ttl);
    cJSON_AddNumberToObject(o, "length", a->length);
    cJSON_AddNumberToObject(o, "next_protocol", a->next_protocol);
    cJSON_AddNumberToObject(o, "c1", a->c1);
    cJSON_AddNumberToObject(o, "c2", a->c2);
    cJSON_AddNumberToObject(o, "c3", a->c3);
    cJSON_AddNumberToObject(o, "c4", a->c4);
    cJSON_AddNumberToObject(o, "tlv_length", a->tlv_length);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->tlv, 248);
    cJSON_AddStringToObject(o, "tlv", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_nsh_add_del_entry_reply_t_tojson (vl_api_nsh_add_del_entry_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_add_del_entry_reply");
    cJSON_AddStringToObject(o, "_crc", "6296a9eb");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "entry_index", a->entry_index);
    return o;
}
static inline cJSON *vl_api_nsh_entry_dump_t_tojson (vl_api_nsh_entry_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_entry_dump");
    cJSON_AddStringToObject(o, "_crc", "cdaf8ccb");
    cJSON_AddNumberToObject(o, "entry_index", a->entry_index);
    return o;
}
static inline cJSON *vl_api_nsh_entry_details_t_tojson (vl_api_nsh_entry_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_entry_details");
    cJSON_AddStringToObject(o, "_crc", "046fb556");
    cJSON_AddNumberToObject(o, "entry_index", a->entry_index);
    cJSON_AddNumberToObject(o, "nsp_nsi", a->nsp_nsi);
    cJSON_AddNumberToObject(o, "md_type", a->md_type);
    cJSON_AddNumberToObject(o, "ver_o_c", a->ver_o_c);
    cJSON_AddNumberToObject(o, "ttl", a->ttl);
    cJSON_AddNumberToObject(o, "length", a->length);
    cJSON_AddNumberToObject(o, "next_protocol", a->next_protocol);
    cJSON_AddNumberToObject(o, "c1", a->c1);
    cJSON_AddNumberToObject(o, "c2", a->c2);
    cJSON_AddNumberToObject(o, "c3", a->c3);
    cJSON_AddNumberToObject(o, "c4", a->c4);
    cJSON_AddNumberToObject(o, "tlv_length", a->tlv_length);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->tlv, 248);
    cJSON_AddStringToObject(o, "tlv", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_nsh_add_del_map_t_tojson (vl_api_nsh_add_del_map_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_add_del_map");
    cJSON_AddStringToObject(o, "_crc", "0a0f42b0");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "nsp_nsi", a->nsp_nsi);
    cJSON_AddNumberToObject(o, "mapped_nsp_nsi", a->mapped_nsp_nsi);
    cJSON_AddNumberToObject(o, "nsh_action", a->nsh_action);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "next_node", a->next_node);
    return o;
}
static inline cJSON *vl_api_nsh_add_del_map_reply_t_tojson (vl_api_nsh_add_del_map_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_add_del_map_reply");
    cJSON_AddStringToObject(o, "_crc", "b2b127ef");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "map_index", a->map_index);
    return o;
}
static inline cJSON *vl_api_nsh_map_dump_t_tojson (vl_api_nsh_map_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_map_dump");
    cJSON_AddStringToObject(o, "_crc", "8fc06b82");
    cJSON_AddNumberToObject(o, "map_index", a->map_index);
    return o;
}
static inline cJSON *vl_api_nsh_map_details_t_tojson (vl_api_nsh_map_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsh_map_details");
    cJSON_AddStringToObject(o, "_crc", "2fefcf49");
    cJSON_AddNumberToObject(o, "map_index", a->map_index);
    cJSON_AddNumberToObject(o, "nsp_nsi", a->nsp_nsi);
    cJSON_AddNumberToObject(o, "mapped_nsp_nsi", a->mapped_nsp_nsi);
    cJSON_AddNumberToObject(o, "nsh_action", a->nsh_action);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "rx_sw_if_index", a->rx_sw_if_index);
    cJSON_AddNumberToObject(o, "next_node", a->next_node);
    return o;
}
#endif
