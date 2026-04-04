/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_udp_ping_api_tojson_h
#define included_udp_ping_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_udp_ping_add_del_t_tojson (vl_api_udp_ping_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_ping_add_del");
    cJSON_AddStringToObject(o, "_crc", "fa2628fc");
    cJSON_AddItemToObject(o, "src_ip_address", vl_api_address_t_tojson(&a->src_ip_address));
    cJSON_AddItemToObject(o, "dst_ip_address", vl_api_address_t_tojson(&a->dst_ip_address));
    cJSON_AddNumberToObject(o, "start_src_port", a->start_src_port);
    cJSON_AddNumberToObject(o, "end_src_port", a->end_src_port);
    cJSON_AddNumberToObject(o, "start_dst_port", a->start_dst_port);
    cJSON_AddNumberToObject(o, "end_dst_port", a->end_dst_port);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    cJSON_AddNumberToObject(o, "dis", a->dis);
    cJSON_AddNumberToObject(o, "fault_det", a->fault_det);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->reserve, 3);
    cJSON_AddStringToObject(o, "reserve", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_udp_ping_add_del_reply_t_tojson (vl_api_udp_ping_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_ping_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_udp_ping_export_t_tojson (vl_api_udp_ping_export_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_ping_export");
    cJSON_AddStringToObject(o, "_crc", "b3e225d2");
    cJSON_AddBoolToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_udp_ping_export_reply_t_tojson (vl_api_udp_ping_export_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_ping_export_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
