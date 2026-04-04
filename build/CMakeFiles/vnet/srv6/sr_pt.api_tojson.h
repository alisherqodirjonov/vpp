/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_sr_pt_api_tojson_h
#define included_sr_pt_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sr_pt_iface_dump_t_tojson (vl_api_sr_pt_iface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_pt_iface_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sr_pt_iface_details_t_tojson (vl_api_sr_pt_iface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_pt_iface_details");
    cJSON_AddStringToObject(o, "_crc", "1f472f85");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "ingress_load", a->ingress_load);
    cJSON_AddNumberToObject(o, "egress_load", a->egress_load);
    cJSON_AddNumberToObject(o, "tts_template", a->tts_template);
    return o;
}
static inline cJSON *vl_api_sr_pt_iface_add_t_tojson (vl_api_sr_pt_iface_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_pt_iface_add");
    cJSON_AddStringToObject(o, "_crc", "852c0cda");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "ingress_load", a->ingress_load);
    cJSON_AddNumberToObject(o, "egress_load", a->egress_load);
    cJSON_AddNumberToObject(o, "tts_template", a->tts_template);
    return o;
}
static inline cJSON *vl_api_sr_pt_iface_add_reply_t_tojson (vl_api_sr_pt_iface_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_pt_iface_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sr_pt_iface_del_t_tojson (vl_api_sr_pt_iface_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_pt_iface_del");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_sr_pt_iface_del_reply_t_tojson (vl_api_sr_pt_iface_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sr_pt_iface_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
