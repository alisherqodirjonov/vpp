/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_udp_api_tojson_h
#define included_udp_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_udp_encap_t_tojson (vl_api_udp_encap_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "src_port", a->src_port);
    cJSON_AddNumberToObject(o, "dst_port", a->dst_port);
    cJSON_AddItemToObject(o, "src_ip", vl_api_address_t_tojson(&a->src_ip));
    cJSON_AddItemToObject(o, "dst_ip", vl_api_address_t_tojson(&a->dst_ip));
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_udp_decap_next_proto_t_tojson (vl_api_udp_decap_next_proto_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("UDP_API_DECAP_PROTO_IP4");
    case 1:
        return cJSON_CreateString("UDP_API_DECAP_PROTO_IP6");
    case 2:
        return cJSON_CreateString("UDP_API_DECAP_PROTO_MPLS");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_udp_decap_t_tojson (vl_api_udp_decap_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "is_ip4", a->is_ip4);
    cJSON_AddNumberToObject(o, "port", a->port);
    cJSON_AddItemToObject(o, "next_proto", vl_api_udp_decap_next_proto_t_tojson(a->next_proto));
    return o;
}
static inline cJSON *vl_api_udp_encap_add_t_tojson (vl_api_udp_encap_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_encap_add");
    cJSON_AddStringToObject(o, "_crc", "f74a60b1");
    cJSON_AddItemToObject(o, "udp_encap", vl_api_udp_encap_t_tojson(&a->udp_encap));
    return o;
}
static inline cJSON *vl_api_udp_encap_add_reply_t_tojson (vl_api_udp_encap_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_encap_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e2fc8294");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_udp_encap_del_t_tojson (vl_api_udp_encap_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_encap_del");
    cJSON_AddStringToObject(o, "_crc", "3a91bde5");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_udp_encap_del_reply_t_tojson (vl_api_udp_encap_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_encap_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_udp_encap_dump_t_tojson (vl_api_udp_encap_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_encap_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_udp_encap_details_t_tojson (vl_api_udp_encap_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_encap_details");
    cJSON_AddStringToObject(o, "_crc", "8cfb9c76");
    cJSON_AddItemToObject(o, "udp_encap", vl_api_udp_encap_t_tojson(&a->udp_encap));
    return o;
}
static inline cJSON *vl_api_udp_decap_add_del_t_tojson (vl_api_udp_decap_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_decap_add_del");
    cJSON_AddStringToObject(o, "_crc", "d14a4f47");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "udp_decap", vl_api_udp_decap_t_tojson(&a->udp_decap));
    return o;
}
static inline cJSON *vl_api_udp_decap_add_del_reply_t_tojson (vl_api_udp_decap_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "udp_decap_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
