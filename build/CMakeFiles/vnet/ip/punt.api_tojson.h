/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_punt_api_tojson_h
#define included_punt_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_punt_type_t_tojson (vl_api_punt_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("PUNT_API_TYPE_L4");
    case 1:
        return cJSON_CreateString("PUNT_API_TYPE_IP_PROTO");
    case 2:
        return cJSON_CreateString("PUNT_API_TYPE_EXCEPTION");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_punt_l4_t_tojson (vl_api_punt_l4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "port", a->port);
    return o;
}
static inline cJSON *vl_api_punt_ip_proto_t_tojson (vl_api_punt_ip_proto_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "af", vl_api_address_family_t_tojson(a->af));
    cJSON_AddItemToObject(o, "protocol", vl_api_ip_proto_t_tojson(a->protocol));
    return o;
}
static inline cJSON *vl_api_punt_exception_t_tojson (vl_api_punt_exception_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_punt_union_t_tojson (vl_api_punt_union_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "exception", vl_api_punt_exception_t_tojson(&a->exception));
    cJSON_AddItemToObject(o, "l4", vl_api_punt_l4_t_tojson(&a->l4));
    cJSON_AddItemToObject(o, "ip_proto", vl_api_punt_ip_proto_t_tojson(&a->ip_proto));
    return o;
}
static inline cJSON *vl_api_punt_t_tojson (vl_api_punt_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "type", vl_api_punt_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "punt", vl_api_punt_union_t_tojson(&a->punt));
    return o;
}
static inline cJSON *vl_api_punt_reason_t_tojson (vl_api_punt_reason_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "id", a->id);
    vl_api_string_cJSON_AddToObject(o, "name", &a->name);
    return o;
}
static inline cJSON *vl_api_set_punt_t_tojson (vl_api_set_punt_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_punt");
    cJSON_AddStringToObject(o, "_crc", "47d0e347");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "punt", vl_api_punt_t_tojson(&a->punt));
    return o;
}
static inline cJSON *vl_api_set_punt_reply_t_tojson (vl_api_set_punt_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "set_punt_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_punt_socket_register_t_tojson (vl_api_punt_socket_register_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_socket_register");
    cJSON_AddStringToObject(o, "_crc", "7875badb");
    cJSON_AddNumberToObject(o, "header_version", a->header_version);
    cJSON_AddItemToObject(o, "punt", vl_api_punt_t_tojson(&a->punt));
    cJSON_AddStringToObject(o, "pathname", (char *)a->pathname);
    return o;
}
static inline cJSON *vl_api_punt_socket_register_reply_t_tojson (vl_api_punt_socket_register_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_socket_register_reply");
    cJSON_AddStringToObject(o, "_crc", "bd30ae90");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddStringToObject(o, "pathname", (char *)a->pathname);
    return o;
}
static inline cJSON *vl_api_punt_socket_dump_t_tojson (vl_api_punt_socket_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_socket_dump");
    cJSON_AddStringToObject(o, "_crc", "916fb004");
    cJSON_AddItemToObject(o, "type", vl_api_punt_type_t_tojson(a->type));
    return o;
}
static inline cJSON *vl_api_punt_socket_details_t_tojson (vl_api_punt_socket_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_socket_details");
    cJSON_AddStringToObject(o, "_crc", "330466e4");
    cJSON_AddItemToObject(o, "punt", vl_api_punt_t_tojson(&a->punt));
    cJSON_AddStringToObject(o, "pathname", (char *)a->pathname);
    return o;
}
static inline cJSON *vl_api_punt_socket_deregister_t_tojson (vl_api_punt_socket_deregister_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_socket_deregister");
    cJSON_AddStringToObject(o, "_crc", "75afa766");
    cJSON_AddItemToObject(o, "punt", vl_api_punt_t_tojson(&a->punt));
    return o;
}
static inline cJSON *vl_api_punt_socket_deregister_reply_t_tojson (vl_api_punt_socket_deregister_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_socket_deregister_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_punt_reason_dump_t_tojson (vl_api_punt_reason_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_reason_dump");
    cJSON_AddStringToObject(o, "_crc", "5c0dd4fe");
    cJSON_AddItemToObject(o, "reason", vl_api_punt_reason_t_tojson(&a->reason));
    return o;
}
static inline cJSON *vl_api_punt_reason_details_t_tojson (vl_api_punt_reason_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "punt_reason_details");
    cJSON_AddStringToObject(o, "_crc", "2c9d4a40");
    cJSON_AddItemToObject(o, "reason", vl_api_punt_reason_t_tojson(&a->reason));
    return o;
}
#endif
