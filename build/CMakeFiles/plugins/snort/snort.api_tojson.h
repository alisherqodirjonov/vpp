/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_snort_api_tojson_h
#define included_snort_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_snort_instance_create_t_tojson (vl_api_snort_instance_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_create");
    cJSON_AddStringToObject(o, "_crc", "248cc390");
    cJSON_AddNumberToObject(o, "queue_size", a->queue_size);
    cJSON_AddNumberToObject(o, "drop_on_disconnect", a->drop_on_disconnect);
    vl_api_string_cJSON_AddToObject(o, "name", &a->name);
    return o;
}
static inline cJSON *vl_api_snort_instance_create_reply_t_tojson (vl_api_snort_instance_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_create_reply");
    cJSON_AddStringToObject(o, "_crc", "e63a3fba");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    return o;
}
static inline cJSON *vl_api_snort_instance_delete_t_tojson (vl_api_snort_instance_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_delete");
    cJSON_AddStringToObject(o, "_crc", "6981211a");
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    return o;
}
static inline cJSON *vl_api_snort_instance_delete_reply_t_tojson (vl_api_snort_instance_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_snort_client_disconnect_t_tojson (vl_api_snort_client_disconnect_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_client_disconnect");
    cJSON_AddStringToObject(o, "_crc", "30a221a6");
    cJSON_AddNumberToObject(o, "snort_client_index", a->snort_client_index);
    return o;
}
static inline cJSON *vl_api_snort_client_disconnect_reply_t_tojson (vl_api_snort_client_disconnect_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_client_disconnect_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_snort_instance_disconnect_t_tojson (vl_api_snort_instance_disconnect_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_disconnect");
    cJSON_AddStringToObject(o, "_crc", "6981211a");
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    return o;
}
static inline cJSON *vl_api_snort_instance_disconnect_reply_t_tojson (vl_api_snort_instance_disconnect_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_disconnect_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_snort_interface_attach_t_tojson (vl_api_snort_interface_attach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_attach");
    cJSON_AddStringToObject(o, "_crc", "79ceda89");
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "snort_dir", a->snort_dir);
    return o;
}
static inline cJSON *vl_api_snort_interface_attach_reply_t_tojson (vl_api_snort_interface_attach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_attach_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_snort_interface_detach_t_tojson (vl_api_snort_interface_detach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_detach");
    cJSON_AddStringToObject(o, "_crc", "529cb13f");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_snort_interface_detach_reply_t_tojson (vl_api_snort_interface_detach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_detach_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_snort_input_mode_get_t_tojson (vl_api_snort_input_mode_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_input_mode_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_snort_input_mode_get_reply_t_tojson (vl_api_snort_input_mode_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_input_mode_get_reply");
    cJSON_AddStringToObject(o, "_crc", "a18796bf");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "snort_mode", a->snort_mode);
    return o;
}
static inline cJSON *vl_api_snort_input_mode_set_t_tojson (vl_api_snort_input_mode_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_input_mode_set");
    cJSON_AddStringToObject(o, "_crc", "d595d008");
    cJSON_AddNumberToObject(o, "input_mode", a->input_mode);
    return o;
}
static inline cJSON *vl_api_snort_input_mode_set_reply_t_tojson (vl_api_snort_input_mode_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_input_mode_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_snort_instance_get_t_tojson (vl_api_snort_instance_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_get");
    cJSON_AddStringToObject(o, "_crc", "07c37475");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    return o;
}
static inline cJSON *vl_api_snort_instance_get_reply_t_tojson (vl_api_snort_instance_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_snort_instance_details_t_tojson (vl_api_snort_instance_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_instance_details");
    cJSON_AddStringToObject(o, "_crc", "abb60d49");
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    cJSON_AddNumberToObject(o, "shm_size", a->shm_size);
    cJSON_AddNumberToObject(o, "shm_fd", a->shm_fd);
    cJSON_AddNumberToObject(o, "drop_on_disconnect", a->drop_on_disconnect);
    cJSON_AddNumberToObject(o, "snort_client_index", a->snort_client_index);
    vl_api_string_cJSON_AddToObject(o, "name", &a->name);
    return o;
}
static inline cJSON *vl_api_snort_interface_get_t_tojson (vl_api_snort_interface_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_get");
    cJSON_AddStringToObject(o, "_crc", "765a2424");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_snort_interface_get_reply_t_tojson (vl_api_snort_interface_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_snort_interface_details_t_tojson (vl_api_snort_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_interface_details");
    cJSON_AddStringToObject(o, "_crc", "52c75990");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    return o;
}
static inline cJSON *vl_api_snort_client_get_t_tojson (vl_api_snort_client_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_client_get");
    cJSON_AddStringToObject(o, "_crc", "51d54b70");
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    cJSON_AddNumberToObject(o, "snort_client_index", a->snort_client_index);
    return o;
}
static inline cJSON *vl_api_snort_client_get_reply_t_tojson (vl_api_snort_client_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_client_get_reply");
    cJSON_AddStringToObject(o, "_crc", "53b48f5d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "cursor", a->cursor);
    return o;
}
static inline cJSON *vl_api_snort_client_details_t_tojson (vl_api_snort_client_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "snort_client_details");
    cJSON_AddStringToObject(o, "_crc", "7e29e6f5");
    cJSON_AddNumberToObject(o, "instance_index", a->instance_index);
    return o;
}
#endif
