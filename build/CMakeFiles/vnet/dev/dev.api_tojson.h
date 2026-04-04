/* Imported API files */
#ifndef included_dev_api_tojson_h
#define included_dev_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_dev_flags_t_tojson (vl_api_dev_flags_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & VL_API_DEV_FLAG_NO_STATS)
       cJSON_AddItemToArray(array, cJSON_CreateString("VL_API_DEV_FLAG_NO_STATS"));
    return array;
}
static inline cJSON *vl_api_dev_port_flags_t_tojson (vl_api_dev_port_flags_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & VL_API_DEV_PORT_FLAG_INTERRUPT_MODE)
       cJSON_AddItemToArray(array, cJSON_CreateString("VL_API_DEV_PORT_FLAG_INTERRUPT_MODE"));
    if (a & VL_API_DEV_PORT_FLAG_CONSISTENT_QP)
       cJSON_AddItemToArray(array, cJSON_CreateString("VL_API_DEV_PORT_FLAG_CONSISTENT_QP"));
    return array;
}
static inline cJSON *vl_api_dev_attach_t_tojson (vl_api_dev_attach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_attach");
    cJSON_AddStringToObject(o, "_crc", "44b725fc");
    cJSON_AddStringToObject(o, "device_id", (char *)a->device_id);
    cJSON_AddStringToObject(o, "driver_name", (char *)a->driver_name);
    cJSON_AddItemToObject(o, "flags", vl_api_dev_flags_t_tojson(a->flags));
    vl_api_string_cJSON_AddToObject(o, "args", &a->args);
    return o;
}
static inline cJSON *vl_api_dev_attach_reply_t_tojson (vl_api_dev_attach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_attach_reply");
    cJSON_AddStringToObject(o, "_crc", "6082b181");
    cJSON_AddNumberToObject(o, "dev_index", a->dev_index);
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "error_string", &a->error_string);
    return o;
}
static inline cJSON *vl_api_dev_detach_t_tojson (vl_api_dev_detach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_detach");
    cJSON_AddStringToObject(o, "_crc", "afae52d6");
    cJSON_AddNumberToObject(o, "dev_index", a->dev_index);
    return o;
}
static inline cJSON *vl_api_dev_detach_reply_t_tojson (vl_api_dev_detach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_detach_reply");
    cJSON_AddStringToObject(o, "_crc", "c8d74455");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "error_string", &a->error_string);
    return o;
}
static inline cJSON *vl_api_dev_create_port_if_t_tojson (vl_api_dev_create_port_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_create_port_if");
    cJSON_AddStringToObject(o, "_crc", "dbdf06f3");
    cJSON_AddNumberToObject(o, "dev_index", a->dev_index);
    cJSON_AddStringToObject(o, "intf_name", (char *)a->intf_name);
    cJSON_AddNumberToObject(o, "num_rx_queues", a->num_rx_queues);
    cJSON_AddNumberToObject(o, "num_tx_queues", a->num_tx_queues);
    cJSON_AddNumberToObject(o, "rx_queue_size", a->rx_queue_size);
    cJSON_AddNumberToObject(o, "tx_queue_size", a->tx_queue_size);
    cJSON_AddNumberToObject(o, "port_id", a->port_id);
    cJSON_AddItemToObject(o, "flags", vl_api_dev_port_flags_t_tojson(a->flags));
    vl_api_string_cJSON_AddToObject(o, "args", &a->args);
    return o;
}
static inline cJSON *vl_api_dev_create_port_if_reply_t_tojson (vl_api_dev_create_port_if_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_create_port_if_reply");
    cJSON_AddStringToObject(o, "_crc", "243c2374");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "error_string", &a->error_string);
    return o;
}
static inline cJSON *vl_api_dev_remove_port_if_t_tojson (vl_api_dev_remove_port_if_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_remove_port_if");
    cJSON_AddStringToObject(o, "_crc", "529cb13f");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_dev_remove_port_if_reply_t_tojson (vl_api_dev_remove_port_if_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dev_remove_port_if_reply");
    cJSON_AddStringToObject(o, "_crc", "c8d74455");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "error_string", &a->error_string);
    return o;
}
#endif
