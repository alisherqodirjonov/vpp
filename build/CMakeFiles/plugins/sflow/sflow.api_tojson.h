/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_sflow_api_tojson_h
#define included_sflow_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sflow_enable_disable_t_tojson (vl_api_sflow_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "8499814f");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    return o;
}
static inline cJSON *vl_api_sflow_enable_disable_reply_t_tojson (vl_api_sflow_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sflow_sampling_rate_get_t_tojson (vl_api_sflow_sampling_rate_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_sampling_rate_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sflow_sampling_rate_get_reply_t_tojson (vl_api_sflow_sampling_rate_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_sampling_rate_get_reply");
    cJSON_AddStringToObject(o, "_crc", "9c8c8236");
    cJSON_AddNumberToObject(o, "sampling_N", a->sampling_N);
    return o;
}
static inline cJSON *vl_api_sflow_sampling_rate_set_t_tojson (vl_api_sflow_sampling_rate_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_sampling_rate_set");
    cJSON_AddStringToObject(o, "_crc", "94778f50");
    cJSON_AddNumberToObject(o, "sampling_N", a->sampling_N);
    return o;
}
static inline cJSON *vl_api_sflow_sampling_rate_set_reply_t_tojson (vl_api_sflow_sampling_rate_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_sampling_rate_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sflow_polling_interval_set_t_tojson (vl_api_sflow_polling_interval_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_polling_interval_set");
    cJSON_AddStringToObject(o, "_crc", "7f19cb51");
    cJSON_AddNumberToObject(o, "polling_S", a->polling_S);
    return o;
}
static inline cJSON *vl_api_sflow_polling_interval_set_reply_t_tojson (vl_api_sflow_polling_interval_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_polling_interval_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sflow_polling_interval_get_t_tojson (vl_api_sflow_polling_interval_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_polling_interval_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sflow_polling_interval_get_reply_t_tojson (vl_api_sflow_polling_interval_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_polling_interval_get_reply");
    cJSON_AddStringToObject(o, "_crc", "e929801c");
    cJSON_AddNumberToObject(o, "polling_S", a->polling_S);
    return o;
}
static inline cJSON *vl_api_sflow_header_bytes_set_t_tojson (vl_api_sflow_header_bytes_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_header_bytes_set");
    cJSON_AddStringToObject(o, "_crc", "5baf56f3");
    cJSON_AddNumberToObject(o, "header_B", a->header_B);
    return o;
}
static inline cJSON *vl_api_sflow_header_bytes_set_reply_t_tojson (vl_api_sflow_header_bytes_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_header_bytes_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sflow_header_bytes_get_t_tojson (vl_api_sflow_header_bytes_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_header_bytes_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sflow_header_bytes_get_reply_t_tojson (vl_api_sflow_header_bytes_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_header_bytes_get_reply");
    cJSON_AddStringToObject(o, "_crc", "624c95b9");
    cJSON_AddNumberToObject(o, "header_B", a->header_B);
    return o;
}
static inline cJSON *vl_api_sflow_direction_set_t_tojson (vl_api_sflow_direction_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_direction_set");
    cJSON_AddStringToObject(o, "_crc", "fbca6f34");
    cJSON_AddNumberToObject(o, "sampling_D", a->sampling_D);
    return o;
}
static inline cJSON *vl_api_sflow_direction_set_reply_t_tojson (vl_api_sflow_direction_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_direction_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sflow_direction_get_t_tojson (vl_api_sflow_direction_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_direction_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sflow_direction_get_reply_t_tojson (vl_api_sflow_direction_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_direction_get_reply");
    cJSON_AddStringToObject(o, "_crc", "f3316252");
    cJSON_AddNumberToObject(o, "sampling_D", a->sampling_D);
    return o;
}
static inline cJSON *vl_api_sflow_drop_monitoring_set_t_tojson (vl_api_sflow_drop_monitoring_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_drop_monitoring_set");
    cJSON_AddStringToObject(o, "_crc", "100b1e04");
    cJSON_AddNumberToObject(o, "drop_M", a->drop_M);
    return o;
}
static inline cJSON *vl_api_sflow_drop_monitoring_set_reply_t_tojson (vl_api_sflow_drop_monitoring_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_drop_monitoring_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_sflow_drop_monitoring_get_t_tojson (vl_api_sflow_drop_monitoring_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_drop_monitoring_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_sflow_drop_monitoring_get_reply_t_tojson (vl_api_sflow_drop_monitoring_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_drop_monitoring_get_reply");
    cJSON_AddStringToObject(o, "_crc", "b56ae30e");
    cJSON_AddNumberToObject(o, "drop_M", a->drop_M);
    return o;
}
static inline cJSON *vl_api_sflow_interface_dump_t_tojson (vl_api_sflow_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "451a727d");
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    return o;
}
static inline cJSON *vl_api_sflow_interface_details_t_tojson (vl_api_sflow_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sflow_interface_details");
    cJSON_AddStringToObject(o, "_crc", "b7b9143f");
    cJSON_AddNumberToObject(o, "hw_if_index", a->hw_if_index);
    return o;
}
#endif
