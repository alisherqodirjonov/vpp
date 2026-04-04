/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_nsim_api_tojson_h
#define included_nsim_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nsim_cross_connect_enable_disable_t_tojson (vl_api_nsim_cross_connect_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_cross_connect_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "9c3ead86");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "sw_if_index0", a->sw_if_index0);
    cJSON_AddNumberToObject(o, "sw_if_index1", a->sw_if_index1);
    return o;
}
static inline cJSON *vl_api_nsim_cross_connect_enable_disable_reply_t_tojson (vl_api_nsim_cross_connect_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_cross_connect_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nsim_output_feature_enable_disable_t_tojson (vl_api_nsim_output_feature_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_output_feature_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "3865946c");
    cJSON_AddBoolToObject(o, "enable_disable", a->enable_disable);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_nsim_output_feature_enable_disable_reply_t_tojson (vl_api_nsim_output_feature_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_output_feature_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nsim_configure_t_tojson (vl_api_nsim_configure_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_configure");
    cJSON_AddStringToObject(o, "_crc", "16ed400f");
    cJSON_AddNumberToObject(o, "delay_in_usec", a->delay_in_usec);
    cJSON_AddNumberToObject(o, "average_packet_size", a->average_packet_size);
    cJSON_AddNumberToObject(o, "bandwidth_in_bits_per_second", a->bandwidth_in_bits_per_second);
    cJSON_AddNumberToObject(o, "packets_per_drop", a->packets_per_drop);
    return o;
}
static inline cJSON *vl_api_nsim_configure_reply_t_tojson (vl_api_nsim_configure_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_configure_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_nsim_configure2_t_tojson (vl_api_nsim_configure2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_configure2");
    cJSON_AddStringToObject(o, "_crc", "64de8ed3");
    cJSON_AddNumberToObject(o, "delay_in_usec", a->delay_in_usec);
    cJSON_AddNumberToObject(o, "average_packet_size", a->average_packet_size);
    cJSON_AddNumberToObject(o, "bandwidth_in_bits_per_second", a->bandwidth_in_bits_per_second);
    cJSON_AddNumberToObject(o, "packets_per_drop", a->packets_per_drop);
    cJSON_AddNumberToObject(o, "packets_per_reorder", a->packets_per_reorder);
    return o;
}
static inline cJSON *vl_api_nsim_configure2_reply_t_tojson (vl_api_nsim_configure2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "nsim_configure2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
