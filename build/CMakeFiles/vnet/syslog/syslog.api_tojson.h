/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_syslog_api_tojson_h
#define included_syslog_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_syslog_severity_t_tojson (vl_api_syslog_severity_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_EMERG");
    case 1:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_ALERT");
    case 2:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_CRIT");
    case 3:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_ERR");
    case 4:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_WARN");
    case 5:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_NOTICE");
    case 6:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_INFO");
    case 7:
        return cJSON_CreateString("SYSLOG_API_SEVERITY_DBG");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_syslog_set_sender_t_tojson (vl_api_syslog_set_sender_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_set_sender");
    cJSON_AddStringToObject(o, "_crc", "b8011d0b");
    cJSON_AddItemToObject(o, "src_address", vl_api_ip4_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "collector_address", vl_api_ip4_address_t_tojson(&a->collector_address));
    cJSON_AddNumberToObject(o, "collector_port", a->collector_port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "max_msg_size", a->max_msg_size);
    return o;
}
static inline cJSON *vl_api_syslog_set_sender_reply_t_tojson (vl_api_syslog_set_sender_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_set_sender_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_syslog_get_sender_t_tojson (vl_api_syslog_get_sender_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_get_sender");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_syslog_get_sender_reply_t_tojson (vl_api_syslog_get_sender_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_get_sender_reply");
    cJSON_AddStringToObject(o, "_crc", "424cfa4e");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "src_address", vl_api_ip4_address_t_tojson(&a->src_address));
    cJSON_AddItemToObject(o, "collector_address", vl_api_ip4_address_t_tojson(&a->collector_address));
    cJSON_AddNumberToObject(o, "collector_port", a->collector_port);
    cJSON_AddNumberToObject(o, "vrf_id", a->vrf_id);
    cJSON_AddNumberToObject(o, "max_msg_size", a->max_msg_size);
    return o;
}
static inline cJSON *vl_api_syslog_set_filter_t_tojson (vl_api_syslog_set_filter_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_set_filter");
    cJSON_AddStringToObject(o, "_crc", "571348c3");
    cJSON_AddItemToObject(o, "severity", vl_api_syslog_severity_t_tojson(a->severity));
    return o;
}
static inline cJSON *vl_api_syslog_set_filter_reply_t_tojson (vl_api_syslog_set_filter_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_set_filter_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_syslog_get_filter_t_tojson (vl_api_syslog_get_filter_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_get_filter");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_syslog_get_filter_reply_t_tojson (vl_api_syslog_get_filter_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "syslog_get_filter_reply");
    cJSON_AddStringToObject(o, "_crc", "eb1833f8");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddItemToObject(o, "severity", vl_api_syslog_severity_t_tojson(a->severity));
    return o;
}
#endif
