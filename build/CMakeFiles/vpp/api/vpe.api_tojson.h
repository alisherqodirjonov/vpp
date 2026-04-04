/* Imported API files */
#include <vpp/api/vpe_types.api_tojson.h>
#ifndef included_vpe_api_tojson_h
#define included_vpe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_show_version_t_tojson (vl_api_show_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_version");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_version_reply_t_tojson (vl_api_show_version_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_version_reply");
    cJSON_AddStringToObject(o, "_crc", "c919bde1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddStringToObject(o, "program", (char *)a->program);
    cJSON_AddStringToObject(o, "version", (char *)a->version);
    cJSON_AddStringToObject(o, "build_date", (char *)a->build_date);
    cJSON_AddStringToObject(o, "build_directory", (char *)a->build_directory);
    return o;
}
static inline cJSON *vl_api_show_vpe_system_time_t_tojson (vl_api_show_vpe_system_time_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_vpe_system_time");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_vpe_system_time_reply_t_tojson (vl_api_show_vpe_system_time_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_vpe_system_time_reply");
    cJSON_AddStringToObject(o, "_crc", "7ffd8193");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vpe_system_time", a->vpe_system_time);
    return o;
}
static inline cJSON *vl_api_log_dump_t_tojson (vl_api_log_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "log_dump");
    cJSON_AddStringToObject(o, "_crc", "6ab31753");
    cJSON_AddNumberToObject(o, "start_timestamp", a->start_timestamp);
    return o;
}
static inline cJSON *vl_api_log_details_t_tojson (vl_api_log_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "log_details");
    cJSON_AddStringToObject(o, "_crc", "03d61cc0");
    cJSON_AddNumberToObject(o, "timestamp", a->timestamp);
    cJSON_AddItemToObject(o, "level", vl_api_log_level_t_tojson(a->level));
    cJSON_AddStringToObject(o, "msg_class", (char *)a->msg_class);
    cJSON_AddStringToObject(o, "message", (char *)a->message);
    return o;
}
#endif
