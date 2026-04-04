/* Imported API files */
#ifndef included_trace_api_tojson_h
#define included_trace_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_trace_profile_add_t_tojson (vl_api_trace_profile_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_profile_add");
    cJSON_AddStringToObject(o, "_crc", "de08aa6d");
    cJSON_AddNumberToObject(o, "trace_type", a->trace_type);
    cJSON_AddNumberToObject(o, "num_elts", a->num_elts);
    cJSON_AddNumberToObject(o, "trace_tsp", a->trace_tsp);
    cJSON_AddNumberToObject(o, "node_id", a->node_id);
    cJSON_AddNumberToObject(o, "app_data", a->app_data);
    return o;
}
static inline cJSON *vl_api_trace_profile_add_reply_t_tojson (vl_api_trace_profile_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_profile_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_profile_del_t_tojson (vl_api_trace_profile_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_profile_del");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_trace_profile_del_reply_t_tojson (vl_api_trace_profile_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_profile_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_profile_show_config_t_tojson (vl_api_trace_profile_show_config_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_profile_show_config");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_trace_profile_show_config_reply_t_tojson (vl_api_trace_profile_show_config_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_profile_show_config_reply");
    cJSON_AddStringToObject(o, "_crc", "0f1d374c");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "trace_type", a->trace_type);
    cJSON_AddNumberToObject(o, "num_elts", a->num_elts);
    cJSON_AddNumberToObject(o, "trace_tsp", a->trace_tsp);
    cJSON_AddNumberToObject(o, "node_id", a->node_id);
    cJSON_AddNumberToObject(o, "app_data", a->app_data);
    return o;
}
#endif
