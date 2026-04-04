/* Imported API files */
#ifndef included_bpf_trace_filter_api_tojson_h
#define included_bpf_trace_filter_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_bpf_trace_filter_set_t_tojson (vl_api_bpf_trace_filter_set_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bpf_trace_filter_set");
    cJSON_AddStringToObject(o, "_crc", "3171346e");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    vl_api_string_cJSON_AddToObject(o, "filter", &a->filter);
    return o;
}
static inline cJSON *vl_api_bpf_trace_filter_set_reply_t_tojson (vl_api_bpf_trace_filter_set_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bpf_trace_filter_set_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bpf_trace_filter_set_v2_t_tojson (vl_api_bpf_trace_filter_set_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bpf_trace_filter_set_v2");
    cJSON_AddStringToObject(o, "_crc", "5615acbf");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "optimize", a->optimize);
    vl_api_string_cJSON_AddToObject(o, "filter", &a->filter);
    return o;
}
static inline cJSON *vl_api_bpf_trace_filter_set_v2_reply_t_tojson (vl_api_bpf_trace_filter_set_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bpf_trace_filter_set_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
