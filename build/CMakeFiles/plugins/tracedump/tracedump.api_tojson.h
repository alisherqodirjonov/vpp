/* Imported API files */
#ifndef included_tracedump_api_tojson_h
#define included_tracedump_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_trace_filter_flag_t_tojson (vl_api_trace_filter_flag_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("TRACE_FF_NONE");
    case 1:
        return cJSON_CreateString("TRACE_FF_INCLUDE_NODE");
    case 2:
        return cJSON_CreateString("TRACE_FF_EXCLUDE_NODE");
    case 3:
        return cJSON_CreateString("TRACE_FF_INCLUDE_CLASSIFIER");
    case 4:
        return cJSON_CreateString("TRACE_FF_EXCLUDE_CLASSIFIER");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_trace_set_filters_t_tojson (vl_api_trace_set_filters_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_set_filters");
    cJSON_AddStringToObject(o, "_crc", "f522b44a");
    cJSON_AddItemToObject(o, "flag", vl_api_trace_filter_flag_t_tojson(a->flag));
    cJSON_AddNumberToObject(o, "count", a->count);
    cJSON_AddNumberToObject(o, "node_index", a->node_index);
    cJSON_AddNumberToObject(o, "classifier_table_index", a->classifier_table_index);
    return o;
}
static inline cJSON *vl_api_trace_set_filters_reply_t_tojson (vl_api_trace_set_filters_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_set_filters_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_capture_packets_t_tojson (vl_api_trace_capture_packets_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_capture_packets");
    cJSON_AddStringToObject(o, "_crc", "9e791a9b");
    cJSON_AddNumberToObject(o, "node_index", a->node_index);
    cJSON_AddNumberToObject(o, "max_packets", a->max_packets);
    cJSON_AddBoolToObject(o, "use_filter", a->use_filter);
    cJSON_AddBoolToObject(o, "verbose", a->verbose);
    cJSON_AddBoolToObject(o, "pre_capture_clear", a->pre_capture_clear);
    return o;
}
static inline cJSON *vl_api_trace_capture_packets_reply_t_tojson (vl_api_trace_capture_packets_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_capture_packets_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_clear_capture_t_tojson (vl_api_trace_clear_capture_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_clear_capture");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_trace_clear_capture_reply_t_tojson (vl_api_trace_clear_capture_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_clear_capture_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_dump_t_tojson (vl_api_trace_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_dump");
    cJSON_AddStringToObject(o, "_crc", "c7d6681f");
    cJSON_AddNumberToObject(o, "clear_cache", a->clear_cache);
    cJSON_AddNumberToObject(o, "thread_id", a->thread_id);
    cJSON_AddNumberToObject(o, "position", a->position);
    cJSON_AddNumberToObject(o, "max_records", a->max_records);
    return o;
}
static inline cJSON *vl_api_trace_dump_reply_t_tojson (vl_api_trace_dump_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_dump_reply");
    cJSON_AddStringToObject(o, "_crc", "e0e87f9d");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "last_thread_id", a->last_thread_id);
    cJSON_AddNumberToObject(o, "last_position", a->last_position);
    cJSON_AddNumberToObject(o, "more_this_thread", a->more_this_thread);
    cJSON_AddNumberToObject(o, "more_threads", a->more_threads);
    cJSON_AddNumberToObject(o, "flush_only", a->flush_only);
    cJSON_AddNumberToObject(o, "done", a->done);
    return o;
}
static inline cJSON *vl_api_trace_details_t_tojson (vl_api_trace_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_details");
    cJSON_AddStringToObject(o, "_crc", "1553e9eb");
    cJSON_AddNumberToObject(o, "thread_id", a->thread_id);
    cJSON_AddNumberToObject(o, "position", a->position);
    cJSON_AddNumberToObject(o, "more_this_thread", a->more_this_thread);
    cJSON_AddNumberToObject(o, "more_threads", a->more_threads);
    cJSON_AddNumberToObject(o, "done", a->done);
    cJSON_AddNumberToObject(o, "packet_number", a->packet_number);
    vl_api_string_cJSON_AddToObject(o, "trace_data", &a->trace_data);
    return o;
}
static inline cJSON *vl_api_trace_clear_cache_t_tojson (vl_api_trace_clear_cache_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_clear_cache");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_trace_clear_cache_reply_t_tojson (vl_api_trace_clear_cache_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_clear_cache_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_v2_dump_t_tojson (vl_api_trace_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "83f88d8e");
    cJSON_AddNumberToObject(o, "thread_id", a->thread_id);
    cJSON_AddNumberToObject(o, "position", a->position);
    cJSON_AddNumberToObject(o, "max", a->max);
    cJSON_AddBoolToObject(o, "clear_cache", a->clear_cache);
    return o;
}
static inline cJSON *vl_api_trace_v2_details_t_tojson (vl_api_trace_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_v2_details");
    cJSON_AddStringToObject(o, "_crc", "91f87d52");
    cJSON_AddNumberToObject(o, "thread_id", a->thread_id);
    cJSON_AddNumberToObject(o, "position", a->position);
    cJSON_AddBoolToObject(o, "more", a->more);
    vl_api_string_cJSON_AddToObject(o, "trace_data", &a->trace_data);
    return o;
}
static inline cJSON *vl_api_trace_set_filter_function_t_tojson (vl_api_trace_set_filter_function_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_set_filter_function");
    cJSON_AddStringToObject(o, "_crc", "616abb92");
    vl_api_string_cJSON_AddToObject(o, "filter_function_name", &a->filter_function_name);
    return o;
}
static inline cJSON *vl_api_trace_set_filter_function_reply_t_tojson (vl_api_trace_set_filter_function_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_set_filter_function_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_trace_filter_function_dump_t_tojson (vl_api_trace_filter_function_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_filter_function_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_trace_filter_function_details_t_tojson (vl_api_trace_filter_function_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_filter_function_details");
    cJSON_AddStringToObject(o, "_crc", "28821359");
    cJSON_AddBoolToObject(o, "selected", a->selected);
    vl_api_string_cJSON_AddToObject(o, "name", &a->name);
    return o;
}
#endif
