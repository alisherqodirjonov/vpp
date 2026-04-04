/* Imported API files */
#ifndef included_tracedump_api_fromjson_h
#define included_tracedump_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_trace_filter_flag_t_fromjson(void **mp, int *len, cJSON *o, vl_api_trace_filter_flag_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "TRACE_FF_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "TRACE_FF_INCLUDE_NODE") == 0) {*a = 1; return 0;}
    if (strcmp(p, "TRACE_FF_EXCLUDE_NODE") == 0) {*a = 2; return 0;}
    if (strcmp(p, "TRACE_FF_INCLUDE_CLASSIFIER") == 0) {*a = 3; return 0;}
    if (strcmp(p, "TRACE_FF_EXCLUDE_CLASSIFIER") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_trace_set_filters_t *vl_api_trace_set_filters_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_set_filters_t);
    vl_api_trace_set_filters_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flag");
    if (!item) goto error;
    if (vl_api_trace_filter_flag_t_fromjson((void **)&a, &l, item, &a->flag) < 0) goto error;

    item = cJSON_GetObjectItem(o, "count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->count);

    item = cJSON_GetObjectItem(o, "node_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->node_index);

    item = cJSON_GetObjectItem(o, "classifier_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->classifier_table_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_set_filters_reply_t *vl_api_trace_set_filters_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_set_filters_reply_t);
    vl_api_trace_set_filters_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_capture_packets_t *vl_api_trace_capture_packets_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_capture_packets_t);
    vl_api_trace_capture_packets_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "node_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->node_index);

    item = cJSON_GetObjectItem(o, "max_packets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_packets);

    item = cJSON_GetObjectItem(o, "use_filter");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->use_filter);

    item = cJSON_GetObjectItem(o, "verbose");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->verbose);

    item = cJSON_GetObjectItem(o, "pre_capture_clear");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->pre_capture_clear);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_capture_packets_reply_t *vl_api_trace_capture_packets_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_capture_packets_reply_t);
    vl_api_trace_capture_packets_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_clear_capture_t *vl_api_trace_clear_capture_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_clear_capture_t);
    vl_api_trace_clear_capture_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_trace_clear_capture_reply_t *vl_api_trace_clear_capture_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_clear_capture_reply_t);
    vl_api_trace_clear_capture_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_dump_t *vl_api_trace_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_dump_t);
    vl_api_trace_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "clear_cache");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->clear_cache);

    item = cJSON_GetObjectItem(o, "thread_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->thread_id);

    item = cJSON_GetObjectItem(o, "position");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->position);

    item = cJSON_GetObjectItem(o, "max_records");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max_records);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_dump_reply_t *vl_api_trace_dump_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_dump_reply_t);
    vl_api_trace_dump_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "last_thread_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->last_thread_id);

    item = cJSON_GetObjectItem(o, "last_position");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->last_position);

    item = cJSON_GetObjectItem(o, "more_this_thread");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->more_this_thread);

    item = cJSON_GetObjectItem(o, "more_threads");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->more_threads);

    item = cJSON_GetObjectItem(o, "flush_only");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flush_only);

    item = cJSON_GetObjectItem(o, "done");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->done);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_details_t *vl_api_trace_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_details_t);
    vl_api_trace_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "thread_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->thread_id);

    item = cJSON_GetObjectItem(o, "position");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->position);

    item = cJSON_GetObjectItem(o, "more_this_thread");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->more_this_thread);

    item = cJSON_GetObjectItem(o, "more_threads");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->more_threads);

    item = cJSON_GetObjectItem(o, "done");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->done);

    item = cJSON_GetObjectItem(o, "packet_number");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->packet_number);

    item = cJSON_GetObjectItem(o, "trace_data");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_clear_cache_t *vl_api_trace_clear_cache_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_clear_cache_t);
    vl_api_trace_clear_cache_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_trace_clear_cache_reply_t *vl_api_trace_clear_cache_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_clear_cache_reply_t);
    vl_api_trace_clear_cache_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_v2_dump_t *vl_api_trace_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_v2_dump_t);
    vl_api_trace_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "thread_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->thread_id);

    item = cJSON_GetObjectItem(o, "position");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->position);

    item = cJSON_GetObjectItem(o, "max");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->max);

    item = cJSON_GetObjectItem(o, "clear_cache");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->clear_cache);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_v2_details_t *vl_api_trace_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_v2_details_t);
    vl_api_trace_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "thread_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->thread_id);

    item = cJSON_GetObjectItem(o, "position");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->position);

    item = cJSON_GetObjectItem(o, "more");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->more);

    item = cJSON_GetObjectItem(o, "trace_data");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_set_filter_function_t *vl_api_trace_set_filter_function_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_set_filter_function_t);
    vl_api_trace_set_filter_function_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "filter_function_name");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_set_filter_function_reply_t *vl_api_trace_set_filter_function_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_set_filter_function_reply_t);
    vl_api_trace_set_filter_function_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_filter_function_dump_t *vl_api_trace_filter_function_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_filter_function_dump_t);
    vl_api_trace_filter_function_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_trace_filter_function_details_t *vl_api_trace_filter_function_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_filter_function_details_t);
    vl_api_trace_filter_function_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "selected");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->selected);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
