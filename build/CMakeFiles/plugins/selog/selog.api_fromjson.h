/* Imported API files */
#ifndef included_selog_api_fromjson_h
#define included_selog_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_selog_get_shm_t *vl_api_selog_get_shm_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_get_shm_t);
    vl_api_selog_get_shm_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_selog_get_shm_reply_t *vl_api_selog_get_shm_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_get_shm_reply_t);
    vl_api_selog_get_shm_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_selog_get_string_table_t *vl_api_selog_get_string_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_get_string_table_t);
    vl_api_selog_get_string_table_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_selog_get_string_table_reply_t *vl_api_selog_get_string_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_get_string_table_reply_t);
    vl_api_selog_get_string_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "s");
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
static inline vl_api_selog_track_dump_t *vl_api_selog_track_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_track_dump_t);
    vl_api_selog_track_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_selog_track_details_t *vl_api_selog_track_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_track_details_t);
    vl_api_selog_track_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

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
static inline vl_api_selog_event_type_dump_t *vl_api_selog_event_type_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_event_type_dump_t);
    vl_api_selog_event_type_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_selog_event_type_details_t *vl_api_selog_event_type_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_event_type_details_t);
    vl_api_selog_event_type_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "fmt_args");
    if (!item) goto error;
    strncpy_s((char *)a->fmt_args, sizeof(a->fmt_args), cJSON_GetStringValue(item), sizeof(a->fmt_args) - 1);

    item = cJSON_GetObjectItem(o, "fmt");
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
static inline vl_api_selog_event_type_string_dump_t *vl_api_selog_event_type_string_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_event_type_string_dump_t);
    vl_api_selog_event_type_string_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "event_type_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->event_type_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_selog_event_type_string_details_t *vl_api_selog_event_type_string_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_selog_event_type_string_details_t);
    vl_api_selog_event_type_string_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "s");
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
