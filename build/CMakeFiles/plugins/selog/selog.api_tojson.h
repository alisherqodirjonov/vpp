/* Imported API files */
#ifndef included_selog_api_tojson_h
#define included_selog_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_selog_get_shm_t_tojson (vl_api_selog_get_shm_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_get_shm");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_selog_get_shm_reply_t_tojson (vl_api_selog_get_shm_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_get_shm_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_selog_get_string_table_t_tojson (vl_api_selog_get_string_table_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_get_string_table");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_selog_get_string_table_reply_t_tojson (vl_api_selog_get_string_table_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_get_string_table_reply");
    cJSON_AddStringToObject(o, "_crc", "17fc26aa");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "s", &a->s);
    return o;
}
static inline cJSON *vl_api_selog_track_dump_t_tojson (vl_api_selog_track_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_track_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_selog_track_details_t_tojson (vl_api_selog_track_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_track_details");
    cJSON_AddStringToObject(o, "_crc", "33dce766");
    cJSON_AddNumberToObject(o, "index", a->index);
    vl_api_string_cJSON_AddToObject(o, "name", &a->name);
    return o;
}
static inline cJSON *vl_api_selog_event_type_dump_t_tojson (vl_api_selog_event_type_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_event_type_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_selog_event_type_details_t_tojson (vl_api_selog_event_type_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_event_type_details");
    cJSON_AddStringToObject(o, "_crc", "745bca80");
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddStringToObject(o, "fmt_args", (char *)a->fmt_args);
    vl_api_string_cJSON_AddToObject(o, "fmt", &a->fmt);
    return o;
}
static inline cJSON *vl_api_selog_event_type_string_dump_t_tojson (vl_api_selog_event_type_string_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_event_type_string_dump");
    cJSON_AddStringToObject(o, "_crc", "6a7f2680");
    cJSON_AddNumberToObject(o, "event_type_index", a->event_type_index);
    return o;
}
static inline cJSON *vl_api_selog_event_type_string_details_t_tojson (vl_api_selog_event_type_string_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "selog_event_type_string_details");
    cJSON_AddStringToObject(o, "_crc", "3718921d");
    cJSON_AddNumberToObject(o, "index", a->index);
    vl_api_string_cJSON_AddToObject(o, "s", &a->s);
    return o;
}
#endif
