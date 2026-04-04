/* Imported API files */
#include <vnet/fib/fib_types.api_tojson.h>
#ifndef included_fib_api_tojson_h
#define included_fib_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_fib_source_t_tojson (vl_api_fib_source_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_fib_source_add_t_tojson (vl_api_fib_source_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "fib_source_add");
    cJSON_AddStringToObject(o, "_crc", "b3ac2aec");
    cJSON_AddItemToObject(o, "src", vl_api_fib_source_t_tojson(&a->src));
    return o;
}
static inline cJSON *vl_api_fib_source_add_reply_t_tojson (vl_api_fib_source_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "fib_source_add_reply");
    cJSON_AddStringToObject(o, "_crc", "604fd6f1");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_fib_source_dump_t_tojson (vl_api_fib_source_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "fib_source_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_fib_source_details_t_tojson (vl_api_fib_source_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "fib_source_details");
    cJSON_AddStringToObject(o, "_crc", "8668acdb");
    cJSON_AddItemToObject(o, "src", vl_api_fib_source_t_tojson(&a->src));
    return o;
}
#endif
