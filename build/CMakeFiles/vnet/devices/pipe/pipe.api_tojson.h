/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_pipe_api_tojson_h
#define included_pipe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pipe_create_t_tojson (vl_api_pipe_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pipe_create");
    cJSON_AddStringToObject(o, "_crc", "bb263bd3");
    cJSON_AddBoolToObject(o, "is_specified", a->is_specified);
    cJSON_AddNumberToObject(o, "user_instance", a->user_instance);
    return o;
}
static inline cJSON *vl_api_pipe_create_reply_t_tojson (vl_api_pipe_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pipe_create_reply");
    cJSON_AddStringToObject(o, "_crc", "b7ce310c");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "pipe_sw_if_index");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, vl_api_interface_index_t_tojson(&a->pipe_sw_if_index[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_pipe_delete_t_tojson (vl_api_pipe_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pipe_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_pipe_delete_reply_t_tojson (vl_api_pipe_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pipe_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_pipe_dump_t_tojson (vl_api_pipe_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pipe_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_pipe_details_t_tojson (vl_api_pipe_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "pipe_details");
    cJSON_AddStringToObject(o, "_crc", "c52b799d");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "pipe_sw_if_index");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, vl_api_interface_index_t_tojson(&a->pipe_sw_if_index[i]));
        }
    }
    cJSON_AddNumberToObject(o, "instance", a->instance);
    return o;
}
#endif
