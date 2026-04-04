/* Imported API files */
#ifndef included_vlib_api_tojson_h
#define included_vlib_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_thread_data_t_tojson (vl_api_thread_data_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddStringToObject(o, "type", (char *)a->type);
    cJSON_AddNumberToObject(o, "pid", a->pid);
    cJSON_AddNumberToObject(o, "cpu_id", a->cpu_id);
    cJSON_AddNumberToObject(o, "core", a->core);
    cJSON_AddNumberToObject(o, "cpu_socket", a->cpu_socket);
    return o;
}
static inline cJSON *vl_api_cli_t_tojson (vl_api_cli_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cli");
    cJSON_AddStringToObject(o, "_crc", "23bfbfff");
    cJSON_AddNumberToObject(o, "cmd_in_shmem", a->cmd_in_shmem);
    return o;
}
static inline cJSON *vl_api_cli_inband_t_tojson (vl_api_cli_inband_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cli_inband");
    cJSON_AddStringToObject(o, "_crc", "f8377302");
    vl_api_string_cJSON_AddToObject(o, "cmd", &a->cmd);
    return o;
}
static inline cJSON *vl_api_cli_reply_t_tojson (vl_api_cli_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cli_reply");
    cJSON_AddStringToObject(o, "_crc", "06d68297");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "reply_in_shmem", a->reply_in_shmem);
    return o;
}
static inline cJSON *vl_api_cli_inband_reply_t_tojson (vl_api_cli_inband_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "cli_inband_reply");
    cJSON_AddStringToObject(o, "_crc", "05879051");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "reply", &a->reply);
    return o;
}
static inline cJSON *vl_api_get_node_index_t_tojson (vl_api_get_node_index_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_node_index");
    cJSON_AddStringToObject(o, "_crc", "f1984c64");
    cJSON_AddStringToObject(o, "node_name", (char *)a->node_name);
    return o;
}
static inline cJSON *vl_api_get_node_index_reply_t_tojson (vl_api_get_node_index_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_node_index_reply");
    cJSON_AddStringToObject(o, "_crc", "a8600b89");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "node_index", a->node_index);
    return o;
}
static inline cJSON *vl_api_add_node_next_t_tojson (vl_api_add_node_next_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "add_node_next");
    cJSON_AddStringToObject(o, "_crc", "2457116d");
    cJSON_AddStringToObject(o, "node_name", (char *)a->node_name);
    cJSON_AddStringToObject(o, "next_name", (char *)a->next_name);
    return o;
}
static inline cJSON *vl_api_add_node_next_reply_t_tojson (vl_api_add_node_next_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "add_node_next_reply");
    cJSON_AddStringToObject(o, "_crc", "2ed75f32");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "next_index", a->next_index);
    return o;
}
static inline cJSON *vl_api_show_threads_t_tojson (vl_api_show_threads_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_threads");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_show_threads_reply_t_tojson (vl_api_show_threads_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "show_threads_reply");
    cJSON_AddStringToObject(o, "_crc", "efd78e83");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "thread_data");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_thread_data_t_tojson(&a->thread_data[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_get_node_graph_t_tojson (vl_api_get_node_graph_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_node_graph");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_get_node_graph_reply_t_tojson (vl_api_get_node_graph_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_node_graph_reply");
    cJSON_AddStringToObject(o, "_crc", "06d68297");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "reply_in_shmem", a->reply_in_shmem);
    return o;
}
static inline cJSON *vl_api_get_next_index_t_tojson (vl_api_get_next_index_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_next_index");
    cJSON_AddStringToObject(o, "_crc", "2457116d");
    cJSON_AddStringToObject(o, "node_name", (char *)a->node_name);
    cJSON_AddStringToObject(o, "next_name", (char *)a->next_name);
    return o;
}
static inline cJSON *vl_api_get_next_index_reply_t_tojson (vl_api_get_next_index_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_next_index_reply");
    cJSON_AddStringToObject(o, "_crc", "2ed75f32");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "next_index", a->next_index);
    return o;
}
static inline cJSON *vl_api_get_f64_endian_value_t_tojson (vl_api_get_f64_endian_value_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_f64_endian_value");
    cJSON_AddStringToObject(o, "_crc", "809fcd44");
    cJSON_AddNumberToObject(o, "f64_one", a->f64_one);
    return o;
}
static inline cJSON *vl_api_get_f64_endian_value_reply_t_tojson (vl_api_get_f64_endian_value_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_f64_endian_value_reply");
    cJSON_AddStringToObject(o, "_crc", "7e02e404");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "f64_one_result", a->f64_one_result);
    return o;
}
static inline cJSON *vl_api_get_f64_increment_by_one_t_tojson (vl_api_get_f64_increment_by_one_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_f64_increment_by_one");
    cJSON_AddStringToObject(o, "_crc", "b64f027e");
    cJSON_AddNumberToObject(o, "f64_value", a->f64_value);
    return o;
}
static inline cJSON *vl_api_get_f64_increment_by_one_reply_t_tojson (vl_api_get_f64_increment_by_one_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_f64_increment_by_one_reply");
    cJSON_AddStringToObject(o, "_crc", "d25dbaa3");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "f64_value", a->f64_value);
    return o;
}
#endif
