/* Imported API files */
#ifndef included_vlib_api_fromjson_h
#define included_vlib_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_thread_data_t_fromjson (void **mp, int *len, cJSON *o, vl_api_thread_data_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    strncpy_s((char *)a->type, sizeof(a->type), cJSON_GetStringValue(item), sizeof(a->type) - 1);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "cpu_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cpu_id);

    item = cJSON_GetObjectItem(o, "core");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->core);

    item = cJSON_GetObjectItem(o, "cpu_socket");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cpu_socket);

    return 0;

  error:
    return -1;
}
static inline vl_api_cli_t *vl_api_cli_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cli_t);
    vl_api_cli_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cmd_in_shmem");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->cmd_in_shmem);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cli_inband_t *vl_api_cli_inband_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cli_inband_t);
    vl_api_cli_inband_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cmd");
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
static inline vl_api_cli_reply_t *vl_api_cli_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cli_reply_t);
    vl_api_cli_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "reply_in_shmem");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->reply_in_shmem);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_cli_inband_reply_t *vl_api_cli_inband_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_cli_inband_reply_t);
    vl_api_cli_inband_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "reply");
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
static inline vl_api_get_node_index_t *vl_api_get_node_index_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_node_index_t);
    vl_api_get_node_index_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "node_name");
    if (!item) goto error;
    strncpy_s((char *)a->node_name, sizeof(a->node_name), cJSON_GetStringValue(item), sizeof(a->node_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_node_index_reply_t *vl_api_get_node_index_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_node_index_reply_t);
    vl_api_get_node_index_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "node_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->node_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_add_node_next_t *vl_api_add_node_next_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_add_node_next_t);
    vl_api_add_node_next_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "node_name");
    if (!item) goto error;
    strncpy_s((char *)a->node_name, sizeof(a->node_name), cJSON_GetStringValue(item), sizeof(a->node_name) - 1);

    item = cJSON_GetObjectItem(o, "next_name");
    if (!item) goto error;
    strncpy_s((char *)a->next_name, sizeof(a->next_name), cJSON_GetStringValue(item), sizeof(a->next_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_add_node_next_reply_t *vl_api_add_node_next_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_add_node_next_reply_t);
    vl_api_add_node_next_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->next_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_show_threads_t *vl_api_show_threads_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_threads_t);
    vl_api_show_threads_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_show_threads_reply_t *vl_api_show_threads_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_show_threads_reply_t);
    vl_api_show_threads_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "thread_data");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "thread_data");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_thread_data_t) * size);
        vl_api_thread_data_t *d = (void *)a + l;
        l += sizeof(vl_api_thread_data_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_thread_data_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_node_graph_t *vl_api_get_node_graph_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_node_graph_t);
    vl_api_get_node_graph_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_get_node_graph_reply_t *vl_api_get_node_graph_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_node_graph_reply_t);
    vl_api_get_node_graph_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "reply_in_shmem");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->reply_in_shmem);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_next_index_t *vl_api_get_next_index_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_next_index_t);
    vl_api_get_next_index_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "node_name");
    if (!item) goto error;
    strncpy_s((char *)a->node_name, sizeof(a->node_name), cJSON_GetStringValue(item), sizeof(a->node_name) - 1);

    item = cJSON_GetObjectItem(o, "next_name");
    if (!item) goto error;
    strncpy_s((char *)a->next_name, sizeof(a->next_name), cJSON_GetStringValue(item), sizeof(a->next_name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_next_index_reply_t *vl_api_get_next_index_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_next_index_reply_t);
    vl_api_get_next_index_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "next_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->next_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_f64_endian_value_t *vl_api_get_f64_endian_value_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_f64_endian_value_t);
    vl_api_get_f64_endian_value_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "f64_one");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->f64_one);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_f64_endian_value_reply_t *vl_api_get_f64_endian_value_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_f64_endian_value_reply_t);
    vl_api_get_f64_endian_value_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "f64_one_result");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->f64_one_result);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_f64_increment_by_one_t *vl_api_get_f64_increment_by_one_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_f64_increment_by_one_t);
    vl_api_get_f64_increment_by_one_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "f64_value");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->f64_value);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_f64_increment_by_one_reply_t *vl_api_get_f64_increment_by_one_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_f64_increment_by_one_reply_t);
    vl_api_get_f64_increment_by_one_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "f64_value");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->f64_value);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
