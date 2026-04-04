/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_pipe_api_fromjson_h
#define included_pipe_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_pipe_create_t *vl_api_pipe_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pipe_create_t);
    vl_api_pipe_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_specified");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_specified);

    item = cJSON_GetObjectItem(o, "user_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pipe_create_reply_t *vl_api_pipe_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pipe_create_reply_t);
    vl_api_pipe_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pipe_sw_if_index");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "pipe_sw_if_index");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_interface_index_t_fromjson((void **)&a, len, e, &a->pipe_sw_if_index[i]) < 0) goto error;
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pipe_delete_t *vl_api_pipe_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pipe_delete_t);
    vl_api_pipe_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pipe_delete_reply_t *vl_api_pipe_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pipe_delete_reply_t);
    vl_api_pipe_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pipe_dump_t *vl_api_pipe_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pipe_dump_t);
    vl_api_pipe_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_pipe_details_t *vl_api_pipe_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pipe_details_t);
    vl_api_pipe_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pipe_sw_if_index");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "pipe_sw_if_index");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_interface_index_t_fromjson((void **)&a, len, e, &a->pipe_sw_if_index[i]) < 0) goto error;
        }
    }

    item = cJSON_GetObjectItem(o, "instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
