/* Imported API files */
#ifndef included_memclnt_api_fromjson_h
#define included_memclnt_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_module_version_t_fromjson (void **mp, int *len, cJSON *o, vl_api_module_version_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "major");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->major);

    item = cJSON_GetObjectItem(o, "minor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->minor);

    item = cJSON_GetObjectItem(o, "patch");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->patch);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    return 0;

  error:
    return -1;
}
static inline int vl_api_message_table_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_message_table_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    return 0;

  error:
    return -1;
}
static inline vl_api_memclnt_create_t *vl_api_memclnt_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_create_t);
    vl_api_memclnt_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ctx_quota");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->ctx_quota);

    item = cJSON_GetObjectItem(o, "input_queue");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->input_queue);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "api_versions");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "api_versions");
        int size = cJSON_GetArraySize(array);
        if (size != 8) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &a->api_versions[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_create_reply_t *vl_api_memclnt_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_create_reply_t);
    vl_api_memclnt_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "response");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->response);

    item = cJSON_GetObjectItem(o, "handle");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->handle);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "message_table");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->message_table);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_delete_t *vl_api_memclnt_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_delete_t);
    vl_api_memclnt_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "handle");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->handle);

    item = cJSON_GetObjectItem(o, "do_cleanup");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->do_cleanup);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_delete_reply_t *vl_api_memclnt_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_delete_reply_t);
    vl_api_memclnt_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "response");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->response);

    item = cJSON_GetObjectItem(o, "handle");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->handle);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_rx_thread_exit_t *vl_api_rx_thread_exit_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_rx_thread_exit_t);
    vl_api_rx_thread_exit_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dummy");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dummy);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_rx_thread_suspend_t *vl_api_memclnt_rx_thread_suspend_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_rx_thread_suspend_t);
    vl_api_memclnt_rx_thread_suspend_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dummy");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dummy);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_read_timeout_t *vl_api_memclnt_read_timeout_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_read_timeout_t);
    vl_api_memclnt_read_timeout_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "dummy");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dummy);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_rpc_call_t *vl_api_rpc_call_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_rpc_call_t);
    vl_api_rpc_call_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "function");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->function);

    item = cJSON_GetObjectItem(o, "multicast");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->multicast);

    item = cJSON_GetObjectItem(o, "need_barrier_sync");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->need_barrier_sync);

    item = cJSON_GetObjectItem(o, "send_reply");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->send_reply);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    s = u8string_fromjson(o, "data");
    if (!s) goto error;
    a->data_len = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_rpc_call_reply_t *vl_api_rpc_call_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_rpc_call_reply_t);
    vl_api_rpc_call_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_first_msg_id_t *vl_api_get_first_msg_id_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_first_msg_id_t);
    vl_api_get_first_msg_id_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_first_msg_id_reply_t *vl_api_get_first_msg_id_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_first_msg_id_reply_t);
    vl_api_get_first_msg_id_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "first_msg_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->first_msg_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_api_versions_t *vl_api_api_versions_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_api_versions_t);
    vl_api_api_versions_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_api_versions_reply_t *vl_api_api_versions_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_api_versions_reply_t);
    vl_api_api_versions_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "api_versions");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "api_versions");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_module_version_t) * size);
        vl_api_module_version_t *d = (void *)a + l;
        l += sizeof(vl_api_module_version_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_module_version_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_trace_plugin_msg_ids_t *vl_api_trace_plugin_msg_ids_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_trace_plugin_msg_ids_t);
    vl_api_trace_plugin_msg_ids_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "plugin_name");
    if (!item) goto error;
    strncpy_s((char *)a->plugin_name, sizeof(a->plugin_name), cJSON_GetStringValue(item), sizeof(a->plugin_name) - 1);

    item = cJSON_GetObjectItem(o, "first_msg_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->first_msg_id);

    item = cJSON_GetObjectItem(o, "last_msg_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->last_msg_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sockclnt_create_t *vl_api_sockclnt_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sockclnt_create_t);
    vl_api_sockclnt_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sockclnt_create_reply_t *vl_api_sockclnt_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sockclnt_create_reply_t);
    vl_api_sockclnt_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "response");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->response);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "message_table");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "message_table");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_message_table_entry_t) * size);
        vl_api_message_table_entry_t *d = (void *)a + l;
        l += sizeof(vl_api_message_table_entry_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_message_table_entry_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sockclnt_delete_t *vl_api_sockclnt_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sockclnt_delete_t);
    vl_api_sockclnt_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sockclnt_delete_reply_t *vl_api_sockclnt_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sockclnt_delete_reply_t);
    vl_api_sockclnt_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "response");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->response);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sock_init_shm_t *vl_api_sock_init_shm_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sock_init_shm_t);
    vl_api_sock_init_shm_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "requested_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->requested_size);

    item = cJSON_GetObjectItem(o, "configs");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "configs");
        int size = cJSON_GetArraySize(array);
        a->nitems = size;
        a = cJSON_realloc(a, l + sizeof(u64) * size);
        u64 *d = (void *)a + l;
        l += sizeof(u64) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u64_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sock_init_shm_reply_t *vl_api_sock_init_shm_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sock_init_shm_reply_t);
    vl_api_sock_init_shm_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_keepalive_t *vl_api_memclnt_keepalive_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_keepalive_t);
    vl_api_memclnt_keepalive_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_memclnt_keepalive_reply_t *vl_api_memclnt_keepalive_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_keepalive_reply_t);
    vl_api_memclnt_keepalive_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_control_ping_t *vl_api_control_ping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_control_ping_t);
    vl_api_control_ping_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_control_ping_reply_t *vl_api_control_ping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_control_ping_reply_t);
    vl_api_control_ping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "vpe_pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vpe_pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_create_v2_t *vl_api_memclnt_create_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_create_v2_t);
    vl_api_memclnt_create_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ctx_quota");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->ctx_quota);

    item = cJSON_GetObjectItem(o, "input_queue");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->input_queue);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "api_versions");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "api_versions");
        int size = cJSON_GetArraySize(array);
        if (size != 8) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &a->api_versions[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "keepalive");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->keepalive);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_memclnt_create_v2_reply_t *vl_api_memclnt_create_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_memclnt_create_v2_reply_t);
    vl_api_memclnt_create_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "response");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->response);

    item = cJSON_GetObjectItem(o, "handle");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->handle);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    item = cJSON_GetObjectItem(o, "message_table");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->message_table);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_get_api_json_t *vl_api_get_api_json_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_api_json_t);
    vl_api_get_api_json_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_get_api_json_reply_t *vl_api_get_api_json_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_get_api_json_reply_t);
    vl_api_get_api_json_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "json");
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
