/* Imported API files */
#ifndef included_memclnt_api_tojson_h
#define included_memclnt_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_module_version_t_tojson (vl_api_module_version_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "major", a->major);
    cJSON_AddNumberToObject(o, "minor", a->minor);
    cJSON_AddNumberToObject(o, "patch", a->patch);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_message_table_entry_t_tojson (vl_api_message_table_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_memclnt_create_t_tojson (vl_api_memclnt_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_create");
    cJSON_AddStringToObject(o, "_crc", "9c5e1c2f");
    cJSON_AddNumberToObject(o, "ctx_quota", a->ctx_quota);
    cJSON_AddNumberToObject(o, "input_queue", a->input_queue);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "api_versions");
        for (i = 0; i < 8; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->api_versions[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_memclnt_create_reply_t_tojson (vl_api_memclnt_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_create_reply");
    cJSON_AddStringToObject(o, "_crc", "42ec4560");
    cJSON_AddNumberToObject(o, "response", a->response);
    cJSON_AddNumberToObject(o, "handle", a->handle);
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddNumberToObject(o, "message_table", a->message_table);
    return o;
}
static inline cJSON *vl_api_memclnt_delete_t_tojson (vl_api_memclnt_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_delete");
    cJSON_AddStringToObject(o, "_crc", "7e1c04e3");
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddNumberToObject(o, "handle", a->handle);
    cJSON_AddBoolToObject(o, "do_cleanup", a->do_cleanup);
    return o;
}
static inline cJSON *vl_api_memclnt_delete_reply_t_tojson (vl_api_memclnt_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "3d3b6312");
    cJSON_AddNumberToObject(o, "response", a->response);
    cJSON_AddNumberToObject(o, "handle", a->handle);
    return o;
}
static inline cJSON *vl_api_rx_thread_exit_t_tojson (vl_api_rx_thread_exit_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "rx_thread_exit");
    cJSON_AddStringToObject(o, "_crc", "c3a3a452");
    cJSON_AddNumberToObject(o, "dummy", a->dummy);
    return o;
}
static inline cJSON *vl_api_memclnt_rx_thread_suspend_t_tojson (vl_api_memclnt_rx_thread_suspend_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_rx_thread_suspend");
    cJSON_AddStringToObject(o, "_crc", "c3a3a452");
    cJSON_AddNumberToObject(o, "dummy", a->dummy);
    return o;
}
static inline cJSON *vl_api_memclnt_read_timeout_t_tojson (vl_api_memclnt_read_timeout_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_read_timeout");
    cJSON_AddStringToObject(o, "_crc", "c3a3a452");
    cJSON_AddNumberToObject(o, "dummy", a->dummy);
    return o;
}
static inline cJSON *vl_api_rpc_call_t_tojson (vl_api_rpc_call_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "rpc_call");
    cJSON_AddStringToObject(o, "_crc", "7e8a2c95");
    cJSON_AddNumberToObject(o, "function", a->function);
    cJSON_AddNumberToObject(o, "multicast", a->multicast);
    cJSON_AddNumberToObject(o, "need_barrier_sync", a->need_barrier_sync);
    cJSON_AddNumberToObject(o, "send_reply", a->send_reply);
    cJSON_AddNumberToObject(o, "data_len", a->data_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->data, a->data_len);
    cJSON_AddStringToObject(o, "data", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_rpc_call_reply_t_tojson (vl_api_rpc_call_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "rpc_call_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_get_first_msg_id_t_tojson (vl_api_get_first_msg_id_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_first_msg_id");
    cJSON_AddStringToObject(o, "_crc", "ebf79a66");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_get_first_msg_id_reply_t_tojson (vl_api_get_first_msg_id_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_first_msg_id_reply");
    cJSON_AddStringToObject(o, "_crc", "7d337472");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "first_msg_id", a->first_msg_id);
    return o;
}
static inline cJSON *vl_api_api_versions_t_tojson (vl_api_api_versions_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "api_versions");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_api_versions_reply_t_tojson (vl_api_api_versions_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "api_versions_reply");
    cJSON_AddStringToObject(o, "_crc", "5f0d99d6");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "api_versions");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_module_version_t_tojson(&a->api_versions[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_trace_plugin_msg_ids_t_tojson (vl_api_trace_plugin_msg_ids_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "trace_plugin_msg_ids");
    cJSON_AddStringToObject(o, "_crc", "f476d3ce");
    cJSON_AddStringToObject(o, "plugin_name", (char *)a->plugin_name);
    cJSON_AddNumberToObject(o, "first_msg_id", a->first_msg_id);
    cJSON_AddNumberToObject(o, "last_msg_id", a->last_msg_id);
    return o;
}
static inline cJSON *vl_api_sockclnt_create_t_tojson (vl_api_sockclnt_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sockclnt_create");
    cJSON_AddStringToObject(o, "_crc", "455fb9c4");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    return o;
}
static inline cJSON *vl_api_sockclnt_create_reply_t_tojson (vl_api_sockclnt_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sockclnt_create_reply");
    cJSON_AddStringToObject(o, "_crc", "35166268");
    cJSON_AddNumberToObject(o, "response", a->response);
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "message_table");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_message_table_entry_t_tojson(&a->message_table[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sockclnt_delete_t_tojson (vl_api_sockclnt_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sockclnt_delete");
    cJSON_AddStringToObject(o, "_crc", "8ac76db6");
    cJSON_AddNumberToObject(o, "index", a->index);
    return o;
}
static inline cJSON *vl_api_sockclnt_delete_reply_t_tojson (vl_api_sockclnt_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sockclnt_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "8f38b1ee");
    cJSON_AddNumberToObject(o, "response", a->response);
    return o;
}
static inline cJSON *vl_api_sock_init_shm_t_tojson (vl_api_sock_init_shm_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sock_init_shm");
    cJSON_AddStringToObject(o, "_crc", "51646d92");
    cJSON_AddNumberToObject(o, "requested_size", a->requested_size);
    cJSON_AddNumberToObject(o, "nitems", a->nitems);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "configs");
        for (i = 0; i < a->nitems; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->configs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_sock_init_shm_reply_t_tojson (vl_api_sock_init_shm_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "sock_init_shm_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_memclnt_keepalive_t_tojson (vl_api_memclnt_keepalive_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_keepalive");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_memclnt_keepalive_reply_t_tojson (vl_api_memclnt_keepalive_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_keepalive_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_control_ping_t_tojson (vl_api_control_ping_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "control_ping");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_control_ping_reply_t_tojson (vl_api_control_ping_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "control_ping_reply");
    cJSON_AddStringToObject(o, "_crc", "f6b0b8ca");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "vpe_pid", a->vpe_pid);
    return o;
}
static inline cJSON *vl_api_memclnt_create_v2_t_tojson (vl_api_memclnt_create_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_create_v2");
    cJSON_AddStringToObject(o, "_crc", "c4bd4882");
    cJSON_AddNumberToObject(o, "ctx_quota", a->ctx_quota);
    cJSON_AddNumberToObject(o, "input_queue", a->input_queue);
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "api_versions");
        for (i = 0; i < 8; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->api_versions[i]));
        }
    }
    cJSON_AddBoolToObject(o, "keepalive", a->keepalive);
    return o;
}
static inline cJSON *vl_api_memclnt_create_v2_reply_t_tojson (vl_api_memclnt_create_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memclnt_create_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "42ec4560");
    cJSON_AddNumberToObject(o, "response", a->response);
    cJSON_AddNumberToObject(o, "handle", a->handle);
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddNumberToObject(o, "message_table", a->message_table);
    return o;
}
static inline cJSON *vl_api_get_api_json_t_tojson (vl_api_get_api_json_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_api_json");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_get_api_json_reply_t_tojson (vl_api_get_api_json_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "get_api_json_reply");
    cJSON_AddStringToObject(o, "_crc", "ea715b59");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    vl_api_string_cJSON_AddToObject(o, "json", &a->json);
    return o;
}
#endif
