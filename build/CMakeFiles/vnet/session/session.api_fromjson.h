/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_session_api_fromjson_h
#define included_session_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_sdl_rule_t_fromjson (void **mp, int *len, cJSON *o, vl_api_sdl_rule_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "lcl");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->lcl) < 0) goto error;

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    return 0;

  error:
    return -1;
}
static inline int vl_api_sdl_rule_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_sdl_rule_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "rmt");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->rmt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    return 0;

  error:
    return -1;
}
static inline int vl_api_transport_proto_t_fromjson(void **mp, int *len, cJSON *o, vl_api_transport_proto_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "TRANSPORT_PROTO_API_TCP") == 0) {*a = 0; return 0;}
    if (strcmp(p, "TRANSPORT_PROTO_API_UDP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "TRANSPORT_PROTO_API_NONE") == 0) {*a = 2; return 0;}
    if (strcmp(p, "TRANSPORT_PROTO_API_TLS") == 0) {*a = 3; return 0;}
    if (strcmp(p, "TRANSPORT_PROTO_API_QUIC") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_rt_backend_engine_t_fromjson(void **mp, int *len, cJSON *o, vl_api_rt_backend_engine_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "RT_BACKEND_ENGINE_API_DISABLE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "RT_BACKEND_ENGINE_API_RULE_TABLE") == 0) {*a = 1; return 0;}
    if (strcmp(p, "RT_BACKEND_ENGINE_API_NONE") == 0) {*a = 2; return 0;}
    if (strcmp(p, "RT_BACKEND_ENGINE_API_SDL") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_session_rule_scope_t_fromjson(void **mp, int *len, cJSON *o, vl_api_session_rule_scope_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "SESSION_RULE_SCOPE_API_GLOBAL") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SESSION_RULE_SCOPE_API_LOCAL") == 0) {*a = 1; return 0;}
    if (strcmp(p, "SESSION_RULE_SCOPE_API_BOTH") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_app_attach_t *vl_api_app_attach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_attach_t);
    vl_api_app_attach_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "options");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "options");
        int size = cJSON_GetArraySize(array);
        if (size != 18) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u64_fromjson(e, &a->options[i]);
        }
    }

    item = cJSON_GetObjectItem(o, "namespace_id");
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
static inline vl_api_app_attach_reply_t *vl_api_app_attach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_attach_reply_t);
    vl_api_app_attach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "app_mq");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->app_mq);

    item = cJSON_GetObjectItem(o, "vpp_ctrl_mq");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->vpp_ctrl_mq);

    item = cJSON_GetObjectItem(o, "vpp_ctrl_mq_thread");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->vpp_ctrl_mq_thread);

    item = cJSON_GetObjectItem(o, "app_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->app_index);

    item = cJSON_GetObjectItem(o, "n_fds");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_fds);

    item = cJSON_GetObjectItem(o, "fd_flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->fd_flags);

    item = cJSON_GetObjectItem(o, "segment_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->segment_size);

    item = cJSON_GetObjectItem(o, "segment_handle");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->segment_handle);

    item = cJSON_GetObjectItem(o, "segment_name");
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
static inline vl_api_application_detach_t *vl_api_application_detach_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_application_detach_t);
    vl_api_application_detach_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_application_detach_reply_t *vl_api_application_detach_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_application_detach_reply_t);
    vl_api_application_detach_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_add_cert_key_pair_t *vl_api_app_add_cert_key_pair_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_add_cert_key_pair_t);
    vl_api_app_add_cert_key_pair_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cert_len");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->cert_len);

    item = cJSON_GetObjectItem(o, "certkey");
    if (!item) goto error;
    s = u8string_fromjson(o, "certkey");
    if (!s) goto error;
    a->certkey_len = vec_len(s);
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
static inline vl_api_app_add_cert_key_pair_reply_t *vl_api_app_add_cert_key_pair_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_add_cert_key_pair_reply_t);
    vl_api_app_add_cert_key_pair_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_del_cert_key_pair_t *vl_api_app_del_cert_key_pair_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_del_cert_key_pair_t);
    vl_api_app_del_cert_key_pair_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_del_cert_key_pair_reply_t *vl_api_app_del_cert_key_pair_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_del_cert_key_pair_reply_t);
    vl_api_app_del_cert_key_pair_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_worker_add_del_t *vl_api_app_worker_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_worker_add_del_t);
    vl_api_app_worker_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "app_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->app_index);

    item = cJSON_GetObjectItem(o, "wrk_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->wrk_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_worker_add_del_reply_t *vl_api_app_worker_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_worker_add_del_reply_t);
    vl_api_app_worker_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "wrk_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->wrk_index);

    item = cJSON_GetObjectItem(o, "app_event_queue_address");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->app_event_queue_address);

    item = cJSON_GetObjectItem(o, "n_fds");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_fds);

    item = cJSON_GetObjectItem(o, "fd_flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->fd_flags);

    item = cJSON_GetObjectItem(o, "segment_handle");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->segment_handle);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "segment_name");
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
static inline vl_api_session_enable_disable_t *vl_api_session_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_enable_disable_t);
    vl_api_session_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_enable_disable_reply_t *vl_api_session_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_enable_disable_reply_t);
    vl_api_session_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_enable_disable_v2_t *vl_api_session_enable_disable_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_enable_disable_v2_t);
    vl_api_session_enable_disable_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rt_engine_type");
    if (!item) goto error;
    if (vl_api_rt_backend_engine_t_fromjson((void **)&a, &l, item, &a->rt_engine_type) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_enable_disable_v2_reply_t *vl_api_session_enable_disable_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_enable_disable_v2_reply_t);
    vl_api_session_enable_disable_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sapi_enable_disable_t *vl_api_session_sapi_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sapi_enable_disable_t);
    vl_api_session_sapi_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sapi_enable_disable_reply_t *vl_api_session_sapi_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sapi_enable_disable_reply_t);
    vl_api_session_sapi_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_namespace_add_del_t *vl_api_app_namespace_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_t);
    vl_api_app_namespace_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "secret");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_fib_id);

    item = cJSON_GetObjectItem(o, "ip6_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_fib_id);

    item = cJSON_GetObjectItem(o, "namespace_id");
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
static inline vl_api_app_namespace_add_del_v4_t *vl_api_app_namespace_add_del_v4_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_v4_t);
    vl_api_app_namespace_add_del_v4_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "secret");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_fib_id);

    item = cJSON_GetObjectItem(o, "ip6_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_fib_id);

    item = cJSON_GetObjectItem(o, "namespace_id");
    if (!item) goto error;
    strncpy_s((char *)a->namespace_id, sizeof(a->namespace_id), cJSON_GetStringValue(item), sizeof(a->namespace_id) - 1);

    item = cJSON_GetObjectItem(o, "sock_name");
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
static inline vl_api_app_namespace_add_del_v4_reply_t *vl_api_app_namespace_add_del_v4_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_v4_reply_t);
    vl_api_app_namespace_add_del_v4_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_namespace_add_del_v2_t *vl_api_app_namespace_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_v2_t);
    vl_api_app_namespace_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "secret");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_fib_id);

    item = cJSON_GetObjectItem(o, "ip6_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_fib_id);

    item = cJSON_GetObjectItem(o, "namespace_id");
    if (!item) goto error;
    strncpy_s((char *)a->namespace_id, sizeof(a->namespace_id), cJSON_GetStringValue(item), sizeof(a->namespace_id) - 1);

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_namespace_add_del_v3_t *vl_api_app_namespace_add_del_v3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_v3_t);
    vl_api_app_namespace_add_del_v3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "secret");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip4_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip4_fib_id);

    item = cJSON_GetObjectItem(o, "ip6_fib_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->ip6_fib_id);

    item = cJSON_GetObjectItem(o, "namespace_id");
    if (!item) goto error;
    strncpy_s((char *)a->namespace_id, sizeof(a->namespace_id), cJSON_GetStringValue(item), sizeof(a->namespace_id) - 1);

    item = cJSON_GetObjectItem(o, "netns");
    if (!item) goto error;
    strncpy_s((char *)a->netns, sizeof(a->netns), cJSON_GetStringValue(item), sizeof(a->netns) - 1);

    item = cJSON_GetObjectItem(o, "sock_name");
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
static inline vl_api_app_namespace_add_del_reply_t *vl_api_app_namespace_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_reply_t);
    vl_api_app_namespace_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_namespace_add_del_v2_reply_t *vl_api_app_namespace_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_v2_reply_t);
    vl_api_app_namespace_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_app_namespace_add_del_v3_reply_t *vl_api_app_namespace_add_del_v3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_app_namespace_add_del_v3_reply_t);
    vl_api_app_namespace_add_del_v3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_rule_add_del_t *vl_api_session_rule_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_rule_add_del_t);
    vl_api_session_rule_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "transport_proto");
    if (!item) goto error;
    if (vl_api_transport_proto_t_fromjson((void **)&a, &l, item, &a->transport_proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->lcl) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rmt");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->rmt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->lcl_port);

    item = cJSON_GetObjectItem(o, "rmt_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rmt_port);

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    item = cJSON_GetObjectItem(o, "scope");
    if (!item) goto error;
    if (vl_api_session_rule_scope_t_fromjson((void **)&a, &l, item, &a->scope) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_rule_add_del_reply_t *vl_api_session_rule_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_rule_add_del_reply_t);
    vl_api_session_rule_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_rules_dump_t *vl_api_session_rules_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_rules_dump_t);
    vl_api_session_rules_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_session_rules_details_t *vl_api_session_rules_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_rules_details_t);
    vl_api_session_rules_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "transport_proto");
    if (!item) goto error;
    if (vl_api_transport_proto_t_fromjson((void **)&a, &l, item, &a->transport_proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->lcl) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rmt");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->rmt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->lcl_port);

    item = cJSON_GetObjectItem(o, "rmt_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rmt_port);

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    item = cJSON_GetObjectItem(o, "scope");
    if (!item) goto error;
    if (vl_api_session_rule_scope_t_fromjson((void **)&a, &l, item, &a->scope) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_rules_v2_dump_t *vl_api_session_rules_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_rules_v2_dump_t);
    vl_api_session_rules_v2_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_session_rules_v2_details_t *vl_api_session_rules_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_rules_v2_details_t);
    vl_api_session_rules_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "transport_proto");
    if (!item) goto error;
    if (vl_api_transport_proto_t_fromjson((void **)&a, &l, item, &a->transport_proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->lcl) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rmt");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->rmt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lcl_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->lcl_port);

    item = cJSON_GetObjectItem(o, "rmt_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->rmt_port);

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "scope");
    if (!item) goto error;
    if (vl_api_session_rule_scope_t_fromjson((void **)&a, &l, item, &a->scope) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "appns_index");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_add_del_t *vl_api_session_sdl_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_add_del_t);
    vl_api_session_sdl_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_sdl_rule_t) * size);
        vl_api_sdl_rule_t *d = (void *)a + l;
        l += sizeof(vl_api_sdl_rule_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_sdl_rule_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_add_del_reply_t *vl_api_session_sdl_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_add_del_reply_t);
    vl_api_session_sdl_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_add_del_v2_t *vl_api_session_sdl_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_add_del_v2_t);
    vl_api_session_sdl_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "r");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "r");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_sdl_rule_v2_t) * size);
        vl_api_sdl_rule_v2_t *d = (void *)a + l;
        l += sizeof(vl_api_sdl_rule_v2_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_sdl_rule_v2_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_add_del_v2_reply_t *vl_api_session_sdl_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_add_del_v2_reply_t);
    vl_api_session_sdl_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_dump_t *vl_api_session_sdl_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_dump_t);
    vl_api_session_sdl_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_session_sdl_details_t *vl_api_session_sdl_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_details_t);
    vl_api_session_sdl_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "lcl");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->lcl) < 0) goto error;

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_v2_dump_t *vl_api_session_sdl_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_v2_dump_t);
    vl_api_session_sdl_v2_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_session_sdl_v2_details_t *vl_api_session_sdl_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_v2_details_t);
    vl_api_session_sdl_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rmt");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->rmt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->appns_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_session_sdl_v3_dump_t *vl_api_session_sdl_v3_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_v3_dump_t);
    vl_api_session_sdl_v3_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_session_sdl_v3_details_t *vl_api_session_sdl_v3_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_session_sdl_v3_details_t);
    vl_api_session_sdl_v3_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rmt");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->rmt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "action_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->action_index);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "appns_index");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "appns_index");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
