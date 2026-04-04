/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_session_api_tojson_h
#define included_session_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_sdl_rule_t_tojson (vl_api_sdl_rule_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "lcl", vl_api_prefix_t_tojson(&a->lcl));
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_sdl_rule_v2_t_tojson (vl_api_sdl_rule_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "rmt", vl_api_prefix_t_tojson(&a->rmt));
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_transport_proto_t_tojson (vl_api_transport_proto_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("TRANSPORT_PROTO_API_TCP");
    case 1:
        return cJSON_CreateString("TRANSPORT_PROTO_API_UDP");
    case 2:
        return cJSON_CreateString("TRANSPORT_PROTO_API_NONE");
    case 3:
        return cJSON_CreateString("TRANSPORT_PROTO_API_TLS");
    case 4:
        return cJSON_CreateString("TRANSPORT_PROTO_API_QUIC");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_rt_backend_engine_t_tojson (vl_api_rt_backend_engine_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("RT_BACKEND_ENGINE_API_DISABLE");
    case 1:
        return cJSON_CreateString("RT_BACKEND_ENGINE_API_RULE_TABLE");
    case 2:
        return cJSON_CreateString("RT_BACKEND_ENGINE_API_NONE");
    case 3:
        return cJSON_CreateString("RT_BACKEND_ENGINE_API_SDL");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_session_rule_scope_t_tojson (vl_api_session_rule_scope_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("SESSION_RULE_SCOPE_API_GLOBAL");
    case 1:
        return cJSON_CreateString("SESSION_RULE_SCOPE_API_LOCAL");
    case 2:
        return cJSON_CreateString("SESSION_RULE_SCOPE_API_BOTH");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_app_attach_t_tojson (vl_api_app_attach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_attach");
    cJSON_AddStringToObject(o, "_crc", "5f4a260d");
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "options");
        for (i = 0; i < 18; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->options[i]));
        }
    }
    vl_api_string_cJSON_AddToObject(o, "namespace_id", &a->namespace_id);
    return o;
}
static inline cJSON *vl_api_app_attach_reply_t_tojson (vl_api_app_attach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_attach_reply");
    cJSON_AddStringToObject(o, "_crc", "5c89c3b0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "app_mq", a->app_mq);
    cJSON_AddNumberToObject(o, "vpp_ctrl_mq", a->vpp_ctrl_mq);
    cJSON_AddNumberToObject(o, "vpp_ctrl_mq_thread", a->vpp_ctrl_mq_thread);
    cJSON_AddNumberToObject(o, "app_index", a->app_index);
    cJSON_AddNumberToObject(o, "n_fds", a->n_fds);
    cJSON_AddNumberToObject(o, "fd_flags", a->fd_flags);
    cJSON_AddNumberToObject(o, "segment_size", a->segment_size);
    cJSON_AddNumberToObject(o, "segment_handle", a->segment_handle);
    vl_api_string_cJSON_AddToObject(o, "segment_name", &a->segment_name);
    return o;
}
static inline cJSON *vl_api_application_detach_t_tojson (vl_api_application_detach_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "application_detach");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_application_detach_reply_t_tojson (vl_api_application_detach_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "application_detach_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_app_add_cert_key_pair_t_tojson (vl_api_app_add_cert_key_pair_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_add_cert_key_pair");
    cJSON_AddStringToObject(o, "_crc", "02eb8016");
    cJSON_AddNumberToObject(o, "cert_len", a->cert_len);
    cJSON_AddNumberToObject(o, "certkey_len", a->certkey_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->certkey, a->certkey_len);
    cJSON_AddStringToObject(o, "certkey", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_app_add_cert_key_pair_reply_t_tojson (vl_api_app_add_cert_key_pair_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_add_cert_key_pair_reply");
    cJSON_AddStringToObject(o, "_crc", "b42958d0");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "index", a->index);
    return o;
}
static inline cJSON *vl_api_app_del_cert_key_pair_t_tojson (vl_api_app_del_cert_key_pair_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_del_cert_key_pair");
    cJSON_AddStringToObject(o, "_crc", "8ac76db6");
    cJSON_AddNumberToObject(o, "index", a->index);
    return o;
}
static inline cJSON *vl_api_app_del_cert_key_pair_reply_t_tojson (vl_api_app_del_cert_key_pair_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_del_cert_key_pair_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_app_worker_add_del_t_tojson (vl_api_app_worker_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_worker_add_del");
    cJSON_AddStringToObject(o, "_crc", "753253dc");
    cJSON_AddNumberToObject(o, "app_index", a->app_index);
    cJSON_AddNumberToObject(o, "wrk_index", a->wrk_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    return o;
}
static inline cJSON *vl_api_app_worker_add_del_reply_t_tojson (vl_api_app_worker_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_worker_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "5735ffe7");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "wrk_index", a->wrk_index);
    cJSON_AddNumberToObject(o, "app_event_queue_address", a->app_event_queue_address);
    cJSON_AddNumberToObject(o, "n_fds", a->n_fds);
    cJSON_AddNumberToObject(o, "fd_flags", a->fd_flags);
    cJSON_AddNumberToObject(o, "segment_handle", a->segment_handle);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    vl_api_string_cJSON_AddToObject(o, "segment_name", &a->segment_name);
    return o;
}
static inline cJSON *vl_api_session_enable_disable_t_tojson (vl_api_session_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "c264d7bf");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_session_enable_disable_reply_t_tojson (vl_api_session_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_session_enable_disable_v2_t_tojson (vl_api_session_enable_disable_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_enable_disable_v2");
    cJSON_AddStringToObject(o, "_crc", "f09fbf32");
    cJSON_AddItemToObject(o, "rt_engine_type", vl_api_rt_backend_engine_t_tojson(a->rt_engine_type));
    return o;
}
static inline cJSON *vl_api_session_enable_disable_v2_reply_t_tojson (vl_api_session_enable_disable_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_enable_disable_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_session_sapi_enable_disable_t_tojson (vl_api_session_sapi_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sapi_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "c264d7bf");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_session_sapi_enable_disable_reply_t_tojson (vl_api_session_sapi_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sapi_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_t_tojson (vl_api_app_namespace_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del");
    cJSON_AddStringToObject(o, "_crc", "6306aecb");
    cJSON_AddNumberToObject(o, "secret", a->secret);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_fib_id", a->ip4_fib_id);
    cJSON_AddNumberToObject(o, "ip6_fib_id", a->ip6_fib_id);
    vl_api_string_cJSON_AddToObject(o, "namespace_id", &a->namespace_id);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_v4_t_tojson (vl_api_app_namespace_add_del_v4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_v4");
    cJSON_AddStringToObject(o, "_crc", "42c1d824");
    cJSON_AddNumberToObject(o, "secret", a->secret);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_fib_id", a->ip4_fib_id);
    cJSON_AddNumberToObject(o, "ip6_fib_id", a->ip6_fib_id);
    cJSON_AddStringToObject(o, "namespace_id", (char *)a->namespace_id);
    vl_api_string_cJSON_AddToObject(o, "sock_name", &a->sock_name);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_v4_reply_t_tojson (vl_api_app_namespace_add_del_v4_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_v4_reply");
    cJSON_AddStringToObject(o, "_crc", "85137120");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_v2_t_tojson (vl_api_app_namespace_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "ee0755cf");
    cJSON_AddNumberToObject(o, "secret", a->secret);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_fib_id", a->ip4_fib_id);
    cJSON_AddNumberToObject(o, "ip6_fib_id", a->ip6_fib_id);
    cJSON_AddStringToObject(o, "namespace_id", (char *)a->namespace_id);
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_v3_t_tojson (vl_api_app_namespace_add_del_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_v3");
    cJSON_AddStringToObject(o, "_crc", "8a7e40a1");
    cJSON_AddNumberToObject(o, "secret", a->secret);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "ip4_fib_id", a->ip4_fib_id);
    cJSON_AddNumberToObject(o, "ip6_fib_id", a->ip6_fib_id);
    cJSON_AddStringToObject(o, "namespace_id", (char *)a->namespace_id);
    cJSON_AddStringToObject(o, "netns", (char *)a->netns);
    vl_api_string_cJSON_AddToObject(o, "sock_name", &a->sock_name);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_reply_t_tojson (vl_api_app_namespace_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "85137120");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_v2_reply_t_tojson (vl_api_app_namespace_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "85137120");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    return o;
}
static inline cJSON *vl_api_app_namespace_add_del_v3_reply_t_tojson (vl_api_app_namespace_add_del_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "app_namespace_add_del_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "85137120");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    return o;
}
static inline cJSON *vl_api_session_rule_add_del_t_tojson (vl_api_session_rule_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_rule_add_del");
    cJSON_AddStringToObject(o, "_crc", "82a90af5");
    cJSON_AddItemToObject(o, "transport_proto", vl_api_transport_proto_t_tojson(a->transport_proto));
    cJSON_AddItemToObject(o, "lcl", vl_api_prefix_t_tojson(&a->lcl));
    cJSON_AddItemToObject(o, "rmt", vl_api_prefix_t_tojson(&a->rmt));
    cJSON_AddNumberToObject(o, "lcl_port", a->lcl_port);
    cJSON_AddNumberToObject(o, "rmt_port", a->rmt_port);
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    cJSON_AddItemToObject(o, "scope", vl_api_session_rule_scope_t_tojson(a->scope));
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_session_rule_add_del_reply_t_tojson (vl_api_session_rule_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_rule_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_session_rules_dump_t_tojson (vl_api_session_rules_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_rules_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_session_rules_details_t_tojson (vl_api_session_rules_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_rules_details");
    cJSON_AddStringToObject(o, "_crc", "4ef746e7");
    cJSON_AddItemToObject(o, "transport_proto", vl_api_transport_proto_t_tojson(a->transport_proto));
    cJSON_AddItemToObject(o, "lcl", vl_api_prefix_t_tojson(&a->lcl));
    cJSON_AddItemToObject(o, "rmt", vl_api_prefix_t_tojson(&a->rmt));
    cJSON_AddNumberToObject(o, "lcl_port", a->lcl_port);
    cJSON_AddNumberToObject(o, "rmt_port", a->rmt_port);
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    cJSON_AddItemToObject(o, "scope", vl_api_session_rule_scope_t_tojson(a->scope));
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_session_rules_v2_dump_t_tojson (vl_api_session_rules_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_rules_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_session_rules_v2_details_t_tojson (vl_api_session_rules_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_rules_v2_details");
    cJSON_AddStringToObject(o, "_crc", "f91993dc");
    cJSON_AddItemToObject(o, "transport_proto", vl_api_transport_proto_t_tojson(a->transport_proto));
    cJSON_AddItemToObject(o, "lcl", vl_api_prefix_t_tojson(&a->lcl));
    cJSON_AddItemToObject(o, "rmt", vl_api_prefix_t_tojson(&a->rmt));
    cJSON_AddNumberToObject(o, "lcl_port", a->lcl_port);
    cJSON_AddNumberToObject(o, "rmt_port", a->rmt_port);
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddItemToObject(o, "scope", vl_api_session_rule_scope_t_tojson(a->scope));
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "appns_index");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->appns_index[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_session_sdl_add_del_t_tojson (vl_api_session_sdl_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_add_del");
    cJSON_AddStringToObject(o, "_crc", "faeb89fc");
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_sdl_rule_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_session_sdl_add_del_reply_t_tojson (vl_api_session_sdl_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_session_sdl_add_del_v2_t_tojson (vl_api_session_sdl_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "7f89d3fa");
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "r");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_sdl_rule_v2_t_tojson(&a->r[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_session_sdl_add_del_v2_reply_t_tojson (vl_api_session_sdl_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_session_sdl_dump_t_tojson (vl_api_session_sdl_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_session_sdl_details_t_tojson (vl_api_session_sdl_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_details");
    cJSON_AddStringToObject(o, "_crc", "9a8ef5d0");
    cJSON_AddItemToObject(o, "lcl", vl_api_prefix_t_tojson(&a->lcl));
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_session_sdl_v2_dump_t_tojson (vl_api_session_sdl_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_session_sdl_v2_details_t_tojson (vl_api_session_sdl_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_v2_details");
    cJSON_AddStringToObject(o, "_crc", "0a057683");
    cJSON_AddItemToObject(o, "rmt", vl_api_prefix_t_tojson(&a->rmt));
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddNumberToObject(o, "appns_index", a->appns_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    return o;
}
static inline cJSON *vl_api_session_sdl_v3_dump_t_tojson (vl_api_session_sdl_v3_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_v3_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_session_sdl_v3_details_t_tojson (vl_api_session_sdl_v3_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "session_sdl_v3_details");
    cJSON_AddStringToObject(o, "_crc", "829e367f");
    cJSON_AddItemToObject(o, "rmt", vl_api_prefix_t_tojson(&a->rmt));
    cJSON_AddNumberToObject(o, "action_index", a->action_index);
    cJSON_AddStringToObject(o, "tag", (char *)a->tag);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "appns_index");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->appns_index[i]));
        }
    }
    return o;
}
#endif
