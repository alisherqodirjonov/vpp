/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: session.api
 * Automatically generated: please edit the input file NOT this file!
 */

#include <stdbool.h>
#if defined(vl_msg_id)||defined(vl_union_id) \
    || defined(vl_printfun) ||defined(vl_endianfun) \
    || defined(vl_api_version)||defined(vl_typedefs) \
    || defined(vl_msg_name)||defined(vl_msg_name_crc_list) \
    || defined(vl_api_version_tuple) || defined(vl_calcsizefun)
/* ok, something was selected */
#else
#warning no content included from session.api
#endif

#define VL_API_PACKED(x) x __attribute__ ((packed))

/*
 * Note: VL_API_MAX_ARRAY_SIZE is set to an arbitrarily large limit.
 *
 * However, any message with a ~2 billion element array is likely to break the
 * api handling long before this limit causes array element endian issues.
 *
 * Applications should be written to create reasonable api messages.
 */
#define VL_API_MAX_ARRAY_SIZE 0x7fffffff

/* Imported API files */
#ifndef vl_api_version
#include <vnet/interface_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_APP_ATTACH, vl_api_app_attach_t_handler)
vl_msg_id(VL_API_APP_ATTACH_REPLY, vl_api_app_attach_reply_t_handler)
vl_msg_id(VL_API_APPLICATION_DETACH, vl_api_application_detach_t_handler)
vl_msg_id(VL_API_APPLICATION_DETACH_REPLY, vl_api_application_detach_reply_t_handler)
vl_msg_id(VL_API_APP_ADD_CERT_KEY_PAIR, vl_api_app_add_cert_key_pair_t_handler)
vl_msg_id(VL_API_APP_ADD_CERT_KEY_PAIR_REPLY, vl_api_app_add_cert_key_pair_reply_t_handler)
vl_msg_id(VL_API_APP_DEL_CERT_KEY_PAIR, vl_api_app_del_cert_key_pair_t_handler)
vl_msg_id(VL_API_APP_DEL_CERT_KEY_PAIR_REPLY, vl_api_app_del_cert_key_pair_reply_t_handler)
vl_msg_id(VL_API_APP_WORKER_ADD_DEL, vl_api_app_worker_add_del_t_handler)
vl_msg_id(VL_API_APP_WORKER_ADD_DEL_REPLY, vl_api_app_worker_add_del_reply_t_handler)
vl_msg_id(VL_API_SESSION_ENABLE_DISABLE, vl_api_session_enable_disable_t_handler)
vl_msg_id(VL_API_SESSION_ENABLE_DISABLE_REPLY, vl_api_session_enable_disable_reply_t_handler)
vl_msg_id(VL_API_SESSION_ENABLE_DISABLE_V2, vl_api_session_enable_disable_v2_t_handler)
vl_msg_id(VL_API_SESSION_ENABLE_DISABLE_V2_REPLY, vl_api_session_enable_disable_v2_reply_t_handler)
vl_msg_id(VL_API_SESSION_SAPI_ENABLE_DISABLE, vl_api_session_sapi_enable_disable_t_handler)
vl_msg_id(VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY, vl_api_session_sapi_enable_disable_reply_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL, vl_api_app_namespace_add_del_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_V4, vl_api_app_namespace_add_del_v4_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY, vl_api_app_namespace_add_del_v4_reply_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_V2, vl_api_app_namespace_add_del_v2_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_V3, vl_api_app_namespace_add_del_v3_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_REPLY, vl_api_app_namespace_add_del_reply_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY, vl_api_app_namespace_add_del_v2_reply_t_handler)
vl_msg_id(VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY, vl_api_app_namespace_add_del_v3_reply_t_handler)
vl_msg_id(VL_API_SESSION_RULE_ADD_DEL, vl_api_session_rule_add_del_t_handler)
vl_msg_id(VL_API_SESSION_RULE_ADD_DEL_REPLY, vl_api_session_rule_add_del_reply_t_handler)
vl_msg_id(VL_API_SESSION_RULES_DUMP, vl_api_session_rules_dump_t_handler)
vl_msg_id(VL_API_SESSION_RULES_DETAILS, vl_api_session_rules_details_t_handler)
vl_msg_id(VL_API_SESSION_RULES_V2_DUMP, vl_api_session_rules_v2_dump_t_handler)
vl_msg_id(VL_API_SESSION_RULES_V2_DETAILS, vl_api_session_rules_v2_details_t_handler)
vl_msg_id(VL_API_SESSION_SDL_ADD_DEL, vl_api_session_sdl_add_del_t_handler)
vl_msg_id(VL_API_SESSION_SDL_ADD_DEL_REPLY, vl_api_session_sdl_add_del_reply_t_handler)
vl_msg_id(VL_API_SESSION_SDL_ADD_DEL_V2, vl_api_session_sdl_add_del_v2_t_handler)
vl_msg_id(VL_API_SESSION_SDL_ADD_DEL_V2_REPLY, vl_api_session_sdl_add_del_v2_reply_t_handler)
vl_msg_id(VL_API_SESSION_SDL_DUMP, vl_api_session_sdl_dump_t_handler)
vl_msg_id(VL_API_SESSION_SDL_DETAILS, vl_api_session_sdl_details_t_handler)
vl_msg_id(VL_API_SESSION_SDL_V2_DUMP, vl_api_session_sdl_v2_dump_t_handler)
vl_msg_id(VL_API_SESSION_SDL_V2_DETAILS, vl_api_session_sdl_v2_details_t_handler)
vl_msg_id(VL_API_SESSION_SDL_V3_DUMP, vl_api_session_sdl_v3_dump_t_handler)
vl_msg_id(VL_API_SESSION_SDL_V3_DETAILS, vl_api_session_sdl_v3_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_app_attach_t, 1)
vl_msg_name(vl_api_app_attach_reply_t, 1)
vl_msg_name(vl_api_application_detach_t, 1)
vl_msg_name(vl_api_application_detach_reply_t, 1)
vl_msg_name(vl_api_app_add_cert_key_pair_t, 1)
vl_msg_name(vl_api_app_add_cert_key_pair_reply_t, 1)
vl_msg_name(vl_api_app_del_cert_key_pair_t, 1)
vl_msg_name(vl_api_app_del_cert_key_pair_reply_t, 1)
vl_msg_name(vl_api_app_worker_add_del_t, 1)
vl_msg_name(vl_api_app_worker_add_del_reply_t, 1)
vl_msg_name(vl_api_session_enable_disable_t, 1)
vl_msg_name(vl_api_session_enable_disable_reply_t, 1)
vl_msg_name(vl_api_session_enable_disable_v2_t, 1)
vl_msg_name(vl_api_session_enable_disable_v2_reply_t, 1)
vl_msg_name(vl_api_session_sapi_enable_disable_t, 1)
vl_msg_name(vl_api_session_sapi_enable_disable_reply_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_v4_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_v4_reply_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_v2_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_v3_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_reply_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_v2_reply_t, 1)
vl_msg_name(vl_api_app_namespace_add_del_v3_reply_t, 1)
vl_msg_name(vl_api_session_rule_add_del_t, 1)
vl_msg_name(vl_api_session_rule_add_del_reply_t, 1)
vl_msg_name(vl_api_session_rules_dump_t, 1)
vl_msg_name(vl_api_session_rules_details_t, 1)
vl_msg_name(vl_api_session_rules_v2_dump_t, 1)
vl_msg_name(vl_api_session_rules_v2_details_t, 1)
vl_msg_name(vl_api_session_sdl_add_del_t, 1)
vl_msg_name(vl_api_session_sdl_add_del_reply_t, 1)
vl_msg_name(vl_api_session_sdl_add_del_v2_t, 1)
vl_msg_name(vl_api_session_sdl_add_del_v2_reply_t, 1)
vl_msg_name(vl_api_session_sdl_dump_t, 1)
vl_msg_name(vl_api_session_sdl_details_t, 1)
vl_msg_name(vl_api_session_sdl_v2_dump_t, 1)
vl_msg_name(vl_api_session_sdl_v2_details_t, 1)
vl_msg_name(vl_api_session_sdl_v3_dump_t, 1)
vl_msg_name(vl_api_session_sdl_v3_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_session \
_(VL_API_APP_ATTACH, app_attach, 5f4a260d) \
_(VL_API_APP_ATTACH_REPLY, app_attach_reply, 5c89c3b0) \
_(VL_API_APPLICATION_DETACH, application_detach, 51077d14) \
_(VL_API_APPLICATION_DETACH_REPLY, application_detach_reply, e8d4e804) \
_(VL_API_APP_ADD_CERT_KEY_PAIR, app_add_cert_key_pair, 02eb8016) \
_(VL_API_APP_ADD_CERT_KEY_PAIR_REPLY, app_add_cert_key_pair_reply, b42958d0) \
_(VL_API_APP_DEL_CERT_KEY_PAIR, app_del_cert_key_pair, 8ac76db6) \
_(VL_API_APP_DEL_CERT_KEY_PAIR_REPLY, app_del_cert_key_pair_reply, e8d4e804) \
_(VL_API_APP_WORKER_ADD_DEL, app_worker_add_del, 753253dc) \
_(VL_API_APP_WORKER_ADD_DEL_REPLY, app_worker_add_del_reply, 5735ffe7) \
_(VL_API_SESSION_ENABLE_DISABLE, session_enable_disable, c264d7bf) \
_(VL_API_SESSION_ENABLE_DISABLE_REPLY, session_enable_disable_reply, e8d4e804) \
_(VL_API_SESSION_ENABLE_DISABLE_V2, session_enable_disable_v2, f09fbf32) \
_(VL_API_SESSION_ENABLE_DISABLE_V2_REPLY, session_enable_disable_v2_reply, e8d4e804) \
_(VL_API_SESSION_SAPI_ENABLE_DISABLE, session_sapi_enable_disable, c264d7bf) \
_(VL_API_SESSION_SAPI_ENABLE_DISABLE_REPLY, session_sapi_enable_disable_reply, e8d4e804) \
_(VL_API_APP_NAMESPACE_ADD_DEL, app_namespace_add_del, 6306aecb) \
_(VL_API_APP_NAMESPACE_ADD_DEL_V4, app_namespace_add_del_v4, 42c1d824) \
_(VL_API_APP_NAMESPACE_ADD_DEL_V4_REPLY, app_namespace_add_del_v4_reply, 85137120) \
_(VL_API_APP_NAMESPACE_ADD_DEL_V2, app_namespace_add_del_v2, ee0755cf) \
_(VL_API_APP_NAMESPACE_ADD_DEL_V3, app_namespace_add_del_v3, 8a7e40a1) \
_(VL_API_APP_NAMESPACE_ADD_DEL_REPLY, app_namespace_add_del_reply, 85137120) \
_(VL_API_APP_NAMESPACE_ADD_DEL_V2_REPLY, app_namespace_add_del_v2_reply, 85137120) \
_(VL_API_APP_NAMESPACE_ADD_DEL_V3_REPLY, app_namespace_add_del_v3_reply, 85137120) \
_(VL_API_SESSION_RULE_ADD_DEL, session_rule_add_del, 82a90af5) \
_(VL_API_SESSION_RULE_ADD_DEL_REPLY, session_rule_add_del_reply, e8d4e804) \
_(VL_API_SESSION_RULES_DUMP, session_rules_dump, 51077d14) \
_(VL_API_SESSION_RULES_DETAILS, session_rules_details, 4ef746e7) \
_(VL_API_SESSION_RULES_V2_DUMP, session_rules_v2_dump, 51077d14) \
_(VL_API_SESSION_RULES_V2_DETAILS, session_rules_v2_details, f91993dc) \
_(VL_API_SESSION_SDL_ADD_DEL, session_sdl_add_del, faeb89fc) \
_(VL_API_SESSION_SDL_ADD_DEL_REPLY, session_sdl_add_del_reply, e8d4e804) \
_(VL_API_SESSION_SDL_ADD_DEL_V2, session_sdl_add_del_v2, 7f89d3fa) \
_(VL_API_SESSION_SDL_ADD_DEL_V2_REPLY, session_sdl_add_del_v2_reply, e8d4e804) \
_(VL_API_SESSION_SDL_DUMP, session_sdl_dump, 51077d14) \
_(VL_API_SESSION_SDL_DETAILS, session_sdl_details, 9a8ef5d0) \
_(VL_API_SESSION_SDL_V2_DUMP, session_sdl_v2_dump, 51077d14) \
_(VL_API_SESSION_SDL_V2_DETAILS, session_sdl_v2_details, 0a057683) \
_(VL_API_SESSION_SDL_V3_DUMP, session_sdl_v3_dump, 51077d14) \
_(VL_API_SESSION_SDL_V3_DETAILS, session_sdl_v3_details, 829e367f) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "session.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_session_printfun_types
#define included_session_printfun_types

static inline u8 *format_vl_api_sdl_rule_t (u8 *s, va_list * args)
{
    vl_api_sdl_rule_t *a = va_arg (*args, vl_api_sdl_rule_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ulcl: %U", format_white_space, indent, format_vl_api_prefix_t, &a->lcl, indent);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *format_vl_api_sdl_rule_v2_t (u8 *s, va_list * args)
{
    vl_api_sdl_rule_v2_t *a = va_arg (*args, vl_api_sdl_rule_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Urmt: %U", format_white_space, indent, format_vl_api_prefix_t, &a->rmt, indent);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *format_vl_api_transport_proto_t (u8 *s, va_list * args)
{
    vl_api_transport_proto_t *a = va_arg (*args, vl_api_transport_proto_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "TRANSPORT_PROTO_API_TCP");
    case 1:
        return format(s, "TRANSPORT_PROTO_API_UDP");
    case 2:
        return format(s, "TRANSPORT_PROTO_API_NONE");
    case 3:
        return format(s, "TRANSPORT_PROTO_API_TLS");
    case 4:
        return format(s, "TRANSPORT_PROTO_API_QUIC");
    }
    return s;
}

static inline u8 *format_vl_api_rt_backend_engine_t (u8 *s, va_list * args)
{
    vl_api_rt_backend_engine_t *a = va_arg (*args, vl_api_rt_backend_engine_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "RT_BACKEND_ENGINE_API_DISABLE");
    case 1:
        return format(s, "RT_BACKEND_ENGINE_API_RULE_TABLE");
    case 2:
        return format(s, "RT_BACKEND_ENGINE_API_NONE");
    case 3:
        return format(s, "RT_BACKEND_ENGINE_API_SDL");
    }
    return s;
}

static inline u8 *format_vl_api_session_rule_scope_t (u8 *s, va_list * args)
{
    vl_api_session_rule_scope_t *a = va_arg (*args, vl_api_session_rule_scope_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "SESSION_RULE_SCOPE_API_GLOBAL");
    case 1:
        return format(s, "SESSION_RULE_SCOPE_API_LOCAL");
    case 2:
        return format(s, "SESSION_RULE_SCOPE_API_BOTH");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_session_printfun
#define included_session_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "session.api_tojson.h"
#include "session.api_fromjson.h"

static inline u8 *vl_api_app_attach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_attach_t *a = va_arg (*args, vl_api_app_attach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_attach_t: */
    s = format(s, "vl_api_app_attach_t:");
    for (i = 0; i < 18; i++) {
        s = format(s, "\n%Uoptions: %llu",
                   format_white_space, indent, a->options[i]);
    }
    if (vl_api_string_len(&a->namespace_id) > 0) {
        s = format(s, "\n%Unamespace_id: %U", format_white_space, indent, vl_api_format_string, (&a->namespace_id));
    } else {
        s = format(s, "\n%Unamespace_id:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_app_attach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_attach_reply_t *a = va_arg (*args, vl_api_app_attach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_attach_reply_t: */
    s = format(s, "vl_api_app_attach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uapp_mq: %llu", format_white_space, indent, a->app_mq);
    s = format(s, "\n%Uvpp_ctrl_mq: %llu", format_white_space, indent, a->vpp_ctrl_mq);
    s = format(s, "\n%Uvpp_ctrl_mq_thread: %u", format_white_space, indent, a->vpp_ctrl_mq_thread);
    s = format(s, "\n%Uapp_index: %u", format_white_space, indent, a->app_index);
    s = format(s, "\n%Un_fds: %u", format_white_space, indent, a->n_fds);
    s = format(s, "\n%Ufd_flags: %u", format_white_space, indent, a->fd_flags);
    s = format(s, "\n%Usegment_size: %u", format_white_space, indent, a->segment_size);
    s = format(s, "\n%Usegment_handle: %llu", format_white_space, indent, a->segment_handle);
    if (vl_api_string_len(&a->segment_name) > 0) {
        s = format(s, "\n%Usegment_name: %U", format_white_space, indent, vl_api_format_string, (&a->segment_name));
    } else {
        s = format(s, "\n%Usegment_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_application_detach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_application_detach_t *a = va_arg (*args, vl_api_application_detach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_application_detach_t: */
    s = format(s, "vl_api_application_detach_t:");
    return s;
}

static inline u8 *vl_api_application_detach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_application_detach_reply_t *a = va_arg (*args, vl_api_application_detach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_application_detach_reply_t: */
    s = format(s, "vl_api_application_detach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_app_add_cert_key_pair_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_add_cert_key_pair_t *a = va_arg (*args, vl_api_app_add_cert_key_pair_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_add_cert_key_pair_t: */
    s = format(s, "vl_api_app_add_cert_key_pair_t:");
    s = format(s, "\n%Ucert_len: %u", format_white_space, indent, a->cert_len);
    s = format(s, "\n%Ucertkey_len: %u", format_white_space, indent, a->certkey_len);
    s = format(s, "\n%Ucertkey: %U", format_white_space, indent, format_hex_bytes, a->certkey, a->certkey_len);
    return s;
}

static inline u8 *vl_api_app_add_cert_key_pair_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_add_cert_key_pair_reply_t *a = va_arg (*args, vl_api_app_add_cert_key_pair_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_add_cert_key_pair_reply_t: */
    s = format(s, "vl_api_app_add_cert_key_pair_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    return s;
}

static inline u8 *vl_api_app_del_cert_key_pair_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_del_cert_key_pair_t *a = va_arg (*args, vl_api_app_del_cert_key_pair_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_del_cert_key_pair_t: */
    s = format(s, "vl_api_app_del_cert_key_pair_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    return s;
}

static inline u8 *vl_api_app_del_cert_key_pair_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_del_cert_key_pair_reply_t *a = va_arg (*args, vl_api_app_del_cert_key_pair_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_del_cert_key_pair_reply_t: */
    s = format(s, "vl_api_app_del_cert_key_pair_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_app_worker_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_worker_add_del_t *a = va_arg (*args, vl_api_app_worker_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_worker_add_del_t: */
    s = format(s, "vl_api_app_worker_add_del_t:");
    s = format(s, "\n%Uapp_index: %u", format_white_space, indent, a->app_index);
    s = format(s, "\n%Uwrk_index: %u", format_white_space, indent, a->wrk_index);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    return s;
}

static inline u8 *vl_api_app_worker_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_worker_add_del_reply_t *a = va_arg (*args, vl_api_app_worker_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_worker_add_del_reply_t: */
    s = format(s, "vl_api_app_worker_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uwrk_index: %u", format_white_space, indent, a->wrk_index);
    s = format(s, "\n%Uapp_event_queue_address: %llu", format_white_space, indent, a->app_event_queue_address);
    s = format(s, "\n%Un_fds: %u", format_white_space, indent, a->n_fds);
    s = format(s, "\n%Ufd_flags: %u", format_white_space, indent, a->fd_flags);
    s = format(s, "\n%Usegment_handle: %llu", format_white_space, indent, a->segment_handle);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    if (vl_api_string_len(&a->segment_name) > 0) {
        s = format(s, "\n%Usegment_name: %U", format_white_space, indent, vl_api_format_string, (&a->segment_name));
    } else {
        s = format(s, "\n%Usegment_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_session_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_enable_disable_t *a = va_arg (*args, vl_api_session_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_enable_disable_t: */
    s = format(s, "vl_api_session_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_session_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_enable_disable_reply_t *a = va_arg (*args, vl_api_session_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_enable_disable_reply_t: */
    s = format(s, "vl_api_session_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_session_enable_disable_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_enable_disable_v2_t *a = va_arg (*args, vl_api_session_enable_disable_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_enable_disable_v2_t: */
    s = format(s, "vl_api_session_enable_disable_v2_t:");
    s = format(s, "\n%Urt_engine_type: %U", format_white_space, indent, format_vl_api_rt_backend_engine_t, &a->rt_engine_type, indent);
    return s;
}

static inline u8 *vl_api_session_enable_disable_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_enable_disable_v2_reply_t *a = va_arg (*args, vl_api_session_enable_disable_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_enable_disable_v2_reply_t: */
    s = format(s, "vl_api_session_enable_disable_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_session_sapi_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sapi_enable_disable_t *a = va_arg (*args, vl_api_session_sapi_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sapi_enable_disable_t: */
    s = format(s, "vl_api_session_sapi_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_session_sapi_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sapi_enable_disable_reply_t *a = va_arg (*args, vl_api_session_sapi_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sapi_enable_disable_reply_t: */
    s = format(s, "vl_api_session_sapi_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_t *a = va_arg (*args, vl_api_app_namespace_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_t: */
    s = format(s, "vl_api_app_namespace_add_del_t:");
    s = format(s, "\n%Usecret: %llu", format_white_space, indent, a->secret);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uip4_fib_id: %u", format_white_space, indent, a->ip4_fib_id);
    s = format(s, "\n%Uip6_fib_id: %u", format_white_space, indent, a->ip6_fib_id);
    if (vl_api_string_len(&a->namespace_id) > 0) {
        s = format(s, "\n%Unamespace_id: %U", format_white_space, indent, vl_api_format_string, (&a->namespace_id));
    } else {
        s = format(s, "\n%Unamespace_id:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_v4_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_v4_t *a = va_arg (*args, vl_api_app_namespace_add_del_v4_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_v4_t: */
    s = format(s, "vl_api_app_namespace_add_del_v4_t:");
    s = format(s, "\n%Usecret: %llu", format_white_space, indent, a->secret);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uip4_fib_id: %u", format_white_space, indent, a->ip4_fib_id);
    s = format(s, "\n%Uip6_fib_id: %u", format_white_space, indent, a->ip6_fib_id);
    s = format(s, "\n%Unamespace_id: %s", format_white_space, indent, a->namespace_id);
    if (vl_api_string_len(&a->sock_name) > 0) {
        s = format(s, "\n%Usock_name: %U", format_white_space, indent, vl_api_format_string, (&a->sock_name));
    } else {
        s = format(s, "\n%Usock_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_v4_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_v4_reply_t *a = va_arg (*args, vl_api_app_namespace_add_del_v4_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_v4_reply_t: */
    s = format(s, "vl_api_app_namespace_add_del_v4_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_v2_t *a = va_arg (*args, vl_api_app_namespace_add_del_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_v2_t: */
    s = format(s, "vl_api_app_namespace_add_del_v2_t:");
    s = format(s, "\n%Usecret: %llu", format_white_space, indent, a->secret);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uip4_fib_id: %u", format_white_space, indent, a->ip4_fib_id);
    s = format(s, "\n%Uip6_fib_id: %u", format_white_space, indent, a->ip6_fib_id);
    s = format(s, "\n%Unamespace_id: %s", format_white_space, indent, a->namespace_id);
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_v3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_v3_t *a = va_arg (*args, vl_api_app_namespace_add_del_v3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_v3_t: */
    s = format(s, "vl_api_app_namespace_add_del_v3_t:");
    s = format(s, "\n%Usecret: %llu", format_white_space, indent, a->secret);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uip4_fib_id: %u", format_white_space, indent, a->ip4_fib_id);
    s = format(s, "\n%Uip6_fib_id: %u", format_white_space, indent, a->ip6_fib_id);
    s = format(s, "\n%Unamespace_id: %s", format_white_space, indent, a->namespace_id);
    s = format(s, "\n%Unetns: %s", format_white_space, indent, a->netns);
    if (vl_api_string_len(&a->sock_name) > 0) {
        s = format(s, "\n%Usock_name: %U", format_white_space, indent, vl_api_format_string, (&a->sock_name));
    } else {
        s = format(s, "\n%Usock_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_reply_t *a = va_arg (*args, vl_api_app_namespace_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_reply_t: */
    s = format(s, "vl_api_app_namespace_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_v2_reply_t *a = va_arg (*args, vl_api_app_namespace_add_del_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_v2_reply_t: */
    s = format(s, "vl_api_app_namespace_add_del_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    return s;
}

static inline u8 *vl_api_app_namespace_add_del_v3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_app_namespace_add_del_v3_reply_t *a = va_arg (*args, vl_api_app_namespace_add_del_v3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_app_namespace_add_del_v3_reply_t: */
    s = format(s, "vl_api_app_namespace_add_del_v3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    return s;
}

static inline u8 *vl_api_session_rule_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_rule_add_del_t *a = va_arg (*args, vl_api_session_rule_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_rule_add_del_t: */
    s = format(s, "vl_api_session_rule_add_del_t:");
    s = format(s, "\n%Utransport_proto: %U", format_white_space, indent, format_vl_api_transport_proto_t, &a->transport_proto, indent);
    s = format(s, "\n%Ulcl: %U", format_white_space, indent, format_vl_api_prefix_t, &a->lcl, indent);
    s = format(s, "\n%Urmt: %U", format_white_space, indent, format_vl_api_prefix_t, &a->rmt, indent);
    s = format(s, "\n%Ulcl_port: %u", format_white_space, indent, a->lcl_port);
    s = format(s, "\n%Urmt_port: %u", format_white_space, indent, a->rmt_port);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    s = format(s, "\n%Uscope: %U", format_white_space, indent, format_vl_api_session_rule_scope_t, &a->scope, indent);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_session_rule_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_rule_add_del_reply_t *a = va_arg (*args, vl_api_session_rule_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_rule_add_del_reply_t: */
    s = format(s, "vl_api_session_rule_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_session_rules_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_rules_dump_t *a = va_arg (*args, vl_api_session_rules_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_rules_dump_t: */
    s = format(s, "vl_api_session_rules_dump_t:");
    return s;
}

static inline u8 *vl_api_session_rules_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_rules_details_t *a = va_arg (*args, vl_api_session_rules_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_rules_details_t: */
    s = format(s, "vl_api_session_rules_details_t:");
    s = format(s, "\n%Utransport_proto: %U", format_white_space, indent, format_vl_api_transport_proto_t, &a->transport_proto, indent);
    s = format(s, "\n%Ulcl: %U", format_white_space, indent, format_vl_api_prefix_t, &a->lcl, indent);
    s = format(s, "\n%Urmt: %U", format_white_space, indent, format_vl_api_prefix_t, &a->rmt, indent);
    s = format(s, "\n%Ulcl_port: %u", format_white_space, indent, a->lcl_port);
    s = format(s, "\n%Urmt_port: %u", format_white_space, indent, a->rmt_port);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    s = format(s, "\n%Uscope: %U", format_white_space, indent, format_vl_api_session_rule_scope_t, &a->scope, indent);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_session_rules_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_rules_v2_dump_t *a = va_arg (*args, vl_api_session_rules_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_rules_v2_dump_t: */
    s = format(s, "vl_api_session_rules_v2_dump_t:");
    return s;
}

static inline u8 *vl_api_session_rules_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_rules_v2_details_t *a = va_arg (*args, vl_api_session_rules_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_rules_v2_details_t: */
    s = format(s, "vl_api_session_rules_v2_details_t:");
    s = format(s, "\n%Utransport_proto: %U", format_white_space, indent, format_vl_api_transport_proto_t, &a->transport_proto, indent);
    s = format(s, "\n%Ulcl: %U", format_white_space, indent, format_vl_api_prefix_t, &a->lcl, indent);
    s = format(s, "\n%Urmt: %U", format_white_space, indent, format_vl_api_prefix_t, &a->rmt, indent);
    s = format(s, "\n%Ulcl_port: %u", format_white_space, indent, a->lcl_port);
    s = format(s, "\n%Urmt_port: %u", format_white_space, indent, a->rmt_port);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Uscope: %U", format_white_space, indent, format_vl_api_session_rule_scope_t, &a->scope, indent);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uappns_index: %u",
                   format_white_space, indent, a->appns_index[i]);
    }
    return s;
}

static inline u8 *vl_api_session_sdl_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_add_del_t *a = va_arg (*args, vl_api_session_sdl_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_add_del_t: */
    s = format(s, "vl_api_session_sdl_add_del_t:");
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_sdl_rule_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_session_sdl_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_add_del_reply_t *a = va_arg (*args, vl_api_session_sdl_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_add_del_reply_t: */
    s = format(s, "vl_api_session_sdl_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_session_sdl_add_del_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_add_del_v2_t *a = va_arg (*args, vl_api_session_sdl_add_del_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_add_del_v2_t: */
    s = format(s, "vl_api_session_sdl_add_del_v2_t:");
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Ur: %U",
                   format_white_space, indent, format_vl_api_sdl_rule_v2_t, &a->r[i], indent);
    }
    return s;
}

static inline u8 *vl_api_session_sdl_add_del_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_add_del_v2_reply_t *a = va_arg (*args, vl_api_session_sdl_add_del_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_add_del_v2_reply_t: */
    s = format(s, "vl_api_session_sdl_add_del_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_session_sdl_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_dump_t *a = va_arg (*args, vl_api_session_sdl_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_dump_t: */
    s = format(s, "vl_api_session_sdl_dump_t:");
    return s;
}

static inline u8 *vl_api_session_sdl_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_details_t *a = va_arg (*args, vl_api_session_sdl_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_details_t: */
    s = format(s, "vl_api_session_sdl_details_t:");
    s = format(s, "\n%Ulcl: %U", format_white_space, indent, format_vl_api_prefix_t, &a->lcl, indent);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_session_sdl_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_v2_dump_t *a = va_arg (*args, vl_api_session_sdl_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_v2_dump_t: */
    s = format(s, "vl_api_session_sdl_v2_dump_t:");
    return s;
}

static inline u8 *vl_api_session_sdl_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_v2_details_t *a = va_arg (*args, vl_api_session_sdl_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_v2_details_t: */
    s = format(s, "vl_api_session_sdl_v2_details_t:");
    s = format(s, "\n%Urmt: %U", format_white_space, indent, format_vl_api_prefix_t, &a->rmt, indent);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Uappns_index: %u", format_white_space, indent, a->appns_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_session_sdl_v3_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_v3_dump_t *a = va_arg (*args, vl_api_session_sdl_v3_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_v3_dump_t: */
    s = format(s, "vl_api_session_sdl_v3_dump_t:");
    return s;
}

static inline u8 *vl_api_session_sdl_v3_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_session_sdl_v3_details_t *a = va_arg (*args, vl_api_session_sdl_v3_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_session_sdl_v3_details_t: */
    s = format(s, "vl_api_session_sdl_v3_details_t:");
    s = format(s, "\n%Urmt: %U", format_white_space, indent, format_vl_api_prefix_t, &a->rmt, indent);
    s = format(s, "\n%Uaction_index: %u", format_white_space, indent, a->action_index);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uappns_index: %u",
                   format_white_space, indent, a->appns_index[i]);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_session_endianfun
#define included_session_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_sdl_rule_t_endian (vl_api_sdl_rule_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_prefix_t_endian(&a->lcl, to_net);
    a->action_index = clib_net_to_host_u32(a->action_index);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_sdl_rule_v2_t_endian (vl_api_sdl_rule_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_prefix_t_endian(&a->rmt, to_net);
    a->action_index = clib_net_to_host_u32(a->action_index);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_transport_proto_t_endian (vl_api_transport_proto_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->transport_proto = a->transport_proto (no-op) */
}

static inline void vl_api_rt_backend_engine_t_endian (vl_api_rt_backend_engine_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->rt_backend_engine = a->rt_backend_engine (no-op) */
}

static inline void vl_api_session_rule_scope_t_endian (vl_api_session_rule_scope_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_app_attach_t_endian (vl_api_app_attach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    ASSERT((u32)18 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 18; i++) {
        a->options[i] = clib_net_to_host_u64(a->options[i]);
    }
    /* a->namespace_id = a->namespace_id (no-op) */
}

static inline void vl_api_app_attach_reply_t_endian (vl_api_app_attach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->app_mq = clib_net_to_host_u64(a->app_mq);
    a->vpp_ctrl_mq = clib_net_to_host_u64(a->vpp_ctrl_mq);
    /* a->vpp_ctrl_mq_thread = a->vpp_ctrl_mq_thread (no-op) */
    a->app_index = clib_net_to_host_u32(a->app_index);
    /* a->n_fds = a->n_fds (no-op) */
    /* a->fd_flags = a->fd_flags (no-op) */
    a->segment_size = clib_net_to_host_u32(a->segment_size);
    a->segment_handle = clib_net_to_host_u64(a->segment_handle);
    /* a->segment_name = a->segment_name (no-op) */
}

static inline void vl_api_application_detach_t_endian (vl_api_application_detach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_application_detach_reply_t_endian (vl_api_application_detach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_app_add_cert_key_pair_t_endian (vl_api_app_add_cert_key_pair_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cert_len = clib_net_to_host_u16(a->cert_len);
    a->certkey_len = clib_net_to_host_u16(a->certkey_len);
    /* a->certkey = a->certkey (no-op) */
}

static inline void vl_api_app_add_cert_key_pair_reply_t_endian (vl_api_app_add_cert_key_pair_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->index = clib_net_to_host_u32(a->index);
}

static inline void vl_api_app_del_cert_key_pair_t_endian (vl_api_app_del_cert_key_pair_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
}

static inline void vl_api_app_del_cert_key_pair_reply_t_endian (vl_api_app_del_cert_key_pair_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_app_worker_add_del_t_endian (vl_api_app_worker_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->app_index = clib_net_to_host_u32(a->app_index);
    a->wrk_index = clib_net_to_host_u32(a->wrk_index);
    /* a->is_add = a->is_add (no-op) */
}

static inline void vl_api_app_worker_add_del_reply_t_endian (vl_api_app_worker_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->wrk_index = clib_net_to_host_u32(a->wrk_index);
    a->app_event_queue_address = clib_net_to_host_u64(a->app_event_queue_address);
    /* a->n_fds = a->n_fds (no-op) */
    /* a->fd_flags = a->fd_flags (no-op) */
    a->segment_handle = clib_net_to_host_u64(a->segment_handle);
    /* a->is_add = a->is_add (no-op) */
    /* a->segment_name = a->segment_name (no-op) */
}

static inline void vl_api_session_enable_disable_t_endian (vl_api_session_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_session_enable_disable_reply_t_endian (vl_api_session_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_session_enable_disable_v2_t_endian (vl_api_session_enable_disable_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_rt_backend_engine_t_endian(&a->rt_engine_type, to_net);
}

static inline void vl_api_session_enable_disable_v2_reply_t_endian (vl_api_session_enable_disable_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_session_sapi_enable_disable_t_endian (vl_api_session_sapi_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_session_sapi_enable_disable_reply_t_endian (vl_api_session_sapi_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_app_namespace_add_del_t_endian (vl_api_app_namespace_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->secret = clib_net_to_host_u64(a->secret);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->ip4_fib_id = clib_net_to_host_u32(a->ip4_fib_id);
    a->ip6_fib_id = clib_net_to_host_u32(a->ip6_fib_id);
    /* a->namespace_id = a->namespace_id (no-op) */
}

static inline void vl_api_app_namespace_add_del_v4_t_endian (vl_api_app_namespace_add_del_v4_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->secret = clib_net_to_host_u64(a->secret);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->ip4_fib_id = clib_net_to_host_u32(a->ip4_fib_id);
    a->ip6_fib_id = clib_net_to_host_u32(a->ip6_fib_id);
    /* a->namespace_id = a->namespace_id (no-op) */
    /* a->sock_name = a->sock_name (no-op) */
}

static inline void vl_api_app_namespace_add_del_v4_reply_t_endian (vl_api_app_namespace_add_del_v4_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
}

static inline void vl_api_app_namespace_add_del_v2_t_endian (vl_api_app_namespace_add_del_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->secret = clib_net_to_host_u64(a->secret);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->ip4_fib_id = clib_net_to_host_u32(a->ip4_fib_id);
    a->ip6_fib_id = clib_net_to_host_u32(a->ip6_fib_id);
    /* a->namespace_id = a->namespace_id (no-op) */
    /* a->netns = a->netns (no-op) */
}

static inline void vl_api_app_namespace_add_del_v3_t_endian (vl_api_app_namespace_add_del_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->secret = clib_net_to_host_u64(a->secret);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->ip4_fib_id = clib_net_to_host_u32(a->ip4_fib_id);
    a->ip6_fib_id = clib_net_to_host_u32(a->ip6_fib_id);
    /* a->namespace_id = a->namespace_id (no-op) */
    /* a->netns = a->netns (no-op) */
    /* a->sock_name = a->sock_name (no-op) */
}

static inline void vl_api_app_namespace_add_del_reply_t_endian (vl_api_app_namespace_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
}

static inline void vl_api_app_namespace_add_del_v2_reply_t_endian (vl_api_app_namespace_add_del_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
}

static inline void vl_api_app_namespace_add_del_v3_reply_t_endian (vl_api_app_namespace_add_del_v3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
}

static inline void vl_api_session_rule_add_del_t_endian (vl_api_session_rule_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_transport_proto_t_endian(&a->transport_proto, to_net);
    vl_api_prefix_t_endian(&a->lcl, to_net);
    vl_api_prefix_t_endian(&a->rmt, to_net);
    a->lcl_port = clib_net_to_host_u16(a->lcl_port);
    a->rmt_port = clib_net_to_host_u16(a->rmt_port);
    a->action_index = clib_net_to_host_u32(a->action_index);
    /* a->is_add = a->is_add (no-op) */
    a->appns_index = clib_net_to_host_u32(a->appns_index);
    vl_api_session_rule_scope_t_endian(&a->scope, to_net);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_session_rule_add_del_reply_t_endian (vl_api_session_rule_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_session_rules_dump_t_endian (vl_api_session_rules_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_session_rules_details_t_endian (vl_api_session_rules_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_transport_proto_t_endian(&a->transport_proto, to_net);
    vl_api_prefix_t_endian(&a->lcl, to_net);
    vl_api_prefix_t_endian(&a->rmt, to_net);
    a->lcl_port = clib_net_to_host_u16(a->lcl_port);
    a->rmt_port = clib_net_to_host_u16(a->rmt_port);
    a->action_index = clib_net_to_host_u32(a->action_index);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
    vl_api_session_rule_scope_t_endian(&a->scope, to_net);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_session_rules_v2_dump_t_endian (vl_api_session_rules_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_session_rules_v2_details_t_endian (vl_api_session_rules_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_transport_proto_t_endian(&a->transport_proto, to_net);
    vl_api_prefix_t_endian(&a->lcl, to_net);
    vl_api_prefix_t_endian(&a->rmt, to_net);
    a->lcl_port = clib_net_to_host_u16(a->lcl_port);
    a->rmt_port = clib_net_to_host_u16(a->rmt_port);
    a->action_index = clib_net_to_host_u32(a->action_index);
    vl_api_session_rule_scope_t_endian(&a->scope, to_net);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->appns_index[i] = clib_net_to_host_u32(a->appns_index[i]);
    }
}

static inline void vl_api_session_sdl_add_del_t_endian (vl_api_session_sdl_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
    /* a->is_add = a->is_add (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_sdl_rule_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_session_sdl_add_del_reply_t_endian (vl_api_session_sdl_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_session_sdl_add_del_v2_t_endian (vl_api_session_sdl_add_del_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
    /* a->is_add = a->is_add (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_sdl_rule_v2_t_endian(&a->r[i], to_net);
    }
}

static inline void vl_api_session_sdl_add_del_v2_reply_t_endian (vl_api_session_sdl_add_del_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_session_sdl_dump_t_endian (vl_api_session_sdl_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_session_sdl_details_t_endian (vl_api_session_sdl_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_prefix_t_endian(&a->lcl, to_net);
    a->action_index = clib_net_to_host_u32(a->action_index);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_session_sdl_v2_dump_t_endian (vl_api_session_sdl_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_session_sdl_v2_details_t_endian (vl_api_session_sdl_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_prefix_t_endian(&a->rmt, to_net);
    a->action_index = clib_net_to_host_u32(a->action_index);
    a->appns_index = clib_net_to_host_u32(a->appns_index);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_session_sdl_v3_dump_t_endian (vl_api_session_sdl_v3_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_session_sdl_v3_details_t_endian (vl_api_session_sdl_v3_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_prefix_t_endian(&a->rmt, to_net);
    a->action_index = clib_net_to_host_u32(a->action_index);
    /* a->tag = a->tag (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->appns_index[i] = clib_net_to_host_u32(a->appns_index[i]);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_session_calcsizefun
#define included_session_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_sdl_rule_t_calc_size (vl_api_sdl_rule_t *a)
{
      return sizeof(*a) - sizeof(a->lcl) + vl_api_prefix_t_calc_size(&a->lcl);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sdl_rule_v2_t_calc_size (vl_api_sdl_rule_v2_t *a)
{
      return sizeof(*a) - sizeof(a->rmt) + vl_api_prefix_t_calc_size(&a->rmt);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_transport_proto_t_calc_size (vl_api_transport_proto_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_rt_backend_engine_t_calc_size (vl_api_rt_backend_engine_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rule_scope_t_calc_size (vl_api_session_rule_scope_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_attach_t_calc_size (vl_api_app_attach_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->namespace_id);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_attach_reply_t_calc_size (vl_api_app_attach_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->segment_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_application_detach_t_calc_size (vl_api_application_detach_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_application_detach_reply_t_calc_size (vl_api_application_detach_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_add_cert_key_pair_t_calc_size (vl_api_app_add_cert_key_pair_t *a)
{
      return sizeof(*a) + clib_net_to_host_u16(a->certkey_len) * sizeof(a->certkey[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_add_cert_key_pair_reply_t_calc_size (vl_api_app_add_cert_key_pair_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_del_cert_key_pair_t_calc_size (vl_api_app_del_cert_key_pair_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_del_cert_key_pair_reply_t_calc_size (vl_api_app_del_cert_key_pair_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_worker_add_del_t_calc_size (vl_api_app_worker_add_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_worker_add_del_reply_t_calc_size (vl_api_app_worker_add_del_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->segment_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_enable_disable_t_calc_size (vl_api_session_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_enable_disable_reply_t_calc_size (vl_api_session_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_enable_disable_v2_t_calc_size (vl_api_session_enable_disable_v2_t *a)
{
      return sizeof(*a) - sizeof(a->rt_engine_type) + vl_api_rt_backend_engine_t_calc_size(&a->rt_engine_type);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_enable_disable_v2_reply_t_calc_size (vl_api_session_enable_disable_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sapi_enable_disable_t_calc_size (vl_api_session_sapi_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sapi_enable_disable_reply_t_calc_size (vl_api_session_sapi_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_t_calc_size (vl_api_app_namespace_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + vl_api_string_len(&a->namespace_id);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_v4_t_calc_size (vl_api_app_namespace_add_del_v4_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + vl_api_string_len(&a->sock_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_v4_reply_t_calc_size (vl_api_app_namespace_add_del_v4_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_v2_t_calc_size (vl_api_app_namespace_add_del_v2_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_v3_t_calc_size (vl_api_app_namespace_add_del_v3_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) + vl_api_string_len(&a->sock_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_reply_t_calc_size (vl_api_app_namespace_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_v2_reply_t_calc_size (vl_api_app_namespace_add_del_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_app_namespace_add_del_v3_reply_t_calc_size (vl_api_app_namespace_add_del_v3_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rule_add_del_t_calc_size (vl_api_session_rule_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->transport_proto) + vl_api_transport_proto_t_calc_size(&a->transport_proto) - sizeof(a->lcl) + vl_api_prefix_t_calc_size(&a->lcl) - sizeof(a->rmt) + vl_api_prefix_t_calc_size(&a->rmt) - sizeof(a->scope) + vl_api_session_rule_scope_t_calc_size(&a->scope);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rule_add_del_reply_t_calc_size (vl_api_session_rule_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rules_dump_t_calc_size (vl_api_session_rules_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rules_details_t_calc_size (vl_api_session_rules_details_t *a)
{
      return sizeof(*a) - sizeof(a->transport_proto) + vl_api_transport_proto_t_calc_size(&a->transport_proto) - sizeof(a->lcl) + vl_api_prefix_t_calc_size(&a->lcl) - sizeof(a->rmt) + vl_api_prefix_t_calc_size(&a->rmt) - sizeof(a->scope) + vl_api_session_rule_scope_t_calc_size(&a->scope);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rules_v2_dump_t_calc_size (vl_api_session_rules_v2_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_rules_v2_details_t_calc_size (vl_api_session_rules_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->transport_proto) + vl_api_transport_proto_t_calc_size(&a->transport_proto) - sizeof(a->lcl) + vl_api_prefix_t_calc_size(&a->lcl) - sizeof(a->rmt) + vl_api_prefix_t_calc_size(&a->rmt) - sizeof(a->scope) + vl_api_session_rule_scope_t_calc_size(&a->scope) + clib_net_to_host_u32(a->count) * sizeof(a->appns_index[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_add_del_t_calc_size (vl_api_session_sdl_add_del_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_add_del_reply_t_calc_size (vl_api_session_sdl_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_add_del_v2_t_calc_size (vl_api_session_sdl_add_del_v2_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->r[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_add_del_v2_reply_t_calc_size (vl_api_session_sdl_add_del_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_dump_t_calc_size (vl_api_session_sdl_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_details_t_calc_size (vl_api_session_sdl_details_t *a)
{
      return sizeof(*a) - sizeof(a->lcl) + vl_api_prefix_t_calc_size(&a->lcl);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_v2_dump_t_calc_size (vl_api_session_sdl_v2_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_v2_details_t_calc_size (vl_api_session_sdl_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->rmt) + vl_api_prefix_t_calc_size(&a->rmt);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_v3_dump_t_calc_size (vl_api_session_sdl_v3_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_session_sdl_v3_details_t_calc_size (vl_api_session_sdl_v3_details_t *a)
{
      return sizeof(*a) - sizeof(a->rmt) + vl_api_prefix_t_calc_size(&a->rmt) + clib_net_to_host_u32(a->count) * sizeof(a->appns_index[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(session.api, 4, 0, 3)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(session.api, 0xaf947b64)

#endif

