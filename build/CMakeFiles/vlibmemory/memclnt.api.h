/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: memclnt.api
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
#warning no content included from memclnt.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_MEMCLNT_CREATE, vl_api_memclnt_create_t_handler)
vl_msg_id(VL_API_MEMCLNT_CREATE_REPLY, vl_api_memclnt_create_reply_t_handler)
vl_msg_id(VL_API_MEMCLNT_DELETE, vl_api_memclnt_delete_t_handler)
vl_msg_id(VL_API_MEMCLNT_DELETE_REPLY, vl_api_memclnt_delete_reply_t_handler)
vl_msg_id(VL_API_RX_THREAD_EXIT, vl_api_rx_thread_exit_t_handler)
vl_msg_id(VL_API_MEMCLNT_RX_THREAD_SUSPEND, vl_api_memclnt_rx_thread_suspend_t_handler)
vl_msg_id(VL_API_MEMCLNT_READ_TIMEOUT, vl_api_memclnt_read_timeout_t_handler)
vl_msg_id(VL_API_RPC_CALL, vl_api_rpc_call_t_handler)
vl_msg_id(VL_API_RPC_CALL_REPLY, vl_api_rpc_call_reply_t_handler)
vl_msg_id(VL_API_GET_FIRST_MSG_ID, vl_api_get_first_msg_id_t_handler)
vl_msg_id(VL_API_GET_FIRST_MSG_ID_REPLY, vl_api_get_first_msg_id_reply_t_handler)
vl_msg_id(VL_API_API_VERSIONS, vl_api_api_versions_t_handler)
vl_msg_id(VL_API_API_VERSIONS_REPLY, vl_api_api_versions_reply_t_handler)
vl_msg_id(VL_API_TRACE_PLUGIN_MSG_IDS, vl_api_trace_plugin_msg_ids_t_handler)
vl_msg_id(VL_API_SOCKCLNT_CREATE, vl_api_sockclnt_create_t_handler)
vl_msg_id(VL_API_SOCKCLNT_CREATE_REPLY, vl_api_sockclnt_create_reply_t_handler)
vl_msg_id(VL_API_SOCKCLNT_DELETE, vl_api_sockclnt_delete_t_handler)
vl_msg_id(VL_API_SOCKCLNT_DELETE_REPLY, vl_api_sockclnt_delete_reply_t_handler)
vl_msg_id(VL_API_SOCK_INIT_SHM, vl_api_sock_init_shm_t_handler)
vl_msg_id(VL_API_SOCK_INIT_SHM_REPLY, vl_api_sock_init_shm_reply_t_handler)
vl_msg_id(VL_API_MEMCLNT_KEEPALIVE, vl_api_memclnt_keepalive_t_handler)
vl_msg_id(VL_API_MEMCLNT_KEEPALIVE_REPLY, vl_api_memclnt_keepalive_reply_t_handler)
vl_msg_id(VL_API_CONTROL_PING, vl_api_control_ping_t_handler)
vl_msg_id(VL_API_CONTROL_PING_REPLY, vl_api_control_ping_reply_t_handler)
vl_msg_id(VL_API_MEMCLNT_CREATE_V2, vl_api_memclnt_create_v2_t_handler)
vl_msg_id(VL_API_MEMCLNT_CREATE_V2_REPLY, vl_api_memclnt_create_v2_reply_t_handler)
vl_msg_id(VL_API_GET_API_JSON, vl_api_get_api_json_t_handler)
vl_msg_id(VL_API_GET_API_JSON_REPLY, vl_api_get_api_json_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_memclnt_create_t, 1)
vl_msg_name(vl_api_memclnt_create_reply_t, 1)
vl_msg_name(vl_api_memclnt_delete_t, 1)
vl_msg_name(vl_api_memclnt_delete_reply_t, 1)
vl_msg_name(vl_api_rx_thread_exit_t, 1)
vl_msg_name(vl_api_memclnt_rx_thread_suspend_t, 1)
vl_msg_name(vl_api_memclnt_read_timeout_t, 1)
vl_msg_name(vl_api_rpc_call_t, 1)
vl_msg_name(vl_api_rpc_call_reply_t, 1)
vl_msg_name(vl_api_get_first_msg_id_t, 1)
vl_msg_name(vl_api_get_first_msg_id_reply_t, 1)
vl_msg_name(vl_api_api_versions_t, 1)
vl_msg_name(vl_api_api_versions_reply_t, 1)
vl_msg_name(vl_api_trace_plugin_msg_ids_t, 1)
vl_msg_name(vl_api_sockclnt_create_t, 1)
vl_msg_name(vl_api_sockclnt_create_reply_t, 1)
vl_msg_name(vl_api_sockclnt_delete_t, 1)
vl_msg_name(vl_api_sockclnt_delete_reply_t, 1)
vl_msg_name(vl_api_sock_init_shm_t, 1)
vl_msg_name(vl_api_sock_init_shm_reply_t, 1)
vl_msg_name(vl_api_memclnt_keepalive_t, 1)
vl_msg_name(vl_api_memclnt_keepalive_reply_t, 1)
vl_msg_name(vl_api_control_ping_t, 1)
vl_msg_name(vl_api_control_ping_reply_t, 1)
vl_msg_name(vl_api_memclnt_create_v2_t, 1)
vl_msg_name(vl_api_memclnt_create_v2_reply_t, 1)
vl_msg_name(vl_api_get_api_json_t, 1)
vl_msg_name(vl_api_get_api_json_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_memclnt \
_(VL_API_MEMCLNT_CREATE, memclnt_create, 9c5e1c2f) \
_(VL_API_MEMCLNT_CREATE_REPLY, memclnt_create_reply, 42ec4560) \
_(VL_API_MEMCLNT_DELETE, memclnt_delete, 7e1c04e3) \
_(VL_API_MEMCLNT_DELETE_REPLY, memclnt_delete_reply, 3d3b6312) \
_(VL_API_RX_THREAD_EXIT, rx_thread_exit, c3a3a452) \
_(VL_API_MEMCLNT_RX_THREAD_SUSPEND, memclnt_rx_thread_suspend, c3a3a452) \
_(VL_API_MEMCLNT_READ_TIMEOUT, memclnt_read_timeout, c3a3a452) \
_(VL_API_RPC_CALL, rpc_call, 7e8a2c95) \
_(VL_API_RPC_CALL_REPLY, rpc_call_reply, e8d4e804) \
_(VL_API_GET_FIRST_MSG_ID, get_first_msg_id, ebf79a66) \
_(VL_API_GET_FIRST_MSG_ID_REPLY, get_first_msg_id_reply, 7d337472) \
_(VL_API_API_VERSIONS, api_versions, 51077d14) \
_(VL_API_API_VERSIONS_REPLY, api_versions_reply, 5f0d99d6) \
_(VL_API_TRACE_PLUGIN_MSG_IDS, trace_plugin_msg_ids, f476d3ce) \
_(VL_API_SOCKCLNT_CREATE, sockclnt_create, 455fb9c4) \
_(VL_API_SOCKCLNT_CREATE_REPLY, sockclnt_create_reply, 35166268) \
_(VL_API_SOCKCLNT_DELETE, sockclnt_delete, 8ac76db6) \
_(VL_API_SOCKCLNT_DELETE_REPLY, sockclnt_delete_reply, 8f38b1ee) \
_(VL_API_SOCK_INIT_SHM, sock_init_shm, 51646d92) \
_(VL_API_SOCK_INIT_SHM_REPLY, sock_init_shm_reply, e8d4e804) \
_(VL_API_MEMCLNT_KEEPALIVE, memclnt_keepalive, 51077d14) \
_(VL_API_MEMCLNT_KEEPALIVE_REPLY, memclnt_keepalive_reply, e8d4e804) \
_(VL_API_CONTROL_PING, control_ping, 51077d14) \
_(VL_API_CONTROL_PING_REPLY, control_ping_reply, f6b0b8ca) \
_(VL_API_MEMCLNT_CREATE_V2, memclnt_create_v2, c4bd4882) \
_(VL_API_MEMCLNT_CREATE_V2_REPLY, memclnt_create_v2_reply, 42ec4560) \
_(VL_API_GET_API_JSON, get_api_json, 51077d14) \
_(VL_API_GET_API_JSON_REPLY, get_api_json_reply, ea715b59) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "memclnt.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_memclnt_printfun_types
#define included_memclnt_printfun_types

static inline u8 *format_vl_api_module_version_t (u8 *s, va_list * args)
{
    vl_api_module_version_t *a = va_arg (*args, vl_api_module_version_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Umajor: %u", format_white_space, indent, a->major);
    s = format(s, "\n%Uminor: %u", format_white_space, indent, a->minor);
    s = format(s, "\n%Upatch: %u", format_white_space, indent, a->patch);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    return s;
}

static inline u8 *format_vl_api_message_table_entry_t (u8 *s, va_list * args)
{
    vl_api_message_table_entry_t *a = va_arg (*args, vl_api_message_table_entry_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_memclnt_printfun
#define included_memclnt_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "memclnt.api_tojson.h"
#include "memclnt.api_fromjson.h"

static inline u8 *vl_api_memclnt_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_create_t *a = va_arg (*args, vl_api_memclnt_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_create_t: */
    s = format(s, "vl_api_memclnt_create_t:");
    s = format(s, "\n%Uctx_quota: %ld", format_white_space, indent, a->ctx_quota);
    s = format(s, "\n%Uinput_queue: %llu", format_white_space, indent, a->input_queue);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    for (i = 0; i < 8; i++) {
        s = format(s, "\n%Uapi_versions: %u",
                   format_white_space, indent, a->api_versions[i]);
    }
    return s;
}

static inline u8 *vl_api_memclnt_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_create_reply_t *a = va_arg (*args, vl_api_memclnt_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_create_reply_t: */
    s = format(s, "vl_api_memclnt_create_reply_t:");
    s = format(s, "\n%Uresponse: %ld", format_white_space, indent, a->response);
    s = format(s, "\n%Uhandle: %llu", format_white_space, indent, a->handle);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Umessage_table: %llu", format_white_space, indent, a->message_table);
    return s;
}

static inline u8 *vl_api_memclnt_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_delete_t *a = va_arg (*args, vl_api_memclnt_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_delete_t: */
    s = format(s, "vl_api_memclnt_delete_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uhandle: %llu", format_white_space, indent, a->handle);
    s = format(s, "\n%Udo_cleanup: %u", format_white_space, indent, a->do_cleanup);
    return s;
}

static inline u8 *vl_api_memclnt_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_delete_reply_t *a = va_arg (*args, vl_api_memclnt_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_delete_reply_t: */
    s = format(s, "vl_api_memclnt_delete_reply_t:");
    s = format(s, "\n%Uresponse: %ld", format_white_space, indent, a->response);
    s = format(s, "\n%Uhandle: %llu", format_white_space, indent, a->handle);
    return s;
}

static inline u8 *vl_api_rx_thread_exit_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_rx_thread_exit_t *a = va_arg (*args, vl_api_rx_thread_exit_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_rx_thread_exit_t: */
    s = format(s, "vl_api_rx_thread_exit_t:");
    s = format(s, "\n%Udummy: %u", format_white_space, indent, a->dummy);
    return s;
}

static inline u8 *vl_api_memclnt_rx_thread_suspend_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_rx_thread_suspend_t *a = va_arg (*args, vl_api_memclnt_rx_thread_suspend_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_rx_thread_suspend_t: */
    s = format(s, "vl_api_memclnt_rx_thread_suspend_t:");
    s = format(s, "\n%Udummy: %u", format_white_space, indent, a->dummy);
    return s;
}

static inline u8 *vl_api_memclnt_read_timeout_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_read_timeout_t *a = va_arg (*args, vl_api_memclnt_read_timeout_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_read_timeout_t: */
    s = format(s, "vl_api_memclnt_read_timeout_t:");
    s = format(s, "\n%Udummy: %u", format_white_space, indent, a->dummy);
    return s;
}

static inline u8 *vl_api_rpc_call_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_rpc_call_t *a = va_arg (*args, vl_api_rpc_call_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_rpc_call_t: */
    s = format(s, "vl_api_rpc_call_t:");
    s = format(s, "\n%Ufunction: %llu", format_white_space, indent, a->function);
    s = format(s, "\n%Umulticast: %u", format_white_space, indent, a->multicast);
    s = format(s, "\n%Uneed_barrier_sync: %u", format_white_space, indent, a->need_barrier_sync);
    s = format(s, "\n%Usend_reply: %u", format_white_space, indent, a->send_reply);
    s = format(s, "\n%Udata_len: %u", format_white_space, indent, a->data_len);
    s = format(s, "\n%Udata: %U", format_white_space, indent, format_hex_bytes, a->data, a->data_len);
    return s;
}

static inline u8 *vl_api_rpc_call_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_rpc_call_reply_t *a = va_arg (*args, vl_api_rpc_call_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_rpc_call_reply_t: */
    s = format(s, "vl_api_rpc_call_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_get_first_msg_id_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_first_msg_id_t *a = va_arg (*args, vl_api_get_first_msg_id_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_first_msg_id_t: */
    s = format(s, "vl_api_get_first_msg_id_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    return s;
}

static inline u8 *vl_api_get_first_msg_id_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_first_msg_id_reply_t *a = va_arg (*args, vl_api_get_first_msg_id_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_first_msg_id_reply_t: */
    s = format(s, "vl_api_get_first_msg_id_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ufirst_msg_id: %u", format_white_space, indent, a->first_msg_id);
    return s;
}

static inline u8 *vl_api_api_versions_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_api_versions_t *a = va_arg (*args, vl_api_api_versions_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_api_versions_t: */
    s = format(s, "vl_api_api_versions_t:");
    return s;
}

static inline u8 *vl_api_api_versions_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_api_versions_reply_t *a = va_arg (*args, vl_api_api_versions_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_api_versions_reply_t: */
    s = format(s, "vl_api_api_versions_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uapi_versions: %U",
                   format_white_space, indent, format_vl_api_module_version_t, &a->api_versions[i], indent);
    }
    return s;
}

static inline u8 *vl_api_trace_plugin_msg_ids_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_plugin_msg_ids_t *a = va_arg (*args, vl_api_trace_plugin_msg_ids_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_plugin_msg_ids_t: */
    s = format(s, "vl_api_trace_plugin_msg_ids_t:");
    s = format(s, "\n%Uplugin_name: %s", format_white_space, indent, a->plugin_name);
    s = format(s, "\n%Ufirst_msg_id: %u", format_white_space, indent, a->first_msg_id);
    s = format(s, "\n%Ulast_msg_id: %u", format_white_space, indent, a->last_msg_id);
    return s;
}

static inline u8 *vl_api_sockclnt_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sockclnt_create_t *a = va_arg (*args, vl_api_sockclnt_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sockclnt_create_t: */
    s = format(s, "vl_api_sockclnt_create_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    return s;
}

static inline u8 *vl_api_sockclnt_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sockclnt_create_reply_t *a = va_arg (*args, vl_api_sockclnt_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sockclnt_create_reply_t: */
    s = format(s, "vl_api_sockclnt_create_reply_t:");
    s = format(s, "\n%Uresponse: %ld", format_white_space, indent, a->response);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Umessage_table: %U",
                   format_white_space, indent, format_vl_api_message_table_entry_t, &a->message_table[i], indent);
    }
    return s;
}

static inline u8 *vl_api_sockclnt_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sockclnt_delete_t *a = va_arg (*args, vl_api_sockclnt_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sockclnt_delete_t: */
    s = format(s, "vl_api_sockclnt_delete_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    return s;
}

static inline u8 *vl_api_sockclnt_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sockclnt_delete_reply_t *a = va_arg (*args, vl_api_sockclnt_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sockclnt_delete_reply_t: */
    s = format(s, "vl_api_sockclnt_delete_reply_t:");
    s = format(s, "\n%Uresponse: %ld", format_white_space, indent, a->response);
    return s;
}

static inline u8 *vl_api_sock_init_shm_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sock_init_shm_t *a = va_arg (*args, vl_api_sock_init_shm_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sock_init_shm_t: */
    s = format(s, "vl_api_sock_init_shm_t:");
    s = format(s, "\n%Urequested_size: %u", format_white_space, indent, a->requested_size);
    s = format(s, "\n%Unitems: %u", format_white_space, indent, a->nitems);
    for (i = 0; i < a->nitems; i++) {
        s = format(s, "\n%Uconfigs: %llu",
                   format_white_space, indent, a->configs[i]);
    }
    return s;
}

static inline u8 *vl_api_sock_init_shm_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sock_init_shm_reply_t *a = va_arg (*args, vl_api_sock_init_shm_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sock_init_shm_reply_t: */
    s = format(s, "vl_api_sock_init_shm_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_memclnt_keepalive_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_keepalive_t *a = va_arg (*args, vl_api_memclnt_keepalive_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_keepalive_t: */
    s = format(s, "vl_api_memclnt_keepalive_t:");
    return s;
}

static inline u8 *vl_api_memclnt_keepalive_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_keepalive_reply_t *a = va_arg (*args, vl_api_memclnt_keepalive_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_keepalive_reply_t: */
    s = format(s, "vl_api_memclnt_keepalive_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_control_ping_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_control_ping_t *a = va_arg (*args, vl_api_control_ping_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_control_ping_t: */
    s = format(s, "vl_api_control_ping_t:");
    return s;
}

static inline u8 *vl_api_control_ping_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_control_ping_reply_t *a = va_arg (*args, vl_api_control_ping_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_control_ping_reply_t: */
    s = format(s, "vl_api_control_ping_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uvpe_pid: %u", format_white_space, indent, a->vpe_pid);
    return s;
}

static inline u8 *vl_api_memclnt_create_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_create_v2_t *a = va_arg (*args, vl_api_memclnt_create_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_create_v2_t: */
    s = format(s, "vl_api_memclnt_create_v2_t:");
    s = format(s, "\n%Uctx_quota: %ld", format_white_space, indent, a->ctx_quota);
    s = format(s, "\n%Uinput_queue: %llu", format_white_space, indent, a->input_queue);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    for (i = 0; i < 8; i++) {
        s = format(s, "\n%Uapi_versions: %u",
                   format_white_space, indent, a->api_versions[i]);
    }
    s = format(s, "\n%Ukeepalive: %u", format_white_space, indent, a->keepalive);
    return s;
}

static inline u8 *vl_api_memclnt_create_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_memclnt_create_v2_reply_t *a = va_arg (*args, vl_api_memclnt_create_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_memclnt_create_v2_reply_t: */
    s = format(s, "vl_api_memclnt_create_v2_reply_t:");
    s = format(s, "\n%Uresponse: %ld", format_white_space, indent, a->response);
    s = format(s, "\n%Uhandle: %llu", format_white_space, indent, a->handle);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Umessage_table: %llu", format_white_space, indent, a->message_table);
    return s;
}

static inline u8 *vl_api_get_api_json_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_api_json_t *a = va_arg (*args, vl_api_get_api_json_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_api_json_t: */
    s = format(s, "vl_api_get_api_json_t:");
    return s;
}

static inline u8 *vl_api_get_api_json_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_api_json_reply_t *a = va_arg (*args, vl_api_get_api_json_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_api_json_reply_t: */
    s = format(s, "vl_api_get_api_json_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->json) > 0) {
        s = format(s, "\n%Ujson: %U", format_white_space, indent, vl_api_format_string, (&a->json));
    } else {
        s = format(s, "\n%Ujson:", format_white_space, indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_memclnt_endianfun
#define included_memclnt_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_module_version_t_endian (vl_api_module_version_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->major = clib_net_to_host_u32(a->major);
    a->minor = clib_net_to_host_u32(a->minor);
    a->patch = clib_net_to_host_u32(a->patch);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_message_table_entry_t_endian (vl_api_message_table_entry_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->index = clib_net_to_host_u16(a->index);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_memclnt_create_t_endian (vl_api_memclnt_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->ctx_quota = clib_net_to_host_i32(a->ctx_quota);
    a->input_queue = clib_net_to_host_u64(a->input_queue);
    /* a->name = a->name (no-op) */
    ASSERT((u32)8 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 8; i++) {
        a->api_versions[i] = clib_net_to_host_u32(a->api_versions[i]);
    }
}

static inline void vl_api_memclnt_create_reply_t_endian (vl_api_memclnt_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->response = clib_net_to_host_i32(a->response);
    a->handle = clib_net_to_host_u64(a->handle);
    a->index = clib_net_to_host_u32(a->index);
    a->message_table = clib_net_to_host_u64(a->message_table);
}

static inline void vl_api_memclnt_delete_t_endian (vl_api_memclnt_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->index = clib_net_to_host_u32(a->index);
    a->handle = clib_net_to_host_u64(a->handle);
    /* a->do_cleanup = a->do_cleanup (no-op) */
}

static inline void vl_api_memclnt_delete_reply_t_endian (vl_api_memclnt_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->response = clib_net_to_host_i32(a->response);
    a->handle = clib_net_to_host_u64(a->handle);
}

static inline void vl_api_rx_thread_exit_t_endian (vl_api_rx_thread_exit_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->dummy = a->dummy (no-op) */
}

static inline void vl_api_memclnt_rx_thread_suspend_t_endian (vl_api_memclnt_rx_thread_suspend_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->dummy = a->dummy (no-op) */
}

static inline void vl_api_memclnt_read_timeout_t_endian (vl_api_memclnt_read_timeout_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->dummy = a->dummy (no-op) */
}

static inline void vl_api_rpc_call_t_endian (vl_api_rpc_call_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->function = clib_net_to_host_u64(a->function);
    /* a->multicast = a->multicast (no-op) */
    /* a->need_barrier_sync = a->need_barrier_sync (no-op) */
    /* a->send_reply = a->send_reply (no-op) */
    a->data_len = clib_net_to_host_u32(a->data_len);
    /* a->data = a->data (no-op) */
}

static inline void vl_api_rpc_call_reply_t_endian (vl_api_rpc_call_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_get_first_msg_id_t_endian (vl_api_get_first_msg_id_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_get_first_msg_id_reply_t_endian (vl_api_get_first_msg_id_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->first_msg_id = clib_net_to_host_u16(a->first_msg_id);
}

static inline void vl_api_api_versions_t_endian (vl_api_api_versions_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_api_versions_reply_t_endian (vl_api_api_versions_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_module_version_t_endian(&a->api_versions[i], to_net);
    }
}

static inline void vl_api_trace_plugin_msg_ids_t_endian (vl_api_trace_plugin_msg_ids_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->plugin_name = a->plugin_name (no-op) */
    a->first_msg_id = clib_net_to_host_u16(a->first_msg_id);
    a->last_msg_id = clib_net_to_host_u16(a->last_msg_id);
}

static inline void vl_api_sockclnt_create_t_endian (vl_api_sockclnt_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_sockclnt_create_reply_t_endian (vl_api_sockclnt_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->response = clib_net_to_host_i32(a->response);
    a->index = clib_net_to_host_u32(a->index);
    a->count = clib_net_to_host_u16(a->count);
    u32 count = to_net ? clib_net_to_host_u16(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_message_table_entry_t_endian(&a->message_table[i], to_net);
    }
}

static inline void vl_api_sockclnt_delete_t_endian (vl_api_sockclnt_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
}

static inline void vl_api_sockclnt_delete_reply_t_endian (vl_api_sockclnt_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->response = clib_net_to_host_i32(a->response);
}

static inline void vl_api_sock_init_shm_t_endian (vl_api_sock_init_shm_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->requested_size = clib_net_to_host_u32(a->requested_size);
    /* a->nitems = a->nitems (no-op) */
    u32 count = a->nitems;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->configs[i] = clib_net_to_host_u64(a->configs[i]);
    }
}

static inline void vl_api_sock_init_shm_reply_t_endian (vl_api_sock_init_shm_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_memclnt_keepalive_t_endian (vl_api_memclnt_keepalive_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_memclnt_keepalive_reply_t_endian (vl_api_memclnt_keepalive_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_control_ping_t_endian (vl_api_control_ping_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_control_ping_reply_t_endian (vl_api_control_ping_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->client_index = a->client_index (no-op) */
    a->vpe_pid = clib_net_to_host_u32(a->vpe_pid);
}

static inline void vl_api_memclnt_create_v2_t_endian (vl_api_memclnt_create_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->ctx_quota = clib_net_to_host_i32(a->ctx_quota);
    a->input_queue = clib_net_to_host_u64(a->input_queue);
    /* a->name = a->name (no-op) */
    ASSERT((u32)8 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 8; i++) {
        a->api_versions[i] = clib_net_to_host_u32(a->api_versions[i]);
    }
    /* a->keepalive = a->keepalive (no-op) */
}

static inline void vl_api_memclnt_create_v2_reply_t_endian (vl_api_memclnt_create_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->response = clib_net_to_host_i32(a->response);
    a->handle = clib_net_to_host_u64(a->handle);
    a->index = clib_net_to_host_u32(a->index);
    a->message_table = clib_net_to_host_u64(a->message_table);
}

static inline void vl_api_get_api_json_t_endian (vl_api_get_api_json_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_get_api_json_reply_t_endian (vl_api_get_api_json_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->json = a->json (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_memclnt_calcsizefun
#define included_memclnt_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_module_version_t_calc_size (vl_api_module_version_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_message_table_entry_t_calc_size (vl_api_message_table_entry_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_create_t_calc_size (vl_api_memclnt_create_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_create_reply_t_calc_size (vl_api_memclnt_create_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_delete_t_calc_size (vl_api_memclnt_delete_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_delete_reply_t_calc_size (vl_api_memclnt_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_rx_thread_exit_t_calc_size (vl_api_rx_thread_exit_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_rx_thread_suspend_t_calc_size (vl_api_memclnt_rx_thread_suspend_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_read_timeout_t_calc_size (vl_api_memclnt_read_timeout_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_rpc_call_t_calc_size (vl_api_rpc_call_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->data_len) * sizeof(a->data[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_rpc_call_reply_t_calc_size (vl_api_rpc_call_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_first_msg_id_t_calc_size (vl_api_get_first_msg_id_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_first_msg_id_reply_t_calc_size (vl_api_get_first_msg_id_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_api_versions_t_calc_size (vl_api_api_versions_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_api_versions_reply_t_calc_size (vl_api_api_versions_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->api_versions[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_plugin_msg_ids_t_calc_size (vl_api_trace_plugin_msg_ids_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sockclnt_create_t_calc_size (vl_api_sockclnt_create_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sockclnt_create_reply_t_calc_size (vl_api_sockclnt_create_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u16(a->count) * sizeof(a->message_table[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sockclnt_delete_t_calc_size (vl_api_sockclnt_delete_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sockclnt_delete_reply_t_calc_size (vl_api_sockclnt_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sock_init_shm_t_calc_size (vl_api_sock_init_shm_t *a)
{
      return sizeof(*a) + a->nitems * sizeof(a->configs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sock_init_shm_reply_t_calc_size (vl_api_sock_init_shm_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_keepalive_t_calc_size (vl_api_memclnt_keepalive_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_keepalive_reply_t_calc_size (vl_api_memclnt_keepalive_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_control_ping_t_calc_size (vl_api_control_ping_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_control_ping_reply_t_calc_size (vl_api_control_ping_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_create_v2_t_calc_size (vl_api_memclnt_create_v2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_memclnt_create_v2_reply_t_calc_size (vl_api_memclnt_create_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_api_json_t_calc_size (vl_api_get_api_json_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_api_json_reply_t_calc_size (vl_api_get_api_json_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->json);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(memclnt.api, 2, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(memclnt.api, 0xb197c551)

#endif

