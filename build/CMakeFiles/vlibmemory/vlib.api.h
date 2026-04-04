/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: vlib.api
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
#warning no content included from vlib.api
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
vl_msg_id(VL_API_CLI, vl_api_cli_t_handler)
vl_msg_id(VL_API_CLI_INBAND, vl_api_cli_inband_t_handler)
vl_msg_id(VL_API_CLI_REPLY, vl_api_cli_reply_t_handler)
vl_msg_id(VL_API_CLI_INBAND_REPLY, vl_api_cli_inband_reply_t_handler)
vl_msg_id(VL_API_GET_NODE_INDEX, vl_api_get_node_index_t_handler)
vl_msg_id(VL_API_GET_NODE_INDEX_REPLY, vl_api_get_node_index_reply_t_handler)
vl_msg_id(VL_API_ADD_NODE_NEXT, vl_api_add_node_next_t_handler)
vl_msg_id(VL_API_ADD_NODE_NEXT_REPLY, vl_api_add_node_next_reply_t_handler)
vl_msg_id(VL_API_SHOW_THREADS, vl_api_show_threads_t_handler)
vl_msg_id(VL_API_SHOW_THREADS_REPLY, vl_api_show_threads_reply_t_handler)
vl_msg_id(VL_API_GET_NODE_GRAPH, vl_api_get_node_graph_t_handler)
vl_msg_id(VL_API_GET_NODE_GRAPH_REPLY, vl_api_get_node_graph_reply_t_handler)
vl_msg_id(VL_API_GET_NEXT_INDEX, vl_api_get_next_index_t_handler)
vl_msg_id(VL_API_GET_NEXT_INDEX_REPLY, vl_api_get_next_index_reply_t_handler)
vl_msg_id(VL_API_GET_F64_ENDIAN_VALUE, vl_api_get_f64_endian_value_t_handler)
vl_msg_id(VL_API_GET_F64_ENDIAN_VALUE_REPLY, vl_api_get_f64_endian_value_reply_t_handler)
vl_msg_id(VL_API_GET_F64_INCREMENT_BY_ONE, vl_api_get_f64_increment_by_one_t_handler)
vl_msg_id(VL_API_GET_F64_INCREMENT_BY_ONE_REPLY, vl_api_get_f64_increment_by_one_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_cli_t, 1)
vl_msg_name(vl_api_cli_inband_t, 1)
vl_msg_name(vl_api_cli_reply_t, 1)
vl_msg_name(vl_api_cli_inband_reply_t, 1)
vl_msg_name(vl_api_get_node_index_t, 1)
vl_msg_name(vl_api_get_node_index_reply_t, 1)
vl_msg_name(vl_api_add_node_next_t, 1)
vl_msg_name(vl_api_add_node_next_reply_t, 1)
vl_msg_name(vl_api_show_threads_t, 1)
vl_msg_name(vl_api_show_threads_reply_t, 1)
vl_msg_name(vl_api_get_node_graph_t, 1)
vl_msg_name(vl_api_get_node_graph_reply_t, 1)
vl_msg_name(vl_api_get_next_index_t, 1)
vl_msg_name(vl_api_get_next_index_reply_t, 1)
vl_msg_name(vl_api_get_f64_endian_value_t, 1)
vl_msg_name(vl_api_get_f64_endian_value_reply_t, 1)
vl_msg_name(vl_api_get_f64_increment_by_one_t, 1)
vl_msg_name(vl_api_get_f64_increment_by_one_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vlib \
_(VL_API_CLI, cli, 23bfbfff) \
_(VL_API_CLI_INBAND, cli_inband, f8377302) \
_(VL_API_CLI_REPLY, cli_reply, 06d68297) \
_(VL_API_CLI_INBAND_REPLY, cli_inband_reply, 05879051) \
_(VL_API_GET_NODE_INDEX, get_node_index, f1984c64) \
_(VL_API_GET_NODE_INDEX_REPLY, get_node_index_reply, a8600b89) \
_(VL_API_ADD_NODE_NEXT, add_node_next, 2457116d) \
_(VL_API_ADD_NODE_NEXT_REPLY, add_node_next_reply, 2ed75f32) \
_(VL_API_SHOW_THREADS, show_threads, 51077d14) \
_(VL_API_SHOW_THREADS_REPLY, show_threads_reply, efd78e83) \
_(VL_API_GET_NODE_GRAPH, get_node_graph, 51077d14) \
_(VL_API_GET_NODE_GRAPH_REPLY, get_node_graph_reply, 06d68297) \
_(VL_API_GET_NEXT_INDEX, get_next_index, 2457116d) \
_(VL_API_GET_NEXT_INDEX_REPLY, get_next_index_reply, 2ed75f32) \
_(VL_API_GET_F64_ENDIAN_VALUE, get_f64_endian_value, 809fcd44) \
_(VL_API_GET_F64_ENDIAN_VALUE_REPLY, get_f64_endian_value_reply, 7e02e404) \
_(VL_API_GET_F64_INCREMENT_BY_ONE, get_f64_increment_by_one, b64f027e) \
_(VL_API_GET_F64_INCREMENT_BY_ONE_REPLY, get_f64_increment_by_one_reply, d25dbaa3) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vlib.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vlib_printfun_types
#define included_vlib_printfun_types

static inline u8 *format_vl_api_thread_data_t (u8 *s, va_list * args)
{
    vl_api_thread_data_t *a = va_arg (*args, vl_api_thread_data_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Utype: %s", format_white_space, indent, a->type);
    s = format(s, "\n%Upid: %u", format_white_space, indent, a->pid);
    s = format(s, "\n%Ucpu_id: %u", format_white_space, indent, a->cpu_id);
    s = format(s, "\n%Ucore: %u", format_white_space, indent, a->core);
    s = format(s, "\n%Ucpu_socket: %u", format_white_space, indent, a->cpu_socket);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vlib_printfun
#define included_vlib_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vlib.api_tojson.h"
#include "vlib.api_fromjson.h"

static inline u8 *vl_api_cli_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cli_t *a = va_arg (*args, vl_api_cli_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cli_t: */
    s = format(s, "vl_api_cli_t:");
    s = format(s, "\n%Ucmd_in_shmem: %llu", format_white_space, indent, a->cmd_in_shmem);
    return s;
}

static inline u8 *vl_api_cli_inband_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cli_inband_t *a = va_arg (*args, vl_api_cli_inband_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cli_inband_t: */
    s = format(s, "vl_api_cli_inband_t:");
    if (vl_api_string_len(&a->cmd) > 0) {
        s = format(s, "\n%Ucmd: %U", format_white_space, indent, vl_api_format_string, (&a->cmd));
    } else {
        s = format(s, "\n%Ucmd:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_cli_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cli_reply_t *a = va_arg (*args, vl_api_cli_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cli_reply_t: */
    s = format(s, "vl_api_cli_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ureply_in_shmem: %llu", format_white_space, indent, a->reply_in_shmem);
    return s;
}

static inline u8 *vl_api_cli_inband_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_cli_inband_reply_t *a = va_arg (*args, vl_api_cli_inband_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_cli_inband_reply_t: */
    s = format(s, "vl_api_cli_inband_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->reply) > 0) {
        s = format(s, "\n%Ureply: %U", format_white_space, indent, vl_api_format_string, (&a->reply));
    } else {
        s = format(s, "\n%Ureply:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_get_node_index_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_node_index_t *a = va_arg (*args, vl_api_get_node_index_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_node_index_t: */
    s = format(s, "vl_api_get_node_index_t:");
    s = format(s, "\n%Unode_name: %s", format_white_space, indent, a->node_name);
    return s;
}

static inline u8 *vl_api_get_node_index_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_node_index_reply_t *a = va_arg (*args, vl_api_get_node_index_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_node_index_reply_t: */
    s = format(s, "vl_api_get_node_index_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Unode_index: %u", format_white_space, indent, a->node_index);
    return s;
}

static inline u8 *vl_api_add_node_next_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_add_node_next_t *a = va_arg (*args, vl_api_add_node_next_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_add_node_next_t: */
    s = format(s, "vl_api_add_node_next_t:");
    s = format(s, "\n%Unode_name: %s", format_white_space, indent, a->node_name);
    s = format(s, "\n%Unext_name: %s", format_white_space, indent, a->next_name);
    return s;
}

static inline u8 *vl_api_add_node_next_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_add_node_next_reply_t *a = va_arg (*args, vl_api_add_node_next_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_add_node_next_reply_t: */
    s = format(s, "vl_api_add_node_next_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Unext_index: %u", format_white_space, indent, a->next_index);
    return s;
}

static inline u8 *vl_api_show_threads_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_threads_t *a = va_arg (*args, vl_api_show_threads_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_threads_t: */
    s = format(s, "vl_api_show_threads_t:");
    return s;
}

static inline u8 *vl_api_show_threads_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_threads_reply_t *a = va_arg (*args, vl_api_show_threads_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_threads_reply_t: */
    s = format(s, "vl_api_show_threads_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uthread_data: %U",
                   format_white_space, indent, format_vl_api_thread_data_t, &a->thread_data[i], indent);
    }
    return s;
}

static inline u8 *vl_api_get_node_graph_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_node_graph_t *a = va_arg (*args, vl_api_get_node_graph_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_node_graph_t: */
    s = format(s, "vl_api_get_node_graph_t:");
    return s;
}

static inline u8 *vl_api_get_node_graph_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_node_graph_reply_t *a = va_arg (*args, vl_api_get_node_graph_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_node_graph_reply_t: */
    s = format(s, "vl_api_get_node_graph_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ureply_in_shmem: %llu", format_white_space, indent, a->reply_in_shmem);
    return s;
}

static inline u8 *vl_api_get_next_index_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_next_index_t *a = va_arg (*args, vl_api_get_next_index_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_next_index_t: */
    s = format(s, "vl_api_get_next_index_t:");
    s = format(s, "\n%Unode_name: %s", format_white_space, indent, a->node_name);
    s = format(s, "\n%Unext_name: %s", format_white_space, indent, a->next_name);
    return s;
}

static inline u8 *vl_api_get_next_index_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_next_index_reply_t *a = va_arg (*args, vl_api_get_next_index_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_next_index_reply_t: */
    s = format(s, "vl_api_get_next_index_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Unext_index: %u", format_white_space, indent, a->next_index);
    return s;
}

static inline u8 *vl_api_get_f64_endian_value_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_f64_endian_value_t *a = va_arg (*args, vl_api_get_f64_endian_value_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_f64_endian_value_t: */
    s = format(s, "vl_api_get_f64_endian_value_t:");
    s = format(s, "\n%Uf64_one: %.2f", format_white_space, indent, a->f64_one);
    return s;
}

static inline u8 *vl_api_get_f64_endian_value_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_f64_endian_value_reply_t *a = va_arg (*args, vl_api_get_f64_endian_value_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_f64_endian_value_reply_t: */
    s = format(s, "vl_api_get_f64_endian_value_reply_t:");
    s = format(s, "\n%Uretval: %u", format_white_space, indent, a->retval);
    s = format(s, "\n%Uf64_one_result: %.2f", format_white_space, indent, a->f64_one_result);
    return s;
}

static inline u8 *vl_api_get_f64_increment_by_one_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_f64_increment_by_one_t *a = va_arg (*args, vl_api_get_f64_increment_by_one_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_f64_increment_by_one_t: */
    s = format(s, "vl_api_get_f64_increment_by_one_t:");
    s = format(s, "\n%Uf64_value: %.2f", format_white_space, indent, a->f64_value);
    return s;
}

static inline u8 *vl_api_get_f64_increment_by_one_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_get_f64_increment_by_one_reply_t *a = va_arg (*args, vl_api_get_f64_increment_by_one_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_get_f64_increment_by_one_reply_t: */
    s = format(s, "vl_api_get_f64_increment_by_one_reply_t:");
    s = format(s, "\n%Uretval: %u", format_white_space, indent, a->retval);
    s = format(s, "\n%Uf64_value: %.2f", format_white_space, indent, a->f64_value);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vlib_endianfun
#define included_vlib_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_thread_data_t_endian (vl_api_thread_data_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->id = clib_net_to_host_u32(a->id);
    /* a->name = a->name (no-op) */
    /* a->type = a->type (no-op) */
    a->pid = clib_net_to_host_u32(a->pid);
    a->cpu_id = clib_net_to_host_u32(a->cpu_id);
    a->core = clib_net_to_host_u32(a->core);
    a->cpu_socket = clib_net_to_host_u32(a->cpu_socket);
}

static inline void vl_api_cli_t_endian (vl_api_cli_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cmd_in_shmem = clib_net_to_host_u64(a->cmd_in_shmem);
}

static inline void vl_api_cli_inband_t_endian (vl_api_cli_inband_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->cmd = a->cmd (no-op) */
}

static inline void vl_api_cli_reply_t_endian (vl_api_cli_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->reply_in_shmem = clib_net_to_host_u64(a->reply_in_shmem);
}

static inline void vl_api_cli_inband_reply_t_endian (vl_api_cli_inband_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->reply = a->reply (no-op) */
}

static inline void vl_api_get_node_index_t_endian (vl_api_get_node_index_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->node_name = a->node_name (no-op) */
}

static inline void vl_api_get_node_index_reply_t_endian (vl_api_get_node_index_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->node_index = clib_net_to_host_u32(a->node_index);
}

static inline void vl_api_add_node_next_t_endian (vl_api_add_node_next_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->node_name = a->node_name (no-op) */
    /* a->next_name = a->next_name (no-op) */
}

static inline void vl_api_add_node_next_reply_t_endian (vl_api_add_node_next_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->next_index = clib_net_to_host_u32(a->next_index);
}

static inline void vl_api_show_threads_t_endian (vl_api_show_threads_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_threads_reply_t_endian (vl_api_show_threads_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_thread_data_t_endian(&a->thread_data[i], to_net);
    }
}

static inline void vl_api_get_node_graph_t_endian (vl_api_get_node_graph_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_get_node_graph_reply_t_endian (vl_api_get_node_graph_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->reply_in_shmem = clib_net_to_host_u64(a->reply_in_shmem);
}

static inline void vl_api_get_next_index_t_endian (vl_api_get_next_index_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->node_name = a->node_name (no-op) */
    /* a->next_name = a->next_name (no-op) */
}

static inline void vl_api_get_next_index_reply_t_endian (vl_api_get_next_index_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->next_index = clib_net_to_host_u32(a->next_index);
}

static inline void vl_api_get_f64_endian_value_t_endian (vl_api_get_f64_endian_value_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->f64_one = clib_net_to_host_f64(a->f64_one);
}

static inline void vl_api_get_f64_endian_value_reply_t_endian (vl_api_get_f64_endian_value_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_u32(a->retval);
    a->f64_one_result = clib_net_to_host_f64(a->f64_one_result);
}

static inline void vl_api_get_f64_increment_by_one_t_endian (vl_api_get_f64_increment_by_one_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->f64_value = clib_net_to_host_f64(a->f64_value);
}

static inline void vl_api_get_f64_increment_by_one_reply_t_endian (vl_api_get_f64_increment_by_one_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_u32(a->retval);
    a->f64_value = clib_net_to_host_f64(a->f64_value);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_vlib_calcsizefun
#define included_vlib_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_thread_data_t_calc_size (vl_api_thread_data_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cli_t_calc_size (vl_api_cli_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cli_inband_t_calc_size (vl_api_cli_inband_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->cmd);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cli_reply_t_calc_size (vl_api_cli_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_cli_inband_reply_t_calc_size (vl_api_cli_inband_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->reply);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_node_index_t_calc_size (vl_api_get_node_index_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_node_index_reply_t_calc_size (vl_api_get_node_index_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_add_node_next_t_calc_size (vl_api_add_node_next_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_add_node_next_reply_t_calc_size (vl_api_add_node_next_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_threads_t_calc_size (vl_api_show_threads_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_threads_reply_t_calc_size (vl_api_show_threads_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->thread_data[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_node_graph_t_calc_size (vl_api_get_node_graph_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_node_graph_reply_t_calc_size (vl_api_get_node_graph_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_next_index_t_calc_size (vl_api_get_next_index_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_next_index_reply_t_calc_size (vl_api_get_next_index_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_f64_endian_value_t_calc_size (vl_api_get_f64_endian_value_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_f64_endian_value_reply_t_calc_size (vl_api_get_f64_endian_value_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_f64_increment_by_one_t_calc_size (vl_api_get_f64_increment_by_one_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_get_f64_increment_by_one_reply_t_calc_size (vl_api_get_f64_increment_by_one_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vlib.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vlib.api, 0x9a9e84e4)

#endif

