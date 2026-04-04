/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: graph.api
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
#warning no content included from graph.api
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
vl_msg_id(VL_API_GRAPH_NODE_GET, vl_api_graph_node_get_t_handler)
vl_msg_id(VL_API_GRAPH_NODE_GET_REPLY, vl_api_graph_node_get_reply_t_handler)
vl_msg_id(VL_API_GRAPH_NODE_DETAILS, vl_api_graph_node_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_graph_node_get_t, 1)
vl_msg_name(vl_api_graph_node_get_reply_t, 1)
vl_msg_name(vl_api_graph_node_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_graph \
_(VL_API_GRAPH_NODE_GET, graph_node_get, 39c8792e) \
_(VL_API_GRAPH_NODE_GET_REPLY, graph_node_get_reply, 53b48f5d) \
_(VL_API_GRAPH_NODE_DETAILS, graph_node_details, ac762018) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "graph.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_graph_printfun_types
#define included_graph_printfun_types

static inline u8 *format_vl_api_node_flag_t (u8 *s, va_list * args)
{
    vl_api_node_flag_t *a = va_arg (*args, vl_api_node_flag_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "NODE_FLAG_FRAME_NO_FREE_AFTER_DISPATCH");
    case 2:
        return format(s, "NODE_FLAG_IS_OUTPUT");
    case 4:
        return format(s, "NODE_FLAG_IS_DROP");
    case 8:
        return format(s, "NODE_FLAG_IS_PUNT");
    case 16:
        return format(s, "NODE_FLAG_IS_HANDOFF");
    case 32:
        return format(s, "NODE_FLAG_TRACE");
    case 64:
        return format(s, "NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE");
    case 128:
        return format(s, "NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE");
    case 256:
        return format(s, "NODE_FLAG_TRACE_SUPPORTED");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_graph_printfun
#define included_graph_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "graph.api_tojson.h"
#include "graph.api_fromjson.h"

static inline u8 *vl_api_graph_node_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_graph_node_get_t *a = va_arg (*args, vl_api_graph_node_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_graph_node_get_t: */
    s = format(s, "vl_api_graph_node_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_node_flag_t, &a->flags, indent);
    s = format(s, "\n%Uwant_arcs: %u", format_white_space, indent, a->want_arcs);
    return s;
}

static inline u8 *vl_api_graph_node_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_graph_node_get_reply_t *a = va_arg (*args, vl_api_graph_node_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_graph_node_get_reply_t: */
    s = format(s, "vl_api_graph_node_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_graph_node_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_graph_node_details_t *a = va_arg (*args, vl_api_graph_node_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_graph_node_details_t: */
    s = format(s, "vl_api_graph_node_details_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_node_flag_t, &a->flags, indent);
    s = format(s, "\n%Un_arcs: %u", format_white_space, indent, a->n_arcs);
    for (i = 0; i < a->n_arcs; i++) {
        s = format(s, "\n%Uarcs_out: %u",
                   format_white_space, indent, a->arcs_out[i]);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_graph_endianfun
#define included_graph_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_node_flag_t_endian (vl_api_node_flag_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_graph_node_get_t_endian (vl_api_graph_node_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
    a->index = clib_net_to_host_u32(a->index);
    /* a->name = a->name (no-op) */
    vl_api_node_flag_t_endian(&a->flags, to_net);
    /* a->want_arcs = a->want_arcs (no-op) */
}

static inline void vl_api_graph_node_get_reply_t_endian (vl_api_graph_node_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_graph_node_details_t_endian (vl_api_graph_node_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
    /* a->name = a->name (no-op) */
    vl_api_node_flag_t_endian(&a->flags, to_net);
    a->n_arcs = clib_net_to_host_u32(a->n_arcs);
    u32 count = to_net ? clib_net_to_host_u32(a->n_arcs) : a->n_arcs;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->arcs_out[i] = clib_net_to_host_u32(a->arcs_out[i]);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_graph_calcsizefun
#define included_graph_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_node_flag_t_calc_size (vl_api_node_flag_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_graph_node_get_t_calc_size (vl_api_graph_node_get_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_node_flag_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_graph_node_get_reply_t_calc_size (vl_api_graph_node_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_graph_node_details_t_calc_size (vl_api_graph_node_details_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_node_flag_t_calc_size(&a->flags) + clib_net_to_host_u32(a->n_arcs) * sizeof(a->arcs_out[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(graph.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(graph.api, 0xa0b3fd1c)

#endif

