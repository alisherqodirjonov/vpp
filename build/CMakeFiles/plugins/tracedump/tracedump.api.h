/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: tracedump.api
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
#warning no content included from tracedump.api
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
vl_msg_id(VL_API_TRACE_SET_FILTERS, vl_api_trace_set_filters_t_handler)
vl_msg_id(VL_API_TRACE_SET_FILTERS_REPLY, vl_api_trace_set_filters_reply_t_handler)
vl_msg_id(VL_API_TRACE_CAPTURE_PACKETS, vl_api_trace_capture_packets_t_handler)
vl_msg_id(VL_API_TRACE_CAPTURE_PACKETS_REPLY, vl_api_trace_capture_packets_reply_t_handler)
vl_msg_id(VL_API_TRACE_CLEAR_CAPTURE, vl_api_trace_clear_capture_t_handler)
vl_msg_id(VL_API_TRACE_CLEAR_CAPTURE_REPLY, vl_api_trace_clear_capture_reply_t_handler)
vl_msg_id(VL_API_TRACE_DUMP, vl_api_trace_dump_t_handler)
vl_msg_id(VL_API_TRACE_DUMP_REPLY, vl_api_trace_dump_reply_t_handler)
vl_msg_id(VL_API_TRACE_DETAILS, vl_api_trace_details_t_handler)
vl_msg_id(VL_API_TRACE_CLEAR_CACHE, vl_api_trace_clear_cache_t_handler)
vl_msg_id(VL_API_TRACE_CLEAR_CACHE_REPLY, vl_api_trace_clear_cache_reply_t_handler)
vl_msg_id(VL_API_TRACE_V2_DUMP, vl_api_trace_v2_dump_t_handler)
vl_msg_id(VL_API_TRACE_V2_DETAILS, vl_api_trace_v2_details_t_handler)
vl_msg_id(VL_API_TRACE_SET_FILTER_FUNCTION, vl_api_trace_set_filter_function_t_handler)
vl_msg_id(VL_API_TRACE_SET_FILTER_FUNCTION_REPLY, vl_api_trace_set_filter_function_reply_t_handler)
vl_msg_id(VL_API_TRACE_FILTER_FUNCTION_DUMP, vl_api_trace_filter_function_dump_t_handler)
vl_msg_id(VL_API_TRACE_FILTER_FUNCTION_DETAILS, vl_api_trace_filter_function_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_trace_set_filters_t, 1)
vl_msg_name(vl_api_trace_set_filters_reply_t, 1)
vl_msg_name(vl_api_trace_capture_packets_t, 1)
vl_msg_name(vl_api_trace_capture_packets_reply_t, 1)
vl_msg_name(vl_api_trace_clear_capture_t, 1)
vl_msg_name(vl_api_trace_clear_capture_reply_t, 1)
vl_msg_name(vl_api_trace_dump_t, 1)
vl_msg_name(vl_api_trace_dump_reply_t, 1)
vl_msg_name(vl_api_trace_details_t, 1)
vl_msg_name(vl_api_trace_clear_cache_t, 1)
vl_msg_name(vl_api_trace_clear_cache_reply_t, 1)
vl_msg_name(vl_api_trace_v2_dump_t, 1)
vl_msg_name(vl_api_trace_v2_details_t, 1)
vl_msg_name(vl_api_trace_set_filter_function_t, 1)
vl_msg_name(vl_api_trace_set_filter_function_reply_t, 1)
vl_msg_name(vl_api_trace_filter_function_dump_t, 1)
vl_msg_name(vl_api_trace_filter_function_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_tracedump \
_(VL_API_TRACE_SET_FILTERS, trace_set_filters, f522b44a) \
_(VL_API_TRACE_SET_FILTERS_REPLY, trace_set_filters_reply, e8d4e804) \
_(VL_API_TRACE_CAPTURE_PACKETS, trace_capture_packets, 9e791a9b) \
_(VL_API_TRACE_CAPTURE_PACKETS_REPLY, trace_capture_packets_reply, e8d4e804) \
_(VL_API_TRACE_CLEAR_CAPTURE, trace_clear_capture, 51077d14) \
_(VL_API_TRACE_CLEAR_CAPTURE_REPLY, trace_clear_capture_reply, e8d4e804) \
_(VL_API_TRACE_DUMP, trace_dump, c7d6681f) \
_(VL_API_TRACE_DUMP_REPLY, trace_dump_reply, e0e87f9d) \
_(VL_API_TRACE_DETAILS, trace_details, 1553e9eb) \
_(VL_API_TRACE_CLEAR_CACHE, trace_clear_cache, 51077d14) \
_(VL_API_TRACE_CLEAR_CACHE_REPLY, trace_clear_cache_reply, e8d4e804) \
_(VL_API_TRACE_V2_DUMP, trace_v2_dump, 83f88d8e) \
_(VL_API_TRACE_V2_DETAILS, trace_v2_details, 91f87d52) \
_(VL_API_TRACE_SET_FILTER_FUNCTION, trace_set_filter_function, 616abb92) \
_(VL_API_TRACE_SET_FILTER_FUNCTION_REPLY, trace_set_filter_function_reply, e8d4e804) \
_(VL_API_TRACE_FILTER_FUNCTION_DUMP, trace_filter_function_dump, 51077d14) \
_(VL_API_TRACE_FILTER_FUNCTION_DETAILS, trace_filter_function_details, 28821359) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "tracedump.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_tracedump_printfun_types
#define included_tracedump_printfun_types

static inline u8 *format_vl_api_trace_filter_flag_t (u8 *s, va_list * args)
{
    vl_api_trace_filter_flag_t *a = va_arg (*args, vl_api_trace_filter_flag_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "TRACE_FF_NONE");
    case 1:
        return format(s, "TRACE_FF_INCLUDE_NODE");
    case 2:
        return format(s, "TRACE_FF_EXCLUDE_NODE");
    case 3:
        return format(s, "TRACE_FF_INCLUDE_CLASSIFIER");
    case 4:
        return format(s, "TRACE_FF_EXCLUDE_CLASSIFIER");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_tracedump_printfun
#define included_tracedump_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "tracedump.api_tojson.h"
#include "tracedump.api_fromjson.h"

static inline u8 *vl_api_trace_set_filters_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_set_filters_t *a = va_arg (*args, vl_api_trace_set_filters_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_set_filters_t: */
    s = format(s, "vl_api_trace_set_filters_t:");
    s = format(s, "\n%Uflag: %U", format_white_space, indent, format_vl_api_trace_filter_flag_t, &a->flag, indent);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Unode_index: %u", format_white_space, indent, a->node_index);
    s = format(s, "\n%Uclassifier_table_index: %u", format_white_space, indent, a->classifier_table_index);
    return s;
}

static inline u8 *vl_api_trace_set_filters_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_set_filters_reply_t *a = va_arg (*args, vl_api_trace_set_filters_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_set_filters_reply_t: */
    s = format(s, "vl_api_trace_set_filters_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_trace_capture_packets_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_capture_packets_t *a = va_arg (*args, vl_api_trace_capture_packets_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_capture_packets_t: */
    s = format(s, "vl_api_trace_capture_packets_t:");
    s = format(s, "\n%Unode_index: %u", format_white_space, indent, a->node_index);
    s = format(s, "\n%Umax_packets: %u", format_white_space, indent, a->max_packets);
    s = format(s, "\n%Uuse_filter: %u", format_white_space, indent, a->use_filter);
    s = format(s, "\n%Uverbose: %u", format_white_space, indent, a->verbose);
    s = format(s, "\n%Upre_capture_clear: %u", format_white_space, indent, a->pre_capture_clear);
    return s;
}

static inline u8 *vl_api_trace_capture_packets_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_capture_packets_reply_t *a = va_arg (*args, vl_api_trace_capture_packets_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_capture_packets_reply_t: */
    s = format(s, "vl_api_trace_capture_packets_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_trace_clear_capture_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_clear_capture_t *a = va_arg (*args, vl_api_trace_clear_capture_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_clear_capture_t: */
    s = format(s, "vl_api_trace_clear_capture_t:");
    return s;
}

static inline u8 *vl_api_trace_clear_capture_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_clear_capture_reply_t *a = va_arg (*args, vl_api_trace_clear_capture_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_clear_capture_reply_t: */
    s = format(s, "vl_api_trace_clear_capture_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_trace_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_dump_t *a = va_arg (*args, vl_api_trace_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_dump_t: */
    s = format(s, "vl_api_trace_dump_t:");
    s = format(s, "\n%Uclear_cache: %u", format_white_space, indent, a->clear_cache);
    s = format(s, "\n%Uthread_id: %u", format_white_space, indent, a->thread_id);
    s = format(s, "\n%Uposition: %u", format_white_space, indent, a->position);
    s = format(s, "\n%Umax_records: %u", format_white_space, indent, a->max_records);
    return s;
}

static inline u8 *vl_api_trace_dump_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_dump_reply_t *a = va_arg (*args, vl_api_trace_dump_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_dump_reply_t: */
    s = format(s, "vl_api_trace_dump_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ulast_thread_id: %u", format_white_space, indent, a->last_thread_id);
    s = format(s, "\n%Ulast_position: %u", format_white_space, indent, a->last_position);
    s = format(s, "\n%Umore_this_thread: %u", format_white_space, indent, a->more_this_thread);
    s = format(s, "\n%Umore_threads: %u", format_white_space, indent, a->more_threads);
    s = format(s, "\n%Uflush_only: %u", format_white_space, indent, a->flush_only);
    s = format(s, "\n%Udone: %u", format_white_space, indent, a->done);
    return s;
}

static inline u8 *vl_api_trace_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_details_t *a = va_arg (*args, vl_api_trace_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_details_t: */
    s = format(s, "vl_api_trace_details_t:");
    s = format(s, "\n%Uthread_id: %u", format_white_space, indent, a->thread_id);
    s = format(s, "\n%Uposition: %u", format_white_space, indent, a->position);
    s = format(s, "\n%Umore_this_thread: %u", format_white_space, indent, a->more_this_thread);
    s = format(s, "\n%Umore_threads: %u", format_white_space, indent, a->more_threads);
    s = format(s, "\n%Udone: %u", format_white_space, indent, a->done);
    s = format(s, "\n%Upacket_number: %u", format_white_space, indent, a->packet_number);
    if (vl_api_string_len(&a->trace_data) > 0) {
        s = format(s, "\n%Utrace_data: %U", format_white_space, indent, vl_api_format_string, (&a->trace_data));
    } else {
        s = format(s, "\n%Utrace_data:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_trace_clear_cache_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_clear_cache_t *a = va_arg (*args, vl_api_trace_clear_cache_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_clear_cache_t: */
    s = format(s, "vl_api_trace_clear_cache_t:");
    return s;
}

static inline u8 *vl_api_trace_clear_cache_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_clear_cache_reply_t *a = va_arg (*args, vl_api_trace_clear_cache_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_clear_cache_reply_t: */
    s = format(s, "vl_api_trace_clear_cache_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_trace_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_v2_dump_t *a = va_arg (*args, vl_api_trace_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_v2_dump_t: */
    s = format(s, "vl_api_trace_v2_dump_t:");
    s = format(s, "\n%Uthread_id: %u", format_white_space, indent, a->thread_id);
    s = format(s, "\n%Uposition: %u", format_white_space, indent, a->position);
    s = format(s, "\n%Umax: %u", format_white_space, indent, a->max);
    s = format(s, "\n%Uclear_cache: %u", format_white_space, indent, a->clear_cache);
    return s;
}

static inline u8 *vl_api_trace_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_v2_details_t *a = va_arg (*args, vl_api_trace_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_v2_details_t: */
    s = format(s, "vl_api_trace_v2_details_t:");
    s = format(s, "\n%Uthread_id: %u", format_white_space, indent, a->thread_id);
    s = format(s, "\n%Uposition: %u", format_white_space, indent, a->position);
    s = format(s, "\n%Umore: %u", format_white_space, indent, a->more);
    if (vl_api_string_len(&a->trace_data) > 0) {
        s = format(s, "\n%Utrace_data: %U", format_white_space, indent, vl_api_format_string, (&a->trace_data));
    } else {
        s = format(s, "\n%Utrace_data:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_trace_set_filter_function_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_set_filter_function_t *a = va_arg (*args, vl_api_trace_set_filter_function_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_set_filter_function_t: */
    s = format(s, "vl_api_trace_set_filter_function_t:");
    if (vl_api_string_len(&a->filter_function_name) > 0) {
        s = format(s, "\n%Ufilter_function_name: %U", format_white_space, indent, vl_api_format_string, (&a->filter_function_name));
    } else {
        s = format(s, "\n%Ufilter_function_name:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_trace_set_filter_function_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_set_filter_function_reply_t *a = va_arg (*args, vl_api_trace_set_filter_function_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_set_filter_function_reply_t: */
    s = format(s, "vl_api_trace_set_filter_function_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_trace_filter_function_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_filter_function_dump_t *a = va_arg (*args, vl_api_trace_filter_function_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_filter_function_dump_t: */
    s = format(s, "vl_api_trace_filter_function_dump_t:");
    return s;
}

static inline u8 *vl_api_trace_filter_function_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_trace_filter_function_details_t *a = va_arg (*args, vl_api_trace_filter_function_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_trace_filter_function_details_t: */
    s = format(s, "vl_api_trace_filter_function_details_t:");
    s = format(s, "\n%Uselected: %u", format_white_space, indent, a->selected);
    if (vl_api_string_len(&a->name) > 0) {
        s = format(s, "\n%Uname: %U", format_white_space, indent, vl_api_format_string, (&a->name));
    } else {
        s = format(s, "\n%Uname:", format_white_space, indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_tracedump_endianfun
#define included_tracedump_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_trace_filter_flag_t_endian (vl_api_trace_filter_flag_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_trace_set_filters_t_endian (vl_api_trace_set_filters_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_trace_filter_flag_t_endian(&a->flag, to_net);
    a->count = clib_net_to_host_u32(a->count);
    a->node_index = clib_net_to_host_u32(a->node_index);
    a->classifier_table_index = clib_net_to_host_u32(a->classifier_table_index);
}

static inline void vl_api_trace_set_filters_reply_t_endian (vl_api_trace_set_filters_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_trace_capture_packets_t_endian (vl_api_trace_capture_packets_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->node_index = clib_net_to_host_u32(a->node_index);
    a->max_packets = clib_net_to_host_u32(a->max_packets);
    /* a->use_filter = a->use_filter (no-op) */
    /* a->verbose = a->verbose (no-op) */
    /* a->pre_capture_clear = a->pre_capture_clear (no-op) */
}

static inline void vl_api_trace_capture_packets_reply_t_endian (vl_api_trace_capture_packets_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_trace_clear_capture_t_endian (vl_api_trace_clear_capture_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_trace_clear_capture_reply_t_endian (vl_api_trace_clear_capture_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_trace_dump_t_endian (vl_api_trace_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->clear_cache = a->clear_cache (no-op) */
    a->thread_id = clib_net_to_host_u32(a->thread_id);
    a->position = clib_net_to_host_u32(a->position);
    a->max_records = clib_net_to_host_u32(a->max_records);
}

static inline void vl_api_trace_dump_reply_t_endian (vl_api_trace_dump_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->last_thread_id = clib_net_to_host_u32(a->last_thread_id);
    a->last_position = clib_net_to_host_u32(a->last_position);
    /* a->more_this_thread = a->more_this_thread (no-op) */
    /* a->more_threads = a->more_threads (no-op) */
    /* a->flush_only = a->flush_only (no-op) */
    /* a->done = a->done (no-op) */
}

static inline void vl_api_trace_details_t_endian (vl_api_trace_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->thread_id = clib_net_to_host_u32(a->thread_id);
    a->position = clib_net_to_host_u32(a->position);
    /* a->more_this_thread = a->more_this_thread (no-op) */
    /* a->more_threads = a->more_threads (no-op) */
    /* a->done = a->done (no-op) */
    a->packet_number = clib_net_to_host_u32(a->packet_number);
    /* a->trace_data = a->trace_data (no-op) */
}

static inline void vl_api_trace_clear_cache_t_endian (vl_api_trace_clear_cache_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_trace_clear_cache_reply_t_endian (vl_api_trace_clear_cache_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_trace_v2_dump_t_endian (vl_api_trace_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->thread_id = clib_net_to_host_u32(a->thread_id);
    a->position = clib_net_to_host_u32(a->position);
    a->max = clib_net_to_host_u32(a->max);
    /* a->clear_cache = a->clear_cache (no-op) */
}

static inline void vl_api_trace_v2_details_t_endian (vl_api_trace_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->thread_id = clib_net_to_host_u32(a->thread_id);
    a->position = clib_net_to_host_u32(a->position);
    /* a->more = a->more (no-op) */
    /* a->trace_data = a->trace_data (no-op) */
}

static inline void vl_api_trace_set_filter_function_t_endian (vl_api_trace_set_filter_function_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->filter_function_name = a->filter_function_name (no-op) */
}

static inline void vl_api_trace_set_filter_function_reply_t_endian (vl_api_trace_set_filter_function_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_trace_filter_function_dump_t_endian (vl_api_trace_filter_function_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_trace_filter_function_details_t_endian (vl_api_trace_filter_function_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->selected = a->selected (no-op) */
    /* a->name = a->name (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_tracedump_calcsizefun
#define included_tracedump_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_filter_flag_t_calc_size (vl_api_trace_filter_flag_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_set_filters_t_calc_size (vl_api_trace_set_filters_t *a)
{
      return sizeof(*a) - sizeof(a->flag) + vl_api_trace_filter_flag_t_calc_size(&a->flag);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_set_filters_reply_t_calc_size (vl_api_trace_set_filters_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_capture_packets_t_calc_size (vl_api_trace_capture_packets_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_capture_packets_reply_t_calc_size (vl_api_trace_capture_packets_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_clear_capture_t_calc_size (vl_api_trace_clear_capture_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_clear_capture_reply_t_calc_size (vl_api_trace_clear_capture_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_dump_t_calc_size (vl_api_trace_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_dump_reply_t_calc_size (vl_api_trace_dump_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_details_t_calc_size (vl_api_trace_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->trace_data);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_clear_cache_t_calc_size (vl_api_trace_clear_cache_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_clear_cache_reply_t_calc_size (vl_api_trace_clear_cache_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_v2_dump_t_calc_size (vl_api_trace_v2_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_v2_details_t_calc_size (vl_api_trace_v2_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->trace_data);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_set_filter_function_t_calc_size (vl_api_trace_set_filter_function_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->filter_function_name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_set_filter_function_reply_t_calc_size (vl_api_trace_set_filter_function_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_filter_function_dump_t_calc_size (vl_api_trace_filter_function_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_trace_filter_function_details_t_calc_size (vl_api_trace_filter_function_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->name);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(tracedump.api, 0, 2, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(tracedump.api, 0x56abf80a)

#endif

