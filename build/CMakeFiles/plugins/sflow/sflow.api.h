/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: sflow.api
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
#warning no content included from sflow.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_SFLOW_ENABLE_DISABLE, vl_api_sflow_enable_disable_t_handler)
vl_msg_id(VL_API_SFLOW_ENABLE_DISABLE_REPLY, vl_api_sflow_enable_disable_reply_t_handler)
vl_msg_id(VL_API_SFLOW_SAMPLING_RATE_GET, vl_api_sflow_sampling_rate_get_t_handler)
vl_msg_id(VL_API_SFLOW_SAMPLING_RATE_GET_REPLY, vl_api_sflow_sampling_rate_get_reply_t_handler)
vl_msg_id(VL_API_SFLOW_SAMPLING_RATE_SET, vl_api_sflow_sampling_rate_set_t_handler)
vl_msg_id(VL_API_SFLOW_SAMPLING_RATE_SET_REPLY, vl_api_sflow_sampling_rate_set_reply_t_handler)
vl_msg_id(VL_API_SFLOW_POLLING_INTERVAL_SET, vl_api_sflow_polling_interval_set_t_handler)
vl_msg_id(VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY, vl_api_sflow_polling_interval_set_reply_t_handler)
vl_msg_id(VL_API_SFLOW_POLLING_INTERVAL_GET, vl_api_sflow_polling_interval_get_t_handler)
vl_msg_id(VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY, vl_api_sflow_polling_interval_get_reply_t_handler)
vl_msg_id(VL_API_SFLOW_HEADER_BYTES_SET, vl_api_sflow_header_bytes_set_t_handler)
vl_msg_id(VL_API_SFLOW_HEADER_BYTES_SET_REPLY, vl_api_sflow_header_bytes_set_reply_t_handler)
vl_msg_id(VL_API_SFLOW_HEADER_BYTES_GET, vl_api_sflow_header_bytes_get_t_handler)
vl_msg_id(VL_API_SFLOW_HEADER_BYTES_GET_REPLY, vl_api_sflow_header_bytes_get_reply_t_handler)
vl_msg_id(VL_API_SFLOW_DIRECTION_SET, vl_api_sflow_direction_set_t_handler)
vl_msg_id(VL_API_SFLOW_DIRECTION_SET_REPLY, vl_api_sflow_direction_set_reply_t_handler)
vl_msg_id(VL_API_SFLOW_DIRECTION_GET, vl_api_sflow_direction_get_t_handler)
vl_msg_id(VL_API_SFLOW_DIRECTION_GET_REPLY, vl_api_sflow_direction_get_reply_t_handler)
vl_msg_id(VL_API_SFLOW_DROP_MONITORING_SET, vl_api_sflow_drop_monitoring_set_t_handler)
vl_msg_id(VL_API_SFLOW_DROP_MONITORING_SET_REPLY, vl_api_sflow_drop_monitoring_set_reply_t_handler)
vl_msg_id(VL_API_SFLOW_DROP_MONITORING_GET, vl_api_sflow_drop_monitoring_get_t_handler)
vl_msg_id(VL_API_SFLOW_DROP_MONITORING_GET_REPLY, vl_api_sflow_drop_monitoring_get_reply_t_handler)
vl_msg_id(VL_API_SFLOW_INTERFACE_DUMP, vl_api_sflow_interface_dump_t_handler)
vl_msg_id(VL_API_SFLOW_INTERFACE_DETAILS, vl_api_sflow_interface_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_sflow_enable_disable_t, 1)
vl_msg_name(vl_api_sflow_enable_disable_reply_t, 1)
vl_msg_name(vl_api_sflow_sampling_rate_get_t, 1)
vl_msg_name(vl_api_sflow_sampling_rate_get_reply_t, 1)
vl_msg_name(vl_api_sflow_sampling_rate_set_t, 1)
vl_msg_name(vl_api_sflow_sampling_rate_set_reply_t, 1)
vl_msg_name(vl_api_sflow_polling_interval_set_t, 1)
vl_msg_name(vl_api_sflow_polling_interval_set_reply_t, 1)
vl_msg_name(vl_api_sflow_polling_interval_get_t, 1)
vl_msg_name(vl_api_sflow_polling_interval_get_reply_t, 1)
vl_msg_name(vl_api_sflow_header_bytes_set_t, 1)
vl_msg_name(vl_api_sflow_header_bytes_set_reply_t, 1)
vl_msg_name(vl_api_sflow_header_bytes_get_t, 1)
vl_msg_name(vl_api_sflow_header_bytes_get_reply_t, 1)
vl_msg_name(vl_api_sflow_direction_set_t, 1)
vl_msg_name(vl_api_sflow_direction_set_reply_t, 1)
vl_msg_name(vl_api_sflow_direction_get_t, 1)
vl_msg_name(vl_api_sflow_direction_get_reply_t, 1)
vl_msg_name(vl_api_sflow_drop_monitoring_set_t, 1)
vl_msg_name(vl_api_sflow_drop_monitoring_set_reply_t, 1)
vl_msg_name(vl_api_sflow_drop_monitoring_get_t, 1)
vl_msg_name(vl_api_sflow_drop_monitoring_get_reply_t, 1)
vl_msg_name(vl_api_sflow_interface_dump_t, 1)
vl_msg_name(vl_api_sflow_interface_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_sflow \
_(VL_API_SFLOW_ENABLE_DISABLE, sflow_enable_disable, 8499814f) \
_(VL_API_SFLOW_ENABLE_DISABLE_REPLY, sflow_enable_disable_reply, e8d4e804) \
_(VL_API_SFLOW_SAMPLING_RATE_GET, sflow_sampling_rate_get, 51077d14) \
_(VL_API_SFLOW_SAMPLING_RATE_GET_REPLY, sflow_sampling_rate_get_reply, 9c8c8236) \
_(VL_API_SFLOW_SAMPLING_RATE_SET, sflow_sampling_rate_set, 94778f50) \
_(VL_API_SFLOW_SAMPLING_RATE_SET_REPLY, sflow_sampling_rate_set_reply, e8d4e804) \
_(VL_API_SFLOW_POLLING_INTERVAL_SET, sflow_polling_interval_set, 7f19cb51) \
_(VL_API_SFLOW_POLLING_INTERVAL_SET_REPLY, sflow_polling_interval_set_reply, e8d4e804) \
_(VL_API_SFLOW_POLLING_INTERVAL_GET, sflow_polling_interval_get, 51077d14) \
_(VL_API_SFLOW_POLLING_INTERVAL_GET_REPLY, sflow_polling_interval_get_reply, e929801c) \
_(VL_API_SFLOW_HEADER_BYTES_SET, sflow_header_bytes_set, 5baf56f3) \
_(VL_API_SFLOW_HEADER_BYTES_SET_REPLY, sflow_header_bytes_set_reply, e8d4e804) \
_(VL_API_SFLOW_HEADER_BYTES_GET, sflow_header_bytes_get, 51077d14) \
_(VL_API_SFLOW_HEADER_BYTES_GET_REPLY, sflow_header_bytes_get_reply, 624c95b9) \
_(VL_API_SFLOW_DIRECTION_SET, sflow_direction_set, fbca6f34) \
_(VL_API_SFLOW_DIRECTION_SET_REPLY, sflow_direction_set_reply, e8d4e804) \
_(VL_API_SFLOW_DIRECTION_GET, sflow_direction_get, 51077d14) \
_(VL_API_SFLOW_DIRECTION_GET_REPLY, sflow_direction_get_reply, f3316252) \
_(VL_API_SFLOW_DROP_MONITORING_SET, sflow_drop_monitoring_set, 100b1e04) \
_(VL_API_SFLOW_DROP_MONITORING_SET_REPLY, sflow_drop_monitoring_set_reply, e8d4e804) \
_(VL_API_SFLOW_DROP_MONITORING_GET, sflow_drop_monitoring_get, 51077d14) \
_(VL_API_SFLOW_DROP_MONITORING_GET_REPLY, sflow_drop_monitoring_get_reply, b56ae30e) \
_(VL_API_SFLOW_INTERFACE_DUMP, sflow_interface_dump, 451a727d) \
_(VL_API_SFLOW_INTERFACE_DETAILS, sflow_interface_details, b7b9143f) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "sflow.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sflow_printfun_types
#define included_sflow_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_sflow_printfun
#define included_sflow_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "sflow.api_tojson.h"
#include "sflow.api_fromjson.h"

static inline u8 *vl_api_sflow_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_enable_disable_t *a = va_arg (*args, vl_api_sflow_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_enable_disable_t: */
    s = format(s, "vl_api_sflow_enable_disable_t:");
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Uhw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->hw_if_index, indent);
    return s;
}

static inline u8 *vl_api_sflow_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_enable_disable_reply_t *a = va_arg (*args, vl_api_sflow_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_enable_disable_reply_t: */
    s = format(s, "vl_api_sflow_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sflow_sampling_rate_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_sampling_rate_get_t *a = va_arg (*args, vl_api_sflow_sampling_rate_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_sampling_rate_get_t: */
    s = format(s, "vl_api_sflow_sampling_rate_get_t:");
    return s;
}

static inline u8 *vl_api_sflow_sampling_rate_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_sampling_rate_get_reply_t *a = va_arg (*args, vl_api_sflow_sampling_rate_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_sampling_rate_get_reply_t: */
    s = format(s, "vl_api_sflow_sampling_rate_get_reply_t:");
    s = format(s, "\n%Usampling_N: %u", format_white_space, indent, a->sampling_N);
    return s;
}

static inline u8 *vl_api_sflow_sampling_rate_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_sampling_rate_set_t *a = va_arg (*args, vl_api_sflow_sampling_rate_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_sampling_rate_set_t: */
    s = format(s, "vl_api_sflow_sampling_rate_set_t:");
    s = format(s, "\n%Usampling_N: %u", format_white_space, indent, a->sampling_N);
    return s;
}

static inline u8 *vl_api_sflow_sampling_rate_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_sampling_rate_set_reply_t *a = va_arg (*args, vl_api_sflow_sampling_rate_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_sampling_rate_set_reply_t: */
    s = format(s, "vl_api_sflow_sampling_rate_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sflow_polling_interval_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_polling_interval_set_t *a = va_arg (*args, vl_api_sflow_polling_interval_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_polling_interval_set_t: */
    s = format(s, "vl_api_sflow_polling_interval_set_t:");
    s = format(s, "\n%Upolling_S: %u", format_white_space, indent, a->polling_S);
    return s;
}

static inline u8 *vl_api_sflow_polling_interval_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_polling_interval_set_reply_t *a = va_arg (*args, vl_api_sflow_polling_interval_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_polling_interval_set_reply_t: */
    s = format(s, "vl_api_sflow_polling_interval_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sflow_polling_interval_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_polling_interval_get_t *a = va_arg (*args, vl_api_sflow_polling_interval_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_polling_interval_get_t: */
    s = format(s, "vl_api_sflow_polling_interval_get_t:");
    return s;
}

static inline u8 *vl_api_sflow_polling_interval_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_polling_interval_get_reply_t *a = va_arg (*args, vl_api_sflow_polling_interval_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_polling_interval_get_reply_t: */
    s = format(s, "vl_api_sflow_polling_interval_get_reply_t:");
    s = format(s, "\n%Upolling_S: %u", format_white_space, indent, a->polling_S);
    return s;
}

static inline u8 *vl_api_sflow_header_bytes_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_header_bytes_set_t *a = va_arg (*args, vl_api_sflow_header_bytes_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_header_bytes_set_t: */
    s = format(s, "vl_api_sflow_header_bytes_set_t:");
    s = format(s, "\n%Uheader_B: %u", format_white_space, indent, a->header_B);
    return s;
}

static inline u8 *vl_api_sflow_header_bytes_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_header_bytes_set_reply_t *a = va_arg (*args, vl_api_sflow_header_bytes_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_header_bytes_set_reply_t: */
    s = format(s, "vl_api_sflow_header_bytes_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sflow_header_bytes_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_header_bytes_get_t *a = va_arg (*args, vl_api_sflow_header_bytes_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_header_bytes_get_t: */
    s = format(s, "vl_api_sflow_header_bytes_get_t:");
    return s;
}

static inline u8 *vl_api_sflow_header_bytes_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_header_bytes_get_reply_t *a = va_arg (*args, vl_api_sflow_header_bytes_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_header_bytes_get_reply_t: */
    s = format(s, "vl_api_sflow_header_bytes_get_reply_t:");
    s = format(s, "\n%Uheader_B: %u", format_white_space, indent, a->header_B);
    return s;
}

static inline u8 *vl_api_sflow_direction_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_direction_set_t *a = va_arg (*args, vl_api_sflow_direction_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_direction_set_t: */
    s = format(s, "vl_api_sflow_direction_set_t:");
    s = format(s, "\n%Usampling_D: %u", format_white_space, indent, a->sampling_D);
    return s;
}

static inline u8 *vl_api_sflow_direction_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_direction_set_reply_t *a = va_arg (*args, vl_api_sflow_direction_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_direction_set_reply_t: */
    s = format(s, "vl_api_sflow_direction_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sflow_direction_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_direction_get_t *a = va_arg (*args, vl_api_sflow_direction_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_direction_get_t: */
    s = format(s, "vl_api_sflow_direction_get_t:");
    return s;
}

static inline u8 *vl_api_sflow_direction_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_direction_get_reply_t *a = va_arg (*args, vl_api_sflow_direction_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_direction_get_reply_t: */
    s = format(s, "vl_api_sflow_direction_get_reply_t:");
    s = format(s, "\n%Usampling_D: %u", format_white_space, indent, a->sampling_D);
    return s;
}

static inline u8 *vl_api_sflow_drop_monitoring_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_drop_monitoring_set_t *a = va_arg (*args, vl_api_sflow_drop_monitoring_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_drop_monitoring_set_t: */
    s = format(s, "vl_api_sflow_drop_monitoring_set_t:");
    s = format(s, "\n%Udrop_M: %u", format_white_space, indent, a->drop_M);
    return s;
}

static inline u8 *vl_api_sflow_drop_monitoring_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_drop_monitoring_set_reply_t *a = va_arg (*args, vl_api_sflow_drop_monitoring_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_drop_monitoring_set_reply_t: */
    s = format(s, "vl_api_sflow_drop_monitoring_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sflow_drop_monitoring_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_drop_monitoring_get_t *a = va_arg (*args, vl_api_sflow_drop_monitoring_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_drop_monitoring_get_t: */
    s = format(s, "vl_api_sflow_drop_monitoring_get_t:");
    return s;
}

static inline u8 *vl_api_sflow_drop_monitoring_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_drop_monitoring_get_reply_t *a = va_arg (*args, vl_api_sflow_drop_monitoring_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_drop_monitoring_get_reply_t: */
    s = format(s, "vl_api_sflow_drop_monitoring_get_reply_t:");
    s = format(s, "\n%Udrop_M: %u", format_white_space, indent, a->drop_M);
    return s;
}

static inline u8 *vl_api_sflow_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_interface_dump_t *a = va_arg (*args, vl_api_sflow_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_interface_dump_t: */
    s = format(s, "vl_api_sflow_interface_dump_t:");
    s = format(s, "\n%Uhw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->hw_if_index, indent);
    return s;
}

static inline u8 *vl_api_sflow_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sflow_interface_details_t *a = va_arg (*args, vl_api_sflow_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sflow_interface_details_t: */
    s = format(s, "vl_api_sflow_interface_details_t:");
    s = format(s, "\n%Uhw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->hw_if_index, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_sflow_endianfun
#define included_sflow_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_sflow_enable_disable_t_endian (vl_api_sflow_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_disable = a->enable_disable (no-op) */
    vl_api_interface_index_t_endian(&a->hw_if_index, to_net);
}

static inline void vl_api_sflow_enable_disable_reply_t_endian (vl_api_sflow_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sflow_sampling_rate_get_t_endian (vl_api_sflow_sampling_rate_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sflow_sampling_rate_get_reply_t_endian (vl_api_sflow_sampling_rate_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->sampling_N = clib_net_to_host_u32(a->sampling_N);
}

static inline void vl_api_sflow_sampling_rate_set_t_endian (vl_api_sflow_sampling_rate_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sampling_N = clib_net_to_host_u32(a->sampling_N);
}

static inline void vl_api_sflow_sampling_rate_set_reply_t_endian (vl_api_sflow_sampling_rate_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sflow_polling_interval_set_t_endian (vl_api_sflow_polling_interval_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->polling_S = clib_net_to_host_u32(a->polling_S);
}

static inline void vl_api_sflow_polling_interval_set_reply_t_endian (vl_api_sflow_polling_interval_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sflow_polling_interval_get_t_endian (vl_api_sflow_polling_interval_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sflow_polling_interval_get_reply_t_endian (vl_api_sflow_polling_interval_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->polling_S = clib_net_to_host_u32(a->polling_S);
}

static inline void vl_api_sflow_header_bytes_set_t_endian (vl_api_sflow_header_bytes_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->header_B = clib_net_to_host_u32(a->header_B);
}

static inline void vl_api_sflow_header_bytes_set_reply_t_endian (vl_api_sflow_header_bytes_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sflow_header_bytes_get_t_endian (vl_api_sflow_header_bytes_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sflow_header_bytes_get_reply_t_endian (vl_api_sflow_header_bytes_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->header_B = clib_net_to_host_u32(a->header_B);
}

static inline void vl_api_sflow_direction_set_t_endian (vl_api_sflow_direction_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sampling_D = clib_net_to_host_u32(a->sampling_D);
}

static inline void vl_api_sflow_direction_set_reply_t_endian (vl_api_sflow_direction_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sflow_direction_get_t_endian (vl_api_sflow_direction_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sflow_direction_get_reply_t_endian (vl_api_sflow_direction_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->sampling_D = clib_net_to_host_u32(a->sampling_D);
}

static inline void vl_api_sflow_drop_monitoring_set_t_endian (vl_api_sflow_drop_monitoring_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->drop_M = clib_net_to_host_u32(a->drop_M);
}

static inline void vl_api_sflow_drop_monitoring_set_reply_t_endian (vl_api_sflow_drop_monitoring_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sflow_drop_monitoring_get_t_endian (vl_api_sflow_drop_monitoring_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_sflow_drop_monitoring_get_reply_t_endian (vl_api_sflow_drop_monitoring_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->drop_M = clib_net_to_host_u32(a->drop_M);
}

static inline void vl_api_sflow_interface_dump_t_endian (vl_api_sflow_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->hw_if_index, to_net);
}

static inline void vl_api_sflow_interface_details_t_endian (vl_api_sflow_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->hw_if_index, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_sflow_calcsizefun
#define included_sflow_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_enable_disable_t_calc_size (vl_api_sflow_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->hw_if_index) + vl_api_interface_index_t_calc_size(&a->hw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_enable_disable_reply_t_calc_size (vl_api_sflow_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_sampling_rate_get_t_calc_size (vl_api_sflow_sampling_rate_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_sampling_rate_get_reply_t_calc_size (vl_api_sflow_sampling_rate_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_sampling_rate_set_t_calc_size (vl_api_sflow_sampling_rate_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_sampling_rate_set_reply_t_calc_size (vl_api_sflow_sampling_rate_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_polling_interval_set_t_calc_size (vl_api_sflow_polling_interval_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_polling_interval_set_reply_t_calc_size (vl_api_sflow_polling_interval_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_polling_interval_get_t_calc_size (vl_api_sflow_polling_interval_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_polling_interval_get_reply_t_calc_size (vl_api_sflow_polling_interval_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_header_bytes_set_t_calc_size (vl_api_sflow_header_bytes_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_header_bytes_set_reply_t_calc_size (vl_api_sflow_header_bytes_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_header_bytes_get_t_calc_size (vl_api_sflow_header_bytes_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_header_bytes_get_reply_t_calc_size (vl_api_sflow_header_bytes_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_direction_set_t_calc_size (vl_api_sflow_direction_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_direction_set_reply_t_calc_size (vl_api_sflow_direction_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_direction_get_t_calc_size (vl_api_sflow_direction_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_direction_get_reply_t_calc_size (vl_api_sflow_direction_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_drop_monitoring_set_t_calc_size (vl_api_sflow_drop_monitoring_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_drop_monitoring_set_reply_t_calc_size (vl_api_sflow_drop_monitoring_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_drop_monitoring_get_t_calc_size (vl_api_sflow_drop_monitoring_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_drop_monitoring_get_reply_t_calc_size (vl_api_sflow_drop_monitoring_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_interface_dump_t_calc_size (vl_api_sflow_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->hw_if_index) + vl_api_interface_index_t_calc_size(&a->hw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sflow_interface_details_t_calc_size (vl_api_sflow_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->hw_if_index) + vl_api_interface_index_t_calc_size(&a->hw_if_index);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(sflow.api, 0, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(sflow.api, 0xba88ab74)

#endif

