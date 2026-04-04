/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: vpe.api
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
#warning no content included from vpe.api
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
#include <vpp/api/vpe_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_SHOW_VERSION, vl_api_show_version_t_handler)
vl_msg_id(VL_API_SHOW_VERSION_REPLY, vl_api_show_version_reply_t_handler)
vl_msg_id(VL_API_SHOW_VPE_SYSTEM_TIME, vl_api_show_vpe_system_time_t_handler)
vl_msg_id(VL_API_SHOW_VPE_SYSTEM_TIME_REPLY, vl_api_show_vpe_system_time_reply_t_handler)
vl_msg_id(VL_API_LOG_DUMP, vl_api_log_dump_t_handler)
vl_msg_id(VL_API_LOG_DETAILS, vl_api_log_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_show_version_t, 1)
vl_msg_name(vl_api_show_version_reply_t, 1)
vl_msg_name(vl_api_show_vpe_system_time_t, 1)
vl_msg_name(vl_api_show_vpe_system_time_reply_t, 1)
vl_msg_name(vl_api_log_dump_t, 1)
vl_msg_name(vl_api_log_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vpe \
_(VL_API_SHOW_VERSION, show_version, 51077d14) \
_(VL_API_SHOW_VERSION_REPLY, show_version_reply, c919bde1) \
_(VL_API_SHOW_VPE_SYSTEM_TIME, show_vpe_system_time, 51077d14) \
_(VL_API_SHOW_VPE_SYSTEM_TIME_REPLY, show_vpe_system_time_reply, 7ffd8193) \
_(VL_API_LOG_DUMP, log_dump, 6ab31753) \
_(VL_API_LOG_DETAILS, log_details, 03d61cc0) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vpe.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vpe_printfun_types
#define included_vpe_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vpe_printfun
#define included_vpe_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vpe.api_tojson.h"
#include "vpe.api_fromjson.h"

static inline u8 *vl_api_show_version_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_version_t *a = va_arg (*args, vl_api_show_version_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_version_t: */
    s = format(s, "vl_api_show_version_t:");
    return s;
}

static inline u8 *vl_api_show_version_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_version_reply_t *a = va_arg (*args, vl_api_show_version_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_version_reply_t: */
    s = format(s, "vl_api_show_version_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uprogram: %s", format_white_space, indent, a->program);
    s = format(s, "\n%Uversion: %s", format_white_space, indent, a->version);
    s = format(s, "\n%Ubuild_date: %s", format_white_space, indent, a->build_date);
    s = format(s, "\n%Ubuild_directory: %s", format_white_space, indent, a->build_directory);
    return s;
}

static inline u8 *vl_api_show_vpe_system_time_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_vpe_system_time_t *a = va_arg (*args, vl_api_show_vpe_system_time_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_vpe_system_time_t: */
    s = format(s, "vl_api_show_vpe_system_time_t:");
    return s;
}

static inline u8 *vl_api_show_vpe_system_time_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_show_vpe_system_time_reply_t *a = va_arg (*args, vl_api_show_vpe_system_time_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_show_vpe_system_time_reply_t: */
    s = format(s, "vl_api_show_vpe_system_time_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uvpe_system_time: %U", format_white_space, indent, format_vl_api_timestamp_t, &a->vpe_system_time, indent);
    return s;
}

static inline u8 *vl_api_log_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_log_dump_t *a = va_arg (*args, vl_api_log_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_log_dump_t: */
    s = format(s, "vl_api_log_dump_t:");
    s = format(s, "\n%Ustart_timestamp: %U", format_white_space, indent, format_vl_api_timestamp_t, &a->start_timestamp, indent);
    return s;
}

static inline u8 *vl_api_log_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_log_details_t *a = va_arg (*args, vl_api_log_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_log_details_t: */
    s = format(s, "vl_api_log_details_t:");
    s = format(s, "\n%Utimestamp: %U", format_white_space, indent, format_vl_api_timestamp_t, &a->timestamp, indent);
    s = format(s, "\n%Ulevel: %U", format_white_space, indent, format_vl_api_log_level_t, &a->level, indent);
    s = format(s, "\n%Umsg_class: %s", format_white_space, indent, a->msg_class);
    s = format(s, "\n%Umessage: %s", format_white_space, indent, a->message);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vpe_endianfun
#define included_vpe_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_show_version_t_endian (vl_api_show_version_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_version_reply_t_endian (vl_api_show_version_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->program = a->program (no-op) */
    /* a->version = a->version (no-op) */
    /* a->build_date = a->build_date (no-op) */
    /* a->build_directory = a->build_directory (no-op) */
}

static inline void vl_api_show_vpe_system_time_t_endian (vl_api_show_vpe_system_time_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_show_vpe_system_time_reply_t_endian (vl_api_show_vpe_system_time_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_timestamp_t_endian(&a->vpe_system_time, to_net);
}

static inline void vl_api_log_dump_t_endian (vl_api_log_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_timestamp_t_endian(&a->start_timestamp, to_net);
}

static inline void vl_api_log_details_t_endian (vl_api_log_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_timestamp_t_endian(&a->timestamp, to_net);
    vl_api_log_level_t_endian(&a->level, to_net);
    /* a->msg_class = a->msg_class (no-op) */
    /* a->message = a->message (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_vpe_calcsizefun
#define included_vpe_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_show_version_t_calc_size (vl_api_show_version_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_version_reply_t_calc_size (vl_api_show_version_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_vpe_system_time_t_calc_size (vl_api_show_vpe_system_time_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_show_vpe_system_time_reply_t_calc_size (vl_api_show_vpe_system_time_reply_t *a)
{
      return sizeof(*a) - sizeof(a->vpe_system_time) + vl_api_timestamp_t_calc_size(&a->vpe_system_time);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_log_dump_t_calc_size (vl_api_log_dump_t *a)
{
      return sizeof(*a) - sizeof(a->start_timestamp) + vl_api_timestamp_t_calc_size(&a->start_timestamp);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_log_details_t_calc_size (vl_api_log_details_t *a)
{
      return sizeof(*a) - sizeof(a->timestamp) + vl_api_timestamp_t_calc_size(&a->timestamp) - sizeof(a->level) + vl_api_log_level_t_calc_size(&a->level);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vpe.api, 1, 7, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vpe.api, 0x33b45969)

#endif

