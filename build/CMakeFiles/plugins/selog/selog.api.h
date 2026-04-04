/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: selog.api
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
#warning no content included from selog.api
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
vl_msg_id(VL_API_SELOG_GET_SHM, vl_api_selog_get_shm_t_handler)
vl_msg_id(VL_API_SELOG_GET_SHM_REPLY, vl_api_selog_get_shm_reply_t_handler)
vl_msg_id(VL_API_SELOG_GET_STRING_TABLE, vl_api_selog_get_string_table_t_handler)
vl_msg_id(VL_API_SELOG_GET_STRING_TABLE_REPLY, vl_api_selog_get_string_table_reply_t_handler)
vl_msg_id(VL_API_SELOG_TRACK_DUMP, vl_api_selog_track_dump_t_handler)
vl_msg_id(VL_API_SELOG_TRACK_DETAILS, vl_api_selog_track_details_t_handler)
vl_msg_id(VL_API_SELOG_EVENT_TYPE_DUMP, vl_api_selog_event_type_dump_t_handler)
vl_msg_id(VL_API_SELOG_EVENT_TYPE_DETAILS, vl_api_selog_event_type_details_t_handler)
vl_msg_id(VL_API_SELOG_EVENT_TYPE_STRING_DUMP, vl_api_selog_event_type_string_dump_t_handler)
vl_msg_id(VL_API_SELOG_EVENT_TYPE_STRING_DETAILS, vl_api_selog_event_type_string_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_selog_get_shm_t, 1)
vl_msg_name(vl_api_selog_get_shm_reply_t, 1)
vl_msg_name(vl_api_selog_get_string_table_t, 1)
vl_msg_name(vl_api_selog_get_string_table_reply_t, 1)
vl_msg_name(vl_api_selog_track_dump_t, 1)
vl_msg_name(vl_api_selog_track_details_t, 1)
vl_msg_name(vl_api_selog_event_type_dump_t, 1)
vl_msg_name(vl_api_selog_event_type_details_t, 1)
vl_msg_name(vl_api_selog_event_type_string_dump_t, 1)
vl_msg_name(vl_api_selog_event_type_string_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_selog \
_(VL_API_SELOG_GET_SHM, selog_get_shm, 51077d14) \
_(VL_API_SELOG_GET_SHM_REPLY, selog_get_shm_reply, e8d4e804) \
_(VL_API_SELOG_GET_STRING_TABLE, selog_get_string_table, 51077d14) \
_(VL_API_SELOG_GET_STRING_TABLE_REPLY, selog_get_string_table_reply, 17fc26aa) \
_(VL_API_SELOG_TRACK_DUMP, selog_track_dump, 51077d14) \
_(VL_API_SELOG_TRACK_DETAILS, selog_track_details, 33dce766) \
_(VL_API_SELOG_EVENT_TYPE_DUMP, selog_event_type_dump, 51077d14) \
_(VL_API_SELOG_EVENT_TYPE_DETAILS, selog_event_type_details, 745bca80) \
_(VL_API_SELOG_EVENT_TYPE_STRING_DUMP, selog_event_type_string_dump, 6a7f2680) \
_(VL_API_SELOG_EVENT_TYPE_STRING_DETAILS, selog_event_type_string_details, 3718921d) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "selog.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_selog_printfun_types
#define included_selog_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_selog_printfun
#define included_selog_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "selog.api_tojson.h"
#include "selog.api_fromjson.h"

static inline u8 *vl_api_selog_get_shm_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_get_shm_t *a = va_arg (*args, vl_api_selog_get_shm_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_get_shm_t: */
    s = format(s, "vl_api_selog_get_shm_t:");
    return s;
}

static inline u8 *vl_api_selog_get_shm_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_get_shm_reply_t *a = va_arg (*args, vl_api_selog_get_shm_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_get_shm_reply_t: */
    s = format(s, "vl_api_selog_get_shm_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_selog_get_string_table_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_get_string_table_t *a = va_arg (*args, vl_api_selog_get_string_table_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_get_string_table_t: */
    s = format(s, "vl_api_selog_get_string_table_t:");
    return s;
}

static inline u8 *vl_api_selog_get_string_table_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_get_string_table_reply_t *a = va_arg (*args, vl_api_selog_get_string_table_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_get_string_table_reply_t: */
    s = format(s, "vl_api_selog_get_string_table_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->s) > 0) {
        s = format(s, "\n%Us: %U", format_white_space, indent, vl_api_format_string, (&a->s));
    } else {
        s = format(s, "\n%Us:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_selog_track_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_track_dump_t *a = va_arg (*args, vl_api_selog_track_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_track_dump_t: */
    s = format(s, "vl_api_selog_track_dump_t:");
    return s;
}

static inline u8 *vl_api_selog_track_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_track_details_t *a = va_arg (*args, vl_api_selog_track_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_track_details_t: */
    s = format(s, "vl_api_selog_track_details_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    if (vl_api_string_len(&a->name) > 0) {
        s = format(s, "\n%Uname: %U", format_white_space, indent, vl_api_format_string, (&a->name));
    } else {
        s = format(s, "\n%Uname:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_selog_event_type_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_event_type_dump_t *a = va_arg (*args, vl_api_selog_event_type_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_event_type_dump_t: */
    s = format(s, "vl_api_selog_event_type_dump_t:");
    return s;
}

static inline u8 *vl_api_selog_event_type_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_event_type_details_t *a = va_arg (*args, vl_api_selog_event_type_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_event_type_details_t: */
    s = format(s, "vl_api_selog_event_type_details_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Ufmt_args: %s", format_white_space, indent, a->fmt_args);
    if (vl_api_string_len(&a->fmt) > 0) {
        s = format(s, "\n%Ufmt: %U", format_white_space, indent, vl_api_format_string, (&a->fmt));
    } else {
        s = format(s, "\n%Ufmt:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_selog_event_type_string_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_event_type_string_dump_t *a = va_arg (*args, vl_api_selog_event_type_string_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_event_type_string_dump_t: */
    s = format(s, "vl_api_selog_event_type_string_dump_t:");
    s = format(s, "\n%Uevent_type_index: %u", format_white_space, indent, a->event_type_index);
    return s;
}

static inline u8 *vl_api_selog_event_type_string_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_selog_event_type_string_details_t *a = va_arg (*args, vl_api_selog_event_type_string_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_selog_event_type_string_details_t: */
    s = format(s, "vl_api_selog_event_type_string_details_t:");
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    if (vl_api_string_len(&a->s) > 0) {
        s = format(s, "\n%Us: %U", format_white_space, indent, vl_api_format_string, (&a->s));
    } else {
        s = format(s, "\n%Us:", format_white_space, indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_selog_endianfun
#define included_selog_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_selog_get_shm_t_endian (vl_api_selog_get_shm_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_selog_get_shm_reply_t_endian (vl_api_selog_get_shm_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_selog_get_string_table_t_endian (vl_api_selog_get_string_table_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_selog_get_string_table_reply_t_endian (vl_api_selog_get_string_table_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->s = a->s (no-op) */
}

static inline void vl_api_selog_track_dump_t_endian (vl_api_selog_track_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_selog_track_details_t_endian (vl_api_selog_track_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_selog_event_type_dump_t_endian (vl_api_selog_event_type_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_selog_event_type_details_t_endian (vl_api_selog_event_type_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
    /* a->fmt_args = a->fmt_args (no-op) */
    /* a->fmt = a->fmt (no-op) */
}

static inline void vl_api_selog_event_type_string_dump_t_endian (vl_api_selog_event_type_string_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->event_type_index = clib_net_to_host_u32(a->event_type_index);
}

static inline void vl_api_selog_event_type_string_details_t_endian (vl_api_selog_event_type_string_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->index = clib_net_to_host_u32(a->index);
    /* a->s = a->s (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_selog_calcsizefun
#define included_selog_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_get_shm_t_calc_size (vl_api_selog_get_shm_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_get_shm_reply_t_calc_size (vl_api_selog_get_shm_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_get_string_table_t_calc_size (vl_api_selog_get_string_table_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_get_string_table_reply_t_calc_size (vl_api_selog_get_string_table_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->s);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_track_dump_t_calc_size (vl_api_selog_track_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_track_details_t_calc_size (vl_api_selog_track_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_event_type_dump_t_calc_size (vl_api_selog_event_type_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_event_type_details_t_calc_size (vl_api_selog_event_type_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->fmt);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_event_type_string_dump_t_calc_size (vl_api_selog_event_type_string_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_selog_event_type_string_details_t_calc_size (vl_api_selog_event_type_string_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->s);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple


#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(selog.api, 0x58ce3561)

#endif

