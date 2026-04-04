/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: flowprobe.api
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
#warning no content included from flowprobe.api
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
vl_msg_id(VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL, vl_api_flowprobe_tx_interface_add_del_t_handler)
vl_msg_id(VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY, vl_api_flowprobe_tx_interface_add_del_reply_t_handler)
vl_msg_id(VL_API_FLOWPROBE_INTERFACE_ADD_DEL, vl_api_flowprobe_interface_add_del_t_handler)
vl_msg_id(VL_API_FLOWPROBE_INTERFACE_ADD_DEL_REPLY, vl_api_flowprobe_interface_add_del_reply_t_handler)
vl_msg_id(VL_API_FLOWPROBE_INTERFACE_DUMP, vl_api_flowprobe_interface_dump_t_handler)
vl_msg_id(VL_API_FLOWPROBE_INTERFACE_DETAILS, vl_api_flowprobe_interface_details_t_handler)
vl_msg_id(VL_API_FLOWPROBE_PARAMS, vl_api_flowprobe_params_t_handler)
vl_msg_id(VL_API_FLOWPROBE_PARAMS_REPLY, vl_api_flowprobe_params_reply_t_handler)
vl_msg_id(VL_API_FLOWPROBE_SET_PARAMS, vl_api_flowprobe_set_params_t_handler)
vl_msg_id(VL_API_FLOWPROBE_SET_PARAMS_REPLY, vl_api_flowprobe_set_params_reply_t_handler)
vl_msg_id(VL_API_FLOWPROBE_GET_PARAMS, vl_api_flowprobe_get_params_t_handler)
vl_msg_id(VL_API_FLOWPROBE_GET_PARAMS_REPLY, vl_api_flowprobe_get_params_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_flowprobe_tx_interface_add_del_t, 1)
vl_msg_name(vl_api_flowprobe_tx_interface_add_del_reply_t, 1)
vl_msg_name(vl_api_flowprobe_interface_add_del_t, 1)
vl_msg_name(vl_api_flowprobe_interface_add_del_reply_t, 1)
vl_msg_name(vl_api_flowprobe_interface_dump_t, 1)
vl_msg_name(vl_api_flowprobe_interface_details_t, 1)
vl_msg_name(vl_api_flowprobe_params_t, 1)
vl_msg_name(vl_api_flowprobe_params_reply_t, 1)
vl_msg_name(vl_api_flowprobe_set_params_t, 1)
vl_msg_name(vl_api_flowprobe_set_params_reply_t, 1)
vl_msg_name(vl_api_flowprobe_get_params_t, 1)
vl_msg_name(vl_api_flowprobe_get_params_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_flowprobe \
_(VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL, flowprobe_tx_interface_add_del, b782c976) \
_(VL_API_FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY, flowprobe_tx_interface_add_del_reply, e8d4e804) \
_(VL_API_FLOWPROBE_INTERFACE_ADD_DEL, flowprobe_interface_add_del, 3420739c) \
_(VL_API_FLOWPROBE_INTERFACE_ADD_DEL_REPLY, flowprobe_interface_add_del_reply, e8d4e804) \
_(VL_API_FLOWPROBE_INTERFACE_DUMP, flowprobe_interface_dump, f9e6675e) \
_(VL_API_FLOWPROBE_INTERFACE_DETAILS, flowprobe_interface_details, 427d77e0) \
_(VL_API_FLOWPROBE_PARAMS, flowprobe_params, baa46c09) \
_(VL_API_FLOWPROBE_PARAMS_REPLY, flowprobe_params_reply, e8d4e804) \
_(VL_API_FLOWPROBE_SET_PARAMS, flowprobe_set_params, baa46c09) \
_(VL_API_FLOWPROBE_SET_PARAMS_REPLY, flowprobe_set_params_reply, e8d4e804) \
_(VL_API_FLOWPROBE_GET_PARAMS, flowprobe_get_params, 51077d14) \
_(VL_API_FLOWPROBE_GET_PARAMS_REPLY, flowprobe_get_params_reply, f350d621) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "flowprobe.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_flowprobe_printfun_types
#define included_flowprobe_printfun_types

static inline u8 *format_vl_api_flowprobe_which_flags_t (u8 *s, va_list * args)
{
    vl_api_flowprobe_which_flags_t *a = va_arg (*args, vl_api_flowprobe_which_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "FLOWPROBE_WHICH_FLAG_IP4");
    case 2:
        return format(s, "FLOWPROBE_WHICH_FLAG_L2");
    case 4:
        return format(s, "FLOWPROBE_WHICH_FLAG_IP6");
    }
    return s;
}

static inline u8 *format_vl_api_flowprobe_which_t (u8 *s, va_list * args)
{
    vl_api_flowprobe_which_t *a = va_arg (*args, vl_api_flowprobe_which_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "FLOWPROBE_WHICH_IP4");
    case 1:
        return format(s, "FLOWPROBE_WHICH_IP6");
    case 2:
        return format(s, "FLOWPROBE_WHICH_L2");
    }
    return s;
}

static inline u8 *format_vl_api_flowprobe_record_flags_t (u8 *s, va_list * args)
{
    vl_api_flowprobe_record_flags_t *a = va_arg (*args, vl_api_flowprobe_record_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "FLOWPROBE_RECORD_FLAG_L2");
    case 2:
        return format(s, "FLOWPROBE_RECORD_FLAG_L3");
    case 4:
        return format(s, "FLOWPROBE_RECORD_FLAG_L4");
    }
    return s;
}

static inline u8 *format_vl_api_flowprobe_direction_t (u8 *s, va_list * args)
{
    vl_api_flowprobe_direction_t *a = va_arg (*args, vl_api_flowprobe_direction_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "FLOWPROBE_DIRECTION_RX");
    case 1:
        return format(s, "FLOWPROBE_DIRECTION_TX");
    case 2:
        return format(s, "FLOWPROBE_DIRECTION_BOTH");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_flowprobe_printfun
#define included_flowprobe_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "flowprobe.api_tojson.h"
#include "flowprobe.api_fromjson.h"

static inline u8 *vl_api_flowprobe_tx_interface_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_tx_interface_add_del_t *a = va_arg (*args, vl_api_flowprobe_tx_interface_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_tx_interface_add_del_t: */
    s = format(s, "vl_api_flowprobe_tx_interface_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uwhich: %U", format_white_space, indent, format_vl_api_flowprobe_which_flags_t, &a->which, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_flowprobe_tx_interface_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_tx_interface_add_del_reply_t *a = va_arg (*args, vl_api_flowprobe_tx_interface_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_tx_interface_add_del_reply_t: */
    s = format(s, "vl_api_flowprobe_tx_interface_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_flowprobe_interface_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_interface_add_del_t *a = va_arg (*args, vl_api_flowprobe_interface_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_interface_add_del_t: */
    s = format(s, "vl_api_flowprobe_interface_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uwhich: %U", format_white_space, indent, format_vl_api_flowprobe_which_t, &a->which, indent);
    s = format(s, "\n%Udirection: %U", format_white_space, indent, format_vl_api_flowprobe_direction_t, &a->direction, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_flowprobe_interface_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_interface_add_del_reply_t *a = va_arg (*args, vl_api_flowprobe_interface_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_interface_add_del_reply_t: */
    s = format(s, "vl_api_flowprobe_interface_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_flowprobe_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_interface_dump_t *a = va_arg (*args, vl_api_flowprobe_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_interface_dump_t: */
    s = format(s, "vl_api_flowprobe_interface_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_flowprobe_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_interface_details_t *a = va_arg (*args, vl_api_flowprobe_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_interface_details_t: */
    s = format(s, "vl_api_flowprobe_interface_details_t:");
    s = format(s, "\n%Uwhich: %U", format_white_space, indent, format_vl_api_flowprobe_which_t, &a->which, indent);
    s = format(s, "\n%Udirection: %U", format_white_space, indent, format_vl_api_flowprobe_direction_t, &a->direction, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_flowprobe_params_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_params_t *a = va_arg (*args, vl_api_flowprobe_params_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_params_t: */
    s = format(s, "vl_api_flowprobe_params_t:");
    s = format(s, "\n%Urecord_flags: %U", format_white_space, indent, format_vl_api_flowprobe_record_flags_t, &a->record_flags, indent);
    s = format(s, "\n%Uactive_timer: %u", format_white_space, indent, a->active_timer);
    s = format(s, "\n%Upassive_timer: %u", format_white_space, indent, a->passive_timer);
    return s;
}

static inline u8 *vl_api_flowprobe_params_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_params_reply_t *a = va_arg (*args, vl_api_flowprobe_params_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_params_reply_t: */
    s = format(s, "vl_api_flowprobe_params_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_flowprobe_set_params_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_set_params_t *a = va_arg (*args, vl_api_flowprobe_set_params_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_set_params_t: */
    s = format(s, "vl_api_flowprobe_set_params_t:");
    s = format(s, "\n%Urecord_flags: %U", format_white_space, indent, format_vl_api_flowprobe_record_flags_t, &a->record_flags, indent);
    s = format(s, "\n%Uactive_timer: %u", format_white_space, indent, a->active_timer);
    s = format(s, "\n%Upassive_timer: %u", format_white_space, indent, a->passive_timer);
    return s;
}

static inline u8 *vl_api_flowprobe_set_params_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_set_params_reply_t *a = va_arg (*args, vl_api_flowprobe_set_params_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_set_params_reply_t: */
    s = format(s, "vl_api_flowprobe_set_params_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_flowprobe_get_params_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_get_params_t *a = va_arg (*args, vl_api_flowprobe_get_params_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_get_params_t: */
    s = format(s, "vl_api_flowprobe_get_params_t:");
    return s;
}

static inline u8 *vl_api_flowprobe_get_params_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_flowprobe_get_params_reply_t *a = va_arg (*args, vl_api_flowprobe_get_params_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_flowprobe_get_params_reply_t: */
    s = format(s, "vl_api_flowprobe_get_params_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Urecord_flags: %U", format_white_space, indent, format_vl_api_flowprobe_record_flags_t, &a->record_flags, indent);
    s = format(s, "\n%Uactive_timer: %u", format_white_space, indent, a->active_timer);
    s = format(s, "\n%Upassive_timer: %u", format_white_space, indent, a->passive_timer);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_flowprobe_endianfun
#define included_flowprobe_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_flowprobe_which_flags_t_endian (vl_api_flowprobe_which_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->flowprobe_which_flags = a->flowprobe_which_flags (no-op) */
}

static inline void vl_api_flowprobe_which_t_endian (vl_api_flowprobe_which_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->flowprobe_which = a->flowprobe_which (no-op) */
}

static inline void vl_api_flowprobe_record_flags_t_endian (vl_api_flowprobe_record_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->flowprobe_record_flags = a->flowprobe_record_flags (no-op) */
}

static inline void vl_api_flowprobe_direction_t_endian (vl_api_flowprobe_direction_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->flowprobe_direction = a->flowprobe_direction (no-op) */
}

static inline void vl_api_flowprobe_tx_interface_add_del_t_endian (vl_api_flowprobe_tx_interface_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_flowprobe_which_flags_t_endian(&a->which, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_flowprobe_tx_interface_add_del_reply_t_endian (vl_api_flowprobe_tx_interface_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_flowprobe_interface_add_del_t_endian (vl_api_flowprobe_interface_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_flowprobe_which_t_endian(&a->which, to_net);
    vl_api_flowprobe_direction_t_endian(&a->direction, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_flowprobe_interface_add_del_reply_t_endian (vl_api_flowprobe_interface_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_flowprobe_interface_dump_t_endian (vl_api_flowprobe_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_flowprobe_interface_details_t_endian (vl_api_flowprobe_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_flowprobe_which_t_endian(&a->which, to_net);
    vl_api_flowprobe_direction_t_endian(&a->direction, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_flowprobe_params_t_endian (vl_api_flowprobe_params_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_flowprobe_record_flags_t_endian(&a->record_flags, to_net);
    a->active_timer = clib_net_to_host_u32(a->active_timer);
    a->passive_timer = clib_net_to_host_u32(a->passive_timer);
}

static inline void vl_api_flowprobe_params_reply_t_endian (vl_api_flowprobe_params_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_flowprobe_set_params_t_endian (vl_api_flowprobe_set_params_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_flowprobe_record_flags_t_endian(&a->record_flags, to_net);
    a->active_timer = clib_net_to_host_u32(a->active_timer);
    a->passive_timer = clib_net_to_host_u32(a->passive_timer);
}

static inline void vl_api_flowprobe_set_params_reply_t_endian (vl_api_flowprobe_set_params_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_flowprobe_get_params_t_endian (vl_api_flowprobe_get_params_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_flowprobe_get_params_reply_t_endian (vl_api_flowprobe_get_params_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_flowprobe_record_flags_t_endian(&a->record_flags, to_net);
    a->active_timer = clib_net_to_host_u32(a->active_timer);
    a->passive_timer = clib_net_to_host_u32(a->passive_timer);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_flowprobe_calcsizefun
#define included_flowprobe_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_which_flags_t_calc_size (vl_api_flowprobe_which_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_which_t_calc_size (vl_api_flowprobe_which_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_record_flags_t_calc_size (vl_api_flowprobe_record_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_direction_t_calc_size (vl_api_flowprobe_direction_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_tx_interface_add_del_t_calc_size (vl_api_flowprobe_tx_interface_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->which) + vl_api_flowprobe_which_flags_t_calc_size(&a->which) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_tx_interface_add_del_reply_t_calc_size (vl_api_flowprobe_tx_interface_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_interface_add_del_t_calc_size (vl_api_flowprobe_interface_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->which) + vl_api_flowprobe_which_t_calc_size(&a->which) - sizeof(a->direction) + vl_api_flowprobe_direction_t_calc_size(&a->direction) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_interface_add_del_reply_t_calc_size (vl_api_flowprobe_interface_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_interface_dump_t_calc_size (vl_api_flowprobe_interface_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_interface_details_t_calc_size (vl_api_flowprobe_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->which) + vl_api_flowprobe_which_t_calc_size(&a->which) - sizeof(a->direction) + vl_api_flowprobe_direction_t_calc_size(&a->direction) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_params_t_calc_size (vl_api_flowprobe_params_t *a)
{
      return sizeof(*a) - sizeof(a->record_flags) + vl_api_flowprobe_record_flags_t_calc_size(&a->record_flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_params_reply_t_calc_size (vl_api_flowprobe_params_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_set_params_t_calc_size (vl_api_flowprobe_set_params_t *a)
{
      return sizeof(*a) - sizeof(a->record_flags) + vl_api_flowprobe_record_flags_t_calc_size(&a->record_flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_set_params_reply_t_calc_size (vl_api_flowprobe_set_params_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_get_params_t_calc_size (vl_api_flowprobe_get_params_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_flowprobe_get_params_reply_t_calc_size (vl_api_flowprobe_get_params_reply_t *a)
{
      return sizeof(*a) - sizeof(a->record_flags) + vl_api_flowprobe_record_flags_t_calc_size(&a->record_flags);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(flowprobe.api, 2, 1, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(flowprobe.api, 0x668f737a)

#endif

