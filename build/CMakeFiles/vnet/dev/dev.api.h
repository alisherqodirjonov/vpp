/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: dev.api
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
#warning no content included from dev.api
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
vl_msg_id(VL_API_DEV_ATTACH, vl_api_dev_attach_t_handler)
vl_msg_id(VL_API_DEV_ATTACH_REPLY, vl_api_dev_attach_reply_t_handler)
vl_msg_id(VL_API_DEV_DETACH, vl_api_dev_detach_t_handler)
vl_msg_id(VL_API_DEV_DETACH_REPLY, vl_api_dev_detach_reply_t_handler)
vl_msg_id(VL_API_DEV_CREATE_PORT_IF, vl_api_dev_create_port_if_t_handler)
vl_msg_id(VL_API_DEV_CREATE_PORT_IF_REPLY, vl_api_dev_create_port_if_reply_t_handler)
vl_msg_id(VL_API_DEV_REMOVE_PORT_IF, vl_api_dev_remove_port_if_t_handler)
vl_msg_id(VL_API_DEV_REMOVE_PORT_IF_REPLY, vl_api_dev_remove_port_if_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_dev_attach_t, 1)
vl_msg_name(vl_api_dev_attach_reply_t, 1)
vl_msg_name(vl_api_dev_detach_t, 1)
vl_msg_name(vl_api_dev_detach_reply_t, 1)
vl_msg_name(vl_api_dev_create_port_if_t, 1)
vl_msg_name(vl_api_dev_create_port_if_reply_t, 1)
vl_msg_name(vl_api_dev_remove_port_if_t, 1)
vl_msg_name(vl_api_dev_remove_port_if_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_dev \
_(VL_API_DEV_ATTACH, dev_attach, 44b725fc) \
_(VL_API_DEV_ATTACH_REPLY, dev_attach_reply, 6082b181) \
_(VL_API_DEV_DETACH, dev_detach, afae52d6) \
_(VL_API_DEV_DETACH_REPLY, dev_detach_reply, c8d74455) \
_(VL_API_DEV_CREATE_PORT_IF, dev_create_port_if, dbdf06f3) \
_(VL_API_DEV_CREATE_PORT_IF_REPLY, dev_create_port_if_reply, 243c2374) \
_(VL_API_DEV_REMOVE_PORT_IF, dev_remove_port_if, 529cb13f) \
_(VL_API_DEV_REMOVE_PORT_IF_REPLY, dev_remove_port_if_reply, c8d74455) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "dev.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_dev_printfun_types
#define included_dev_printfun_types

static inline u8 *format_vl_api_dev_flags_t (u8 *s, va_list * args)
{
    vl_api_dev_flags_t *a = va_arg (*args, vl_api_dev_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "VL_API_DEV_FLAG_NO_STATS");
    }
    return s;
}

static inline u8 *format_vl_api_dev_port_flags_t (u8 *s, va_list * args)
{
    vl_api_dev_port_flags_t *a = va_arg (*args, vl_api_dev_port_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "VL_API_DEV_PORT_FLAG_INTERRUPT_MODE");
    case 2:
        return format(s, "VL_API_DEV_PORT_FLAG_CONSISTENT_QP");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_dev_printfun
#define included_dev_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "dev.api_tojson.h"
#include "dev.api_fromjson.h"

static inline u8 *vl_api_dev_attach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_attach_t *a = va_arg (*args, vl_api_dev_attach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_attach_t: */
    s = format(s, "vl_api_dev_attach_t:");
    s = format(s, "\n%Udevice_id: %s", format_white_space, indent, a->device_id);
    s = format(s, "\n%Udriver_name: %s", format_white_space, indent, a->driver_name);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_dev_flags_t, &a->flags, indent);
    if (vl_api_string_len(&a->args) > 0) {
        s = format(s, "\n%Uargs: %U", format_white_space, indent, vl_api_format_string, (&a->args));
    } else {
        s = format(s, "\n%Uargs:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_dev_attach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_attach_reply_t *a = va_arg (*args, vl_api_dev_attach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_attach_reply_t: */
    s = format(s, "vl_api_dev_attach_reply_t:");
    s = format(s, "\n%Udev_index: %u", format_white_space, indent, a->dev_index);
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->error_string) > 0) {
        s = format(s, "\n%Uerror_string: %U", format_white_space, indent, vl_api_format_string, (&a->error_string));
    } else {
        s = format(s, "\n%Uerror_string:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_dev_detach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_detach_t *a = va_arg (*args, vl_api_dev_detach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_detach_t: */
    s = format(s, "vl_api_dev_detach_t:");
    s = format(s, "\n%Udev_index: %u", format_white_space, indent, a->dev_index);
    return s;
}

static inline u8 *vl_api_dev_detach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_detach_reply_t *a = va_arg (*args, vl_api_dev_detach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_detach_reply_t: */
    s = format(s, "vl_api_dev_detach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->error_string) > 0) {
        s = format(s, "\n%Uerror_string: %U", format_white_space, indent, vl_api_format_string, (&a->error_string));
    } else {
        s = format(s, "\n%Uerror_string:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_dev_create_port_if_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_create_port_if_t *a = va_arg (*args, vl_api_dev_create_port_if_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_create_port_if_t: */
    s = format(s, "vl_api_dev_create_port_if_t:");
    s = format(s, "\n%Udev_index: %u", format_white_space, indent, a->dev_index);
    s = format(s, "\n%Uintf_name: %s", format_white_space, indent, a->intf_name);
    s = format(s, "\n%Unum_rx_queues: %u", format_white_space, indent, a->num_rx_queues);
    s = format(s, "\n%Unum_tx_queues: %u", format_white_space, indent, a->num_tx_queues);
    s = format(s, "\n%Urx_queue_size: %u", format_white_space, indent, a->rx_queue_size);
    s = format(s, "\n%Utx_queue_size: %u", format_white_space, indent, a->tx_queue_size);
    s = format(s, "\n%Uport_id: %u", format_white_space, indent, a->port_id);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_dev_port_flags_t, &a->flags, indent);
    if (vl_api_string_len(&a->args) > 0) {
        s = format(s, "\n%Uargs: %U", format_white_space, indent, vl_api_format_string, (&a->args));
    } else {
        s = format(s, "\n%Uargs:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_dev_create_port_if_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_create_port_if_reply_t *a = va_arg (*args, vl_api_dev_create_port_if_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_create_port_if_reply_t: */
    s = format(s, "vl_api_dev_create_port_if_reply_t:");
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->error_string) > 0) {
        s = format(s, "\n%Uerror_string: %U", format_white_space, indent, vl_api_format_string, (&a->error_string));
    } else {
        s = format(s, "\n%Uerror_string:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_dev_remove_port_if_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_remove_port_if_t *a = va_arg (*args, vl_api_dev_remove_port_if_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_remove_port_if_t: */
    s = format(s, "vl_api_dev_remove_port_if_t:");
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    return s;
}

static inline u8 *vl_api_dev_remove_port_if_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_dev_remove_port_if_reply_t *a = va_arg (*args, vl_api_dev_remove_port_if_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_dev_remove_port_if_reply_t: */
    s = format(s, "vl_api_dev_remove_port_if_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    if (vl_api_string_len(&a->error_string) > 0) {
        s = format(s, "\n%Uerror_string: %U", format_white_space, indent, vl_api_format_string, (&a->error_string));
    } else {
        s = format(s, "\n%Uerror_string:", format_white_space, indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_dev_endianfun
#define included_dev_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_dev_flags_t_endian (vl_api_dev_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_dev_port_flags_t_endian (vl_api_dev_port_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_dev_attach_t_endian (vl_api_dev_attach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->device_id = a->device_id (no-op) */
    /* a->driver_name = a->driver_name (no-op) */
    vl_api_dev_flags_t_endian(&a->flags, to_net);
    /* a->args = a->args (no-op) */
}

static inline void vl_api_dev_attach_reply_t_endian (vl_api_dev_attach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->dev_index = clib_net_to_host_u32(a->dev_index);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->error_string = a->error_string (no-op) */
}

static inline void vl_api_dev_detach_t_endian (vl_api_dev_detach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->dev_index = clib_net_to_host_u32(a->dev_index);
}

static inline void vl_api_dev_detach_reply_t_endian (vl_api_dev_detach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->error_string = a->error_string (no-op) */
}

static inline void vl_api_dev_create_port_if_t_endian (vl_api_dev_create_port_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->dev_index = clib_net_to_host_u32(a->dev_index);
    /* a->intf_name = a->intf_name (no-op) */
    a->num_rx_queues = clib_net_to_host_u16(a->num_rx_queues);
    a->num_tx_queues = clib_net_to_host_u16(a->num_tx_queues);
    a->rx_queue_size = clib_net_to_host_u16(a->rx_queue_size);
    a->tx_queue_size = clib_net_to_host_u16(a->tx_queue_size);
    a->port_id = clib_net_to_host_u16(a->port_id);
    vl_api_dev_port_flags_t_endian(&a->flags, to_net);
    /* a->args = a->args (no-op) */
}

static inline void vl_api_dev_create_port_if_reply_t_endian (vl_api_dev_create_port_if_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->error_string = a->error_string (no-op) */
}

static inline void vl_api_dev_remove_port_if_t_endian (vl_api_dev_remove_port_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
}

static inline void vl_api_dev_remove_port_if_reply_t_endian (vl_api_dev_remove_port_if_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->error_string = a->error_string (no-op) */
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_dev_calcsizefun
#define included_dev_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_flags_t_calc_size (vl_api_dev_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_port_flags_t_calc_size (vl_api_dev_port_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_attach_t_calc_size (vl_api_dev_attach_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_dev_flags_t_calc_size(&a->flags) + vl_api_string_len(&a->args);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_attach_reply_t_calc_size (vl_api_dev_attach_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->error_string);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_detach_t_calc_size (vl_api_dev_detach_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_detach_reply_t_calc_size (vl_api_dev_detach_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->error_string);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_create_port_if_t_calc_size (vl_api_dev_create_port_if_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_dev_port_flags_t_calc_size(&a->flags) + vl_api_string_len(&a->args);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_create_port_if_reply_t_calc_size (vl_api_dev_create_port_if_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->error_string);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_remove_port_if_t_calc_size (vl_api_dev_remove_port_if_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_dev_remove_port_if_reply_t_calc_size (vl_api_dev_remove_port_if_reply_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->error_string);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(dev.api, 0, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(dev.api, 0x86eacf88)

#endif

