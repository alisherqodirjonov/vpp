/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: snort.api
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
#warning no content included from snort.api
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
vl_msg_id(VL_API_SNORT_INSTANCE_CREATE, vl_api_snort_instance_create_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_CREATE_REPLY, vl_api_snort_instance_create_reply_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_DELETE, vl_api_snort_instance_delete_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_DELETE_REPLY, vl_api_snort_instance_delete_reply_t_handler)
vl_msg_id(VL_API_SNORT_CLIENT_DISCONNECT, vl_api_snort_client_disconnect_t_handler)
vl_msg_id(VL_API_SNORT_CLIENT_DISCONNECT_REPLY, vl_api_snort_client_disconnect_reply_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_DISCONNECT, vl_api_snort_instance_disconnect_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_DISCONNECT_REPLY, vl_api_snort_instance_disconnect_reply_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_ATTACH, vl_api_snort_interface_attach_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_ATTACH_REPLY, vl_api_snort_interface_attach_reply_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_DETACH, vl_api_snort_interface_detach_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_DETACH_REPLY, vl_api_snort_interface_detach_reply_t_handler)
vl_msg_id(VL_API_SNORT_INPUT_MODE_GET, vl_api_snort_input_mode_get_t_handler)
vl_msg_id(VL_API_SNORT_INPUT_MODE_GET_REPLY, vl_api_snort_input_mode_get_reply_t_handler)
vl_msg_id(VL_API_SNORT_INPUT_MODE_SET, vl_api_snort_input_mode_set_t_handler)
vl_msg_id(VL_API_SNORT_INPUT_MODE_SET_REPLY, vl_api_snort_input_mode_set_reply_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_GET, vl_api_snort_instance_get_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_GET_REPLY, vl_api_snort_instance_get_reply_t_handler)
vl_msg_id(VL_API_SNORT_INSTANCE_DETAILS, vl_api_snort_instance_details_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_GET, vl_api_snort_interface_get_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_GET_REPLY, vl_api_snort_interface_get_reply_t_handler)
vl_msg_id(VL_API_SNORT_INTERFACE_DETAILS, vl_api_snort_interface_details_t_handler)
vl_msg_id(VL_API_SNORT_CLIENT_GET, vl_api_snort_client_get_t_handler)
vl_msg_id(VL_API_SNORT_CLIENT_GET_REPLY, vl_api_snort_client_get_reply_t_handler)
vl_msg_id(VL_API_SNORT_CLIENT_DETAILS, vl_api_snort_client_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_snort_instance_create_t, 1)
vl_msg_name(vl_api_snort_instance_create_reply_t, 1)
vl_msg_name(vl_api_snort_instance_delete_t, 1)
vl_msg_name(vl_api_snort_instance_delete_reply_t, 1)
vl_msg_name(vl_api_snort_client_disconnect_t, 1)
vl_msg_name(vl_api_snort_client_disconnect_reply_t, 1)
vl_msg_name(vl_api_snort_instance_disconnect_t, 1)
vl_msg_name(vl_api_snort_instance_disconnect_reply_t, 1)
vl_msg_name(vl_api_snort_interface_attach_t, 1)
vl_msg_name(vl_api_snort_interface_attach_reply_t, 1)
vl_msg_name(vl_api_snort_interface_detach_t, 1)
vl_msg_name(vl_api_snort_interface_detach_reply_t, 1)
vl_msg_name(vl_api_snort_input_mode_get_t, 1)
vl_msg_name(vl_api_snort_input_mode_get_reply_t, 1)
vl_msg_name(vl_api_snort_input_mode_set_t, 1)
vl_msg_name(vl_api_snort_input_mode_set_reply_t, 1)
vl_msg_name(vl_api_snort_instance_get_t, 1)
vl_msg_name(vl_api_snort_instance_get_reply_t, 1)
vl_msg_name(vl_api_snort_instance_details_t, 1)
vl_msg_name(vl_api_snort_interface_get_t, 1)
vl_msg_name(vl_api_snort_interface_get_reply_t, 1)
vl_msg_name(vl_api_snort_interface_details_t, 1)
vl_msg_name(vl_api_snort_client_get_t, 1)
vl_msg_name(vl_api_snort_client_get_reply_t, 1)
vl_msg_name(vl_api_snort_client_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_snort \
_(VL_API_SNORT_INSTANCE_CREATE, snort_instance_create, 248cc390) \
_(VL_API_SNORT_INSTANCE_CREATE_REPLY, snort_instance_create_reply, e63a3fba) \
_(VL_API_SNORT_INSTANCE_DELETE, snort_instance_delete, 6981211a) \
_(VL_API_SNORT_INSTANCE_DELETE_REPLY, snort_instance_delete_reply, e8d4e804) \
_(VL_API_SNORT_CLIENT_DISCONNECT, snort_client_disconnect, 30a221a6) \
_(VL_API_SNORT_CLIENT_DISCONNECT_REPLY, snort_client_disconnect_reply, e8d4e804) \
_(VL_API_SNORT_INSTANCE_DISCONNECT, snort_instance_disconnect, 6981211a) \
_(VL_API_SNORT_INSTANCE_DISCONNECT_REPLY, snort_instance_disconnect_reply, e8d4e804) \
_(VL_API_SNORT_INTERFACE_ATTACH, snort_interface_attach, 79ceda89) \
_(VL_API_SNORT_INTERFACE_ATTACH_REPLY, snort_interface_attach_reply, e8d4e804) \
_(VL_API_SNORT_INTERFACE_DETACH, snort_interface_detach, 529cb13f) \
_(VL_API_SNORT_INTERFACE_DETACH_REPLY, snort_interface_detach_reply, e8d4e804) \
_(VL_API_SNORT_INPUT_MODE_GET, snort_input_mode_get, 51077d14) \
_(VL_API_SNORT_INPUT_MODE_GET_REPLY, snort_input_mode_get_reply, a18796bf) \
_(VL_API_SNORT_INPUT_MODE_SET, snort_input_mode_set, d595d008) \
_(VL_API_SNORT_INPUT_MODE_SET_REPLY, snort_input_mode_set_reply, e8d4e804) \
_(VL_API_SNORT_INSTANCE_GET, snort_instance_get, 07c37475) \
_(VL_API_SNORT_INSTANCE_GET_REPLY, snort_instance_get_reply, 53b48f5d) \
_(VL_API_SNORT_INSTANCE_DETAILS, snort_instance_details, abb60d49) \
_(VL_API_SNORT_INTERFACE_GET, snort_interface_get, 765a2424) \
_(VL_API_SNORT_INTERFACE_GET_REPLY, snort_interface_get_reply, 53b48f5d) \
_(VL_API_SNORT_INTERFACE_DETAILS, snort_interface_details, 52c75990) \
_(VL_API_SNORT_CLIENT_GET, snort_client_get, 51d54b70) \
_(VL_API_SNORT_CLIENT_GET_REPLY, snort_client_get_reply, 53b48f5d) \
_(VL_API_SNORT_CLIENT_DETAILS, snort_client_details, 7e29e6f5) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "snort.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_snort_printfun_types
#define included_snort_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_snort_printfun
#define included_snort_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "snort.api_tojson.h"
#include "snort.api_fromjson.h"

static inline u8 *vl_api_snort_instance_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_create_t *a = va_arg (*args, vl_api_snort_instance_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_create_t: */
    s = format(s, "vl_api_snort_instance_create_t:");
    s = format(s, "\n%Uqueue_size: %u", format_white_space, indent, a->queue_size);
    s = format(s, "\n%Udrop_on_disconnect: %u", format_white_space, indent, a->drop_on_disconnect);
    if (vl_api_string_len(&a->name) > 0) {
        s = format(s, "\n%Uname: %U", format_white_space, indent, vl_api_format_string, (&a->name));
    } else {
        s = format(s, "\n%Uname:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_snort_instance_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_create_reply_t *a = va_arg (*args, vl_api_snort_instance_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_create_reply_t: */
    s = format(s, "vl_api_snort_instance_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    return s;
}

static inline u8 *vl_api_snort_instance_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_delete_t *a = va_arg (*args, vl_api_snort_instance_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_delete_t: */
    s = format(s, "vl_api_snort_instance_delete_t:");
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    return s;
}

static inline u8 *vl_api_snort_instance_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_delete_reply_t *a = va_arg (*args, vl_api_snort_instance_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_delete_reply_t: */
    s = format(s, "vl_api_snort_instance_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_snort_client_disconnect_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_client_disconnect_t *a = va_arg (*args, vl_api_snort_client_disconnect_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_client_disconnect_t: */
    s = format(s, "vl_api_snort_client_disconnect_t:");
    s = format(s, "\n%Usnort_client_index: %u", format_white_space, indent, a->snort_client_index);
    return s;
}

static inline u8 *vl_api_snort_client_disconnect_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_client_disconnect_reply_t *a = va_arg (*args, vl_api_snort_client_disconnect_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_client_disconnect_reply_t: */
    s = format(s, "vl_api_snort_client_disconnect_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_snort_instance_disconnect_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_disconnect_t *a = va_arg (*args, vl_api_snort_instance_disconnect_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_disconnect_t: */
    s = format(s, "vl_api_snort_instance_disconnect_t:");
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    return s;
}

static inline u8 *vl_api_snort_instance_disconnect_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_disconnect_reply_t *a = va_arg (*args, vl_api_snort_instance_disconnect_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_disconnect_reply_t: */
    s = format(s, "vl_api_snort_instance_disconnect_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_snort_interface_attach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_attach_t *a = va_arg (*args, vl_api_snort_interface_attach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_attach_t: */
    s = format(s, "vl_api_snort_interface_attach_t:");
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    s = format(s, "\n%Usnort_dir: %u", format_white_space, indent, a->snort_dir);
    return s;
}

static inline u8 *vl_api_snort_interface_attach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_attach_reply_t *a = va_arg (*args, vl_api_snort_interface_attach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_attach_reply_t: */
    s = format(s, "vl_api_snort_interface_attach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_snort_interface_detach_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_detach_t *a = va_arg (*args, vl_api_snort_interface_detach_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_detach_t: */
    s = format(s, "vl_api_snort_interface_detach_t:");
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    return s;
}

static inline u8 *vl_api_snort_interface_detach_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_detach_reply_t *a = va_arg (*args, vl_api_snort_interface_detach_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_detach_reply_t: */
    s = format(s, "vl_api_snort_interface_detach_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_snort_input_mode_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_input_mode_get_t *a = va_arg (*args, vl_api_snort_input_mode_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_input_mode_get_t: */
    s = format(s, "vl_api_snort_input_mode_get_t:");
    return s;
}

static inline u8 *vl_api_snort_input_mode_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_input_mode_get_reply_t *a = va_arg (*args, vl_api_snort_input_mode_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_input_mode_get_reply_t: */
    s = format(s, "vl_api_snort_input_mode_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usnort_mode: %u", format_white_space, indent, a->snort_mode);
    return s;
}

static inline u8 *vl_api_snort_input_mode_set_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_input_mode_set_t *a = va_arg (*args, vl_api_snort_input_mode_set_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_input_mode_set_t: */
    s = format(s, "vl_api_snort_input_mode_set_t:");
    s = format(s, "\n%Uinput_mode: %u", format_white_space, indent, a->input_mode);
    return s;
}

static inline u8 *vl_api_snort_input_mode_set_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_input_mode_set_reply_t *a = va_arg (*args, vl_api_snort_input_mode_set_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_input_mode_set_reply_t: */
    s = format(s, "vl_api_snort_input_mode_set_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_snort_instance_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_get_t *a = va_arg (*args, vl_api_snort_instance_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_get_t: */
    s = format(s, "vl_api_snort_instance_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    return s;
}

static inline u8 *vl_api_snort_instance_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_get_reply_t *a = va_arg (*args, vl_api_snort_instance_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_get_reply_t: */
    s = format(s, "vl_api_snort_instance_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_snort_instance_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_instance_details_t *a = va_arg (*args, vl_api_snort_instance_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_instance_details_t: */
    s = format(s, "vl_api_snort_instance_details_t:");
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    s = format(s, "\n%Ushm_size: %u", format_white_space, indent, a->shm_size);
    s = format(s, "\n%Ushm_fd: %u", format_white_space, indent, a->shm_fd);
    s = format(s, "\n%Udrop_on_disconnect: %u", format_white_space, indent, a->drop_on_disconnect);
    s = format(s, "\n%Usnort_client_index: %u", format_white_space, indent, a->snort_client_index);
    if (vl_api_string_len(&a->name) > 0) {
        s = format(s, "\n%Uname: %U", format_white_space, indent, vl_api_format_string, (&a->name));
    } else {
        s = format(s, "\n%Uname:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_snort_interface_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_get_t *a = va_arg (*args, vl_api_snort_interface_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_get_t: */
    s = format(s, "vl_api_snort_interface_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    return s;
}

static inline u8 *vl_api_snort_interface_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_get_reply_t *a = va_arg (*args, vl_api_snort_interface_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_get_reply_t: */
    s = format(s, "vl_api_snort_interface_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_snort_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_interface_details_t *a = va_arg (*args, vl_api_snort_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_interface_details_t: */
    s = format(s, "vl_api_snort_interface_details_t:");
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    return s;
}

static inline u8 *vl_api_snort_client_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_client_get_t *a = va_arg (*args, vl_api_snort_client_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_client_get_t: */
    s = format(s, "vl_api_snort_client_get_t:");
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    s = format(s, "\n%Usnort_client_index: %u", format_white_space, indent, a->snort_client_index);
    return s;
}

static inline u8 *vl_api_snort_client_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_client_get_reply_t *a = va_arg (*args, vl_api_snort_client_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_client_get_reply_t: */
    s = format(s, "vl_api_snort_client_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucursor: %u", format_white_space, indent, a->cursor);
    return s;
}

static inline u8 *vl_api_snort_client_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_snort_client_details_t *a = va_arg (*args, vl_api_snort_client_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_snort_client_details_t: */
    s = format(s, "vl_api_snort_client_details_t:");
    s = format(s, "\n%Uinstance_index: %u", format_white_space, indent, a->instance_index);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_snort_endianfun
#define included_snort_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_snort_instance_create_t_endian (vl_api_snort_instance_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->queue_size = clib_net_to_host_u32(a->queue_size);
    /* a->drop_on_disconnect = a->drop_on_disconnect (no-op) */
    /* a->name = a->name (no-op) */
}

static inline void vl_api_snort_instance_create_reply_t_endian (vl_api_snort_instance_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
}

static inline void vl_api_snort_instance_delete_t_endian (vl_api_snort_instance_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
}

static inline void vl_api_snort_instance_delete_reply_t_endian (vl_api_snort_instance_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_snort_client_disconnect_t_endian (vl_api_snort_client_disconnect_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->snort_client_index = clib_net_to_host_u32(a->snort_client_index);
}

static inline void vl_api_snort_client_disconnect_reply_t_endian (vl_api_snort_client_disconnect_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_snort_instance_disconnect_t_endian (vl_api_snort_instance_disconnect_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
}

static inline void vl_api_snort_instance_disconnect_reply_t_endian (vl_api_snort_instance_disconnect_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_snort_interface_attach_t_endian (vl_api_snort_interface_attach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    /* a->snort_dir = a->snort_dir (no-op) */
}

static inline void vl_api_snort_interface_attach_reply_t_endian (vl_api_snort_interface_attach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_snort_interface_detach_t_endian (vl_api_snort_interface_detach_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
}

static inline void vl_api_snort_interface_detach_reply_t_endian (vl_api_snort_interface_detach_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_snort_input_mode_get_t_endian (vl_api_snort_input_mode_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_snort_input_mode_get_reply_t_endian (vl_api_snort_input_mode_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->snort_mode = clib_net_to_host_u32(a->snort_mode);
}

static inline void vl_api_snort_input_mode_set_t_endian (vl_api_snort_input_mode_set_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->input_mode = a->input_mode (no-op) */
}

static inline void vl_api_snort_input_mode_set_reply_t_endian (vl_api_snort_input_mode_set_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_snort_instance_get_t_endian (vl_api_snort_instance_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
}

static inline void vl_api_snort_instance_get_reply_t_endian (vl_api_snort_instance_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_snort_instance_details_t_endian (vl_api_snort_instance_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
    a->shm_size = clib_net_to_host_u32(a->shm_size);
    a->shm_fd = clib_net_to_host_u32(a->shm_fd);
    /* a->drop_on_disconnect = a->drop_on_disconnect (no-op) */
    a->snort_client_index = clib_net_to_host_u32(a->snort_client_index);
    /* a->name = a->name (no-op) */
}

static inline void vl_api_snort_interface_get_t_endian (vl_api_snort_interface_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
}

static inline void vl_api_snort_interface_get_reply_t_endian (vl_api_snort_interface_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_snort_interface_details_t_endian (vl_api_snort_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    a->instance_index = clib_net_to_host_u32(a->instance_index);
}

static inline void vl_api_snort_client_get_t_endian (vl_api_snort_client_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->cursor = clib_net_to_host_u32(a->cursor);
    a->snort_client_index = clib_net_to_host_u32(a->snort_client_index);
}

static inline void vl_api_snort_client_get_reply_t_endian (vl_api_snort_client_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->cursor = clib_net_to_host_u32(a->cursor);
}

static inline void vl_api_snort_client_details_t_endian (vl_api_snort_client_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->client_index = a->client_index (no-op) */
    a->instance_index = clib_net_to_host_u32(a->instance_index);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_snort_calcsizefun
#define included_snort_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_create_t_calc_size (vl_api_snort_instance_create_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_create_reply_t_calc_size (vl_api_snort_instance_create_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_delete_t_calc_size (vl_api_snort_instance_delete_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_delete_reply_t_calc_size (vl_api_snort_instance_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_client_disconnect_t_calc_size (vl_api_snort_client_disconnect_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_client_disconnect_reply_t_calc_size (vl_api_snort_client_disconnect_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_disconnect_t_calc_size (vl_api_snort_instance_disconnect_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_disconnect_reply_t_calc_size (vl_api_snort_instance_disconnect_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_attach_t_calc_size (vl_api_snort_interface_attach_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_attach_reply_t_calc_size (vl_api_snort_interface_attach_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_detach_t_calc_size (vl_api_snort_interface_detach_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_detach_reply_t_calc_size (vl_api_snort_interface_detach_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_input_mode_get_t_calc_size (vl_api_snort_input_mode_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_input_mode_get_reply_t_calc_size (vl_api_snort_input_mode_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_input_mode_set_t_calc_size (vl_api_snort_input_mode_set_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_input_mode_set_reply_t_calc_size (vl_api_snort_input_mode_set_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_get_t_calc_size (vl_api_snort_instance_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_get_reply_t_calc_size (vl_api_snort_instance_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_instance_details_t_calc_size (vl_api_snort_instance_details_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->name);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_get_t_calc_size (vl_api_snort_interface_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_get_reply_t_calc_size (vl_api_snort_interface_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_interface_details_t_calc_size (vl_api_snort_interface_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_client_get_t_calc_size (vl_api_snort_client_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_client_get_reply_t_calc_size (vl_api_snort_client_get_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_snort_client_details_t_calc_size (vl_api_snort_client_details_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(snort.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(snort.api, 0xf89115d4)

#endif

