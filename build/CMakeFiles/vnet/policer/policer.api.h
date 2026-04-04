/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: policer.api
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
#warning no content included from policer.api
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
#include <vnet/policer/policer_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_POLICER_BIND, vl_api_policer_bind_t_handler)
vl_msg_id(VL_API_POLICER_BIND_REPLY, vl_api_policer_bind_reply_t_handler)
vl_msg_id(VL_API_POLICER_BIND_V2, vl_api_policer_bind_v2_t_handler)
vl_msg_id(VL_API_POLICER_BIND_V2_REPLY, vl_api_policer_bind_v2_reply_t_handler)
vl_msg_id(VL_API_POLICER_INPUT, vl_api_policer_input_t_handler)
vl_msg_id(VL_API_POLICER_INPUT_REPLY, vl_api_policer_input_reply_t_handler)
vl_msg_id(VL_API_POLICER_INPUT_V2, vl_api_policer_input_v2_t_handler)
vl_msg_id(VL_API_POLICER_INPUT_V2_REPLY, vl_api_policer_input_v2_reply_t_handler)
vl_msg_id(VL_API_POLICER_OUTPUT, vl_api_policer_output_t_handler)
vl_msg_id(VL_API_POLICER_OUTPUT_REPLY, vl_api_policer_output_reply_t_handler)
vl_msg_id(VL_API_POLICER_OUTPUT_V2, vl_api_policer_output_v2_t_handler)
vl_msg_id(VL_API_POLICER_OUTPUT_V2_REPLY, vl_api_policer_output_v2_reply_t_handler)
vl_msg_id(VL_API_POLICER_ADD_DEL, vl_api_policer_add_del_t_handler)
vl_msg_id(VL_API_POLICER_ADD, vl_api_policer_add_t_handler)
vl_msg_id(VL_API_POLICER_DEL, vl_api_policer_del_t_handler)
vl_msg_id(VL_API_POLICER_DEL_REPLY, vl_api_policer_del_reply_t_handler)
vl_msg_id(VL_API_POLICER_UPDATE, vl_api_policer_update_t_handler)
vl_msg_id(VL_API_POLICER_UPDATE_REPLY, vl_api_policer_update_reply_t_handler)
vl_msg_id(VL_API_POLICER_RESET, vl_api_policer_reset_t_handler)
vl_msg_id(VL_API_POLICER_RESET_REPLY, vl_api_policer_reset_reply_t_handler)
vl_msg_id(VL_API_POLICER_ADD_DEL_REPLY, vl_api_policer_add_del_reply_t_handler)
vl_msg_id(VL_API_POLICER_ADD_REPLY, vl_api_policer_add_reply_t_handler)
vl_msg_id(VL_API_POLICER_DUMP, vl_api_policer_dump_t_handler)
vl_msg_id(VL_API_POLICER_DUMP_V2, vl_api_policer_dump_v2_t_handler)
vl_msg_id(VL_API_POLICER_DETAILS, vl_api_policer_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_policer_bind_t, 1)
vl_msg_name(vl_api_policer_bind_reply_t, 1)
vl_msg_name(vl_api_policer_bind_v2_t, 1)
vl_msg_name(vl_api_policer_bind_v2_reply_t, 1)
vl_msg_name(vl_api_policer_input_t, 1)
vl_msg_name(vl_api_policer_input_reply_t, 1)
vl_msg_name(vl_api_policer_input_v2_t, 1)
vl_msg_name(vl_api_policer_input_v2_reply_t, 1)
vl_msg_name(vl_api_policer_output_t, 1)
vl_msg_name(vl_api_policer_output_reply_t, 1)
vl_msg_name(vl_api_policer_output_v2_t, 1)
vl_msg_name(vl_api_policer_output_v2_reply_t, 1)
vl_msg_name(vl_api_policer_add_del_t, 1)
vl_msg_name(vl_api_policer_add_t, 1)
vl_msg_name(vl_api_policer_del_t, 1)
vl_msg_name(vl_api_policer_del_reply_t, 1)
vl_msg_name(vl_api_policer_update_t, 1)
vl_msg_name(vl_api_policer_update_reply_t, 1)
vl_msg_name(vl_api_policer_reset_t, 1)
vl_msg_name(vl_api_policer_reset_reply_t, 1)
vl_msg_name(vl_api_policer_add_del_reply_t, 1)
vl_msg_name(vl_api_policer_add_reply_t, 1)
vl_msg_name(vl_api_policer_dump_t, 1)
vl_msg_name(vl_api_policer_dump_v2_t, 1)
vl_msg_name(vl_api_policer_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_policer \
_(VL_API_POLICER_BIND, policer_bind, dcf516f9) \
_(VL_API_POLICER_BIND_REPLY, policer_bind_reply, e8d4e804) \
_(VL_API_POLICER_BIND_V2, policer_bind_v2, f87bd3c0) \
_(VL_API_POLICER_BIND_V2_REPLY, policer_bind_v2_reply, e8d4e804) \
_(VL_API_POLICER_INPUT, policer_input, 233f0ef5) \
_(VL_API_POLICER_INPUT_REPLY, policer_input_reply, e8d4e804) \
_(VL_API_POLICER_INPUT_V2, policer_input_v2, 8388eb84) \
_(VL_API_POLICER_INPUT_V2_REPLY, policer_input_v2_reply, e8d4e804) \
_(VL_API_POLICER_OUTPUT, policer_output, 233f0ef5) \
_(VL_API_POLICER_OUTPUT_REPLY, policer_output_reply, e8d4e804) \
_(VL_API_POLICER_OUTPUT_V2, policer_output_v2, 8388eb84) \
_(VL_API_POLICER_OUTPUT_V2_REPLY, policer_output_v2_reply, e8d4e804) \
_(VL_API_POLICER_ADD_DEL, policer_add_del, 2b31dd38) \
_(VL_API_POLICER_ADD, policer_add, 4d949e35) \
_(VL_API_POLICER_DEL, policer_del, 7ff7912e) \
_(VL_API_POLICER_DEL_REPLY, policer_del_reply, e8d4e804) \
_(VL_API_POLICER_UPDATE, policer_update, fd039ef0) \
_(VL_API_POLICER_UPDATE_REPLY, policer_update_reply, e8d4e804) \
_(VL_API_POLICER_RESET, policer_reset, 7ff7912e) \
_(VL_API_POLICER_RESET_REPLY, policer_reset_reply, e8d4e804) \
_(VL_API_POLICER_ADD_DEL_REPLY, policer_add_del_reply, a177cef2) \
_(VL_API_POLICER_ADD_REPLY, policer_add_reply, a177cef2) \
_(VL_API_POLICER_DUMP, policer_dump, 35f1ae0f) \
_(VL_API_POLICER_DUMP_V2, policer_dump_v2, 7ff7912e) \
_(VL_API_POLICER_DETAILS, policer_details, 72d0e248) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "policer.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_policer_printfun_types
#define included_policer_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_policer_printfun
#define included_policer_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "policer.api_tojson.h"
#include "policer.api_fromjson.h"

static inline u8 *vl_api_policer_bind_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_bind_t *a = va_arg (*args, vl_api_policer_bind_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_bind_t: */
    s = format(s, "vl_api_policer_bind_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Uworker_index: %u", format_white_space, indent, a->worker_index);
    s = format(s, "\n%Ubind_enable: %u", format_white_space, indent, a->bind_enable);
    return s;
}

static inline u8 *vl_api_policer_bind_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_bind_reply_t *a = va_arg (*args, vl_api_policer_bind_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_bind_reply_t: */
    s = format(s, "vl_api_policer_bind_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_bind_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_bind_v2_t *a = va_arg (*args, vl_api_policer_bind_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_bind_v2_t: */
    s = format(s, "vl_api_policer_bind_v2_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    s = format(s, "\n%Uworker_index: %u", format_white_space, indent, a->worker_index);
    s = format(s, "\n%Ubind_enable: %u", format_white_space, indent, a->bind_enable);
    return s;
}

static inline u8 *vl_api_policer_bind_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_bind_v2_reply_t *a = va_arg (*args, vl_api_policer_bind_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_bind_v2_reply_t: */
    s = format(s, "vl_api_policer_bind_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_input_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_input_t *a = va_arg (*args, vl_api_policer_input_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_input_t: */
    s = format(s, "vl_api_policer_input_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uapply: %u", format_white_space, indent, a->apply);
    return s;
}

static inline u8 *vl_api_policer_input_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_input_reply_t *a = va_arg (*args, vl_api_policer_input_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_input_reply_t: */
    s = format(s, "vl_api_policer_input_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_input_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_input_v2_t *a = va_arg (*args, vl_api_policer_input_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_input_v2_t: */
    s = format(s, "vl_api_policer_input_v2_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uapply: %u", format_white_space, indent, a->apply);
    return s;
}

static inline u8 *vl_api_policer_input_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_input_v2_reply_t *a = va_arg (*args, vl_api_policer_input_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_input_v2_reply_t: */
    s = format(s, "vl_api_policer_input_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_output_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_output_t *a = va_arg (*args, vl_api_policer_output_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_output_t: */
    s = format(s, "vl_api_policer_output_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uapply: %u", format_white_space, indent, a->apply);
    return s;
}

static inline u8 *vl_api_policer_output_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_output_reply_t *a = va_arg (*args, vl_api_policer_output_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_output_reply_t: */
    s = format(s, "vl_api_policer_output_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_output_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_output_v2_t *a = va_arg (*args, vl_api_policer_output_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_output_v2_t: */
    s = format(s, "vl_api_policer_output_v2_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uapply: %u", format_white_space, indent, a->apply);
    return s;
}

static inline u8 *vl_api_policer_output_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_output_v2_reply_t *a = va_arg (*args, vl_api_policer_output_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_output_v2_reply_t: */
    s = format(s, "vl_api_policer_output_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_add_del_t *a = va_arg (*args, vl_api_policer_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_add_del_t: */
    s = format(s, "vl_api_policer_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Ucir: %u", format_white_space, indent, a->cir);
    s = format(s, "\n%Ueir: %u", format_white_space, indent, a->eir);
    s = format(s, "\n%Ucb: %llu", format_white_space, indent, a->cb);
    s = format(s, "\n%Ueb: %llu", format_white_space, indent, a->eb);
    s = format(s, "\n%Urate_type: %U", format_white_space, indent, format_vl_api_sse2_qos_rate_type_t, &a->rate_type, indent);
    s = format(s, "\n%Uround_type: %U", format_white_space, indent, format_vl_api_sse2_qos_round_type_t, &a->round_type, indent);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_sse2_qos_policer_type_t, &a->type, indent);
    s = format(s, "\n%Ucolor_aware: %u", format_white_space, indent, a->color_aware);
    s = format(s, "\n%Uconform_action: %U", format_white_space, indent, format_vl_api_sse2_qos_action_t, &a->conform_action, indent);
    s = format(s, "\n%Uexceed_action: %U", format_white_space, indent, format_vl_api_sse2_qos_action_t, &a->exceed_action, indent);
    s = format(s, "\n%Uviolate_action: %U", format_white_space, indent, format_vl_api_sse2_qos_action_t, &a->violate_action, indent);
    return s;
}

static inline u8 *vl_api_policer_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_add_t *a = va_arg (*args, vl_api_policer_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_add_t: */
    s = format(s, "vl_api_policer_add_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Uinfos: %U", format_white_space, indent, format_vl_api_policer_config_t, &a->infos, indent);
    return s;
}

static inline u8 *vl_api_policer_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_del_t *a = va_arg (*args, vl_api_policer_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_del_t: */
    s = format(s, "vl_api_policer_del_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    return s;
}

static inline u8 *vl_api_policer_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_del_reply_t *a = va_arg (*args, vl_api_policer_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_del_reply_t: */
    s = format(s, "vl_api_policer_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_update_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_update_t *a = va_arg (*args, vl_api_policer_update_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_update_t: */
    s = format(s, "vl_api_policer_update_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    s = format(s, "\n%Uinfos: %U", format_white_space, indent, format_vl_api_policer_config_t, &a->infos, indent);
    return s;
}

static inline u8 *vl_api_policer_update_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_update_reply_t *a = va_arg (*args, vl_api_policer_update_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_update_reply_t: */
    s = format(s, "vl_api_policer_update_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_reset_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_reset_t *a = va_arg (*args, vl_api_policer_reset_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_reset_t: */
    s = format(s, "vl_api_policer_reset_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    return s;
}

static inline u8 *vl_api_policer_reset_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_reset_reply_t *a = va_arg (*args, vl_api_policer_reset_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_reset_reply_t: */
    s = format(s, "vl_api_policer_reset_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_policer_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_add_del_reply_t *a = va_arg (*args, vl_api_policer_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_add_del_reply_t: */
    s = format(s, "vl_api_policer_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    return s;
}

static inline u8 *vl_api_policer_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_add_reply_t *a = va_arg (*args, vl_api_policer_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_add_reply_t: */
    s = format(s, "vl_api_policer_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    return s;
}

static inline u8 *vl_api_policer_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_dump_t *a = va_arg (*args, vl_api_policer_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_dump_t: */
    s = format(s, "vl_api_policer_dump_t:");
    s = format(s, "\n%Umatch_name_valid: %u", format_white_space, indent, a->match_name_valid);
    s = format(s, "\n%Umatch_name: %s", format_white_space, indent, a->match_name);
    return s;
}

static inline u8 *vl_api_policer_dump_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_dump_v2_t *a = va_arg (*args, vl_api_policer_dump_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_dump_v2_t: */
    s = format(s, "vl_api_policer_dump_v2_t:");
    s = format(s, "\n%Upolicer_index: %u", format_white_space, indent, a->policer_index);
    return s;
}

static inline u8 *vl_api_policer_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_policer_details_t *a = va_arg (*args, vl_api_policer_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_policer_details_t: */
    s = format(s, "vl_api_policer_details_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Ucir: %u", format_white_space, indent, a->cir);
    s = format(s, "\n%Ueir: %u", format_white_space, indent, a->eir);
    s = format(s, "\n%Ucb: %llu", format_white_space, indent, a->cb);
    s = format(s, "\n%Ueb: %llu", format_white_space, indent, a->eb);
    s = format(s, "\n%Urate_type: %U", format_white_space, indent, format_vl_api_sse2_qos_rate_type_t, &a->rate_type, indent);
    s = format(s, "\n%Uround_type: %U", format_white_space, indent, format_vl_api_sse2_qos_round_type_t, &a->round_type, indent);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_sse2_qos_policer_type_t, &a->type, indent);
    s = format(s, "\n%Uconform_action: %U", format_white_space, indent, format_vl_api_sse2_qos_action_t, &a->conform_action, indent);
    s = format(s, "\n%Uexceed_action: %U", format_white_space, indent, format_vl_api_sse2_qos_action_t, &a->exceed_action, indent);
    s = format(s, "\n%Uviolate_action: %U", format_white_space, indent, format_vl_api_sse2_qos_action_t, &a->violate_action, indent);
    s = format(s, "\n%Usingle_rate: %u", format_white_space, indent, a->single_rate);
    s = format(s, "\n%Ucolor_aware: %u", format_white_space, indent, a->color_aware);
    s = format(s, "\n%Uscale: %u", format_white_space, indent, a->scale);
    s = format(s, "\n%Ucir_tokens_per_period: %u", format_white_space, indent, a->cir_tokens_per_period);
    s = format(s, "\n%Upir_tokens_per_period: %u", format_white_space, indent, a->pir_tokens_per_period);
    s = format(s, "\n%Ucurrent_limit: %u", format_white_space, indent, a->current_limit);
    s = format(s, "\n%Ucurrent_bucket: %u", format_white_space, indent, a->current_bucket);
    s = format(s, "\n%Uextended_limit: %u", format_white_space, indent, a->extended_limit);
    s = format(s, "\n%Uextended_bucket: %u", format_white_space, indent, a->extended_bucket);
    s = format(s, "\n%Ulast_update_time: %llu", format_white_space, indent, a->last_update_time);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_policer_endianfun
#define included_policer_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_policer_bind_t_endian (vl_api_policer_bind_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
    a->worker_index = clib_net_to_host_u32(a->worker_index);
    /* a->bind_enable = a->bind_enable (no-op) */
}

static inline void vl_api_policer_bind_reply_t_endian (vl_api_policer_bind_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_bind_v2_t_endian (vl_api_policer_bind_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
    a->worker_index = clib_net_to_host_u32(a->worker_index);
    /* a->bind_enable = a->bind_enable (no-op) */
}

static inline void vl_api_policer_bind_v2_reply_t_endian (vl_api_policer_bind_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_input_t_endian (vl_api_policer_input_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->apply = a->apply (no-op) */
}

static inline void vl_api_policer_input_reply_t_endian (vl_api_policer_input_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_input_v2_t_endian (vl_api_policer_input_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->apply = a->apply (no-op) */
}

static inline void vl_api_policer_input_v2_reply_t_endian (vl_api_policer_input_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_output_t_endian (vl_api_policer_output_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->apply = a->apply (no-op) */
}

static inline void vl_api_policer_output_reply_t_endian (vl_api_policer_output_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_output_v2_t_endian (vl_api_policer_output_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->apply = a->apply (no-op) */
}

static inline void vl_api_policer_output_v2_reply_t_endian (vl_api_policer_output_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_add_del_t_endian (vl_api_policer_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->name = a->name (no-op) */
    a->cir = clib_net_to_host_u32(a->cir);
    a->eir = clib_net_to_host_u32(a->eir);
    a->cb = clib_net_to_host_u64(a->cb);
    a->eb = clib_net_to_host_u64(a->eb);
    vl_api_sse2_qos_rate_type_t_endian(&a->rate_type, to_net);
    vl_api_sse2_qos_round_type_t_endian(&a->round_type, to_net);
    vl_api_sse2_qos_policer_type_t_endian(&a->type, to_net);
    /* a->color_aware = a->color_aware (no-op) */
    vl_api_sse2_qos_action_t_endian(&a->conform_action, to_net);
    vl_api_sse2_qos_action_t_endian(&a->exceed_action, to_net);
    vl_api_sse2_qos_action_t_endian(&a->violate_action, to_net);
}

static inline void vl_api_policer_add_t_endian (vl_api_policer_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
    vl_api_policer_config_t_endian(&a->infos, to_net);
}

static inline void vl_api_policer_del_t_endian (vl_api_policer_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
}

static inline void vl_api_policer_del_reply_t_endian (vl_api_policer_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_update_t_endian (vl_api_policer_update_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
    vl_api_policer_config_t_endian(&a->infos, to_net);
}

static inline void vl_api_policer_update_reply_t_endian (vl_api_policer_update_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_reset_t_endian (vl_api_policer_reset_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
}

static inline void vl_api_policer_reset_reply_t_endian (vl_api_policer_reset_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_policer_add_del_reply_t_endian (vl_api_policer_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
}

static inline void vl_api_policer_add_reply_t_endian (vl_api_policer_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
}

static inline void vl_api_policer_dump_t_endian (vl_api_policer_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->match_name_valid = a->match_name_valid (no-op) */
    /* a->match_name = a->match_name (no-op) */
}

static inline void vl_api_policer_dump_v2_t_endian (vl_api_policer_dump_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->policer_index = clib_net_to_host_u32(a->policer_index);
}

static inline void vl_api_policer_details_t_endian (vl_api_policer_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
    a->cir = clib_net_to_host_u32(a->cir);
    a->eir = clib_net_to_host_u32(a->eir);
    a->cb = clib_net_to_host_u64(a->cb);
    a->eb = clib_net_to_host_u64(a->eb);
    vl_api_sse2_qos_rate_type_t_endian(&a->rate_type, to_net);
    vl_api_sse2_qos_round_type_t_endian(&a->round_type, to_net);
    vl_api_sse2_qos_policer_type_t_endian(&a->type, to_net);
    vl_api_sse2_qos_action_t_endian(&a->conform_action, to_net);
    vl_api_sse2_qos_action_t_endian(&a->exceed_action, to_net);
    vl_api_sse2_qos_action_t_endian(&a->violate_action, to_net);
    /* a->single_rate = a->single_rate (no-op) */
    /* a->color_aware = a->color_aware (no-op) */
    a->scale = clib_net_to_host_u32(a->scale);
    a->cir_tokens_per_period = clib_net_to_host_u32(a->cir_tokens_per_period);
    a->pir_tokens_per_period = clib_net_to_host_u32(a->pir_tokens_per_period);
    a->current_limit = clib_net_to_host_u32(a->current_limit);
    a->current_bucket = clib_net_to_host_u32(a->current_bucket);
    a->extended_limit = clib_net_to_host_u32(a->extended_limit);
    a->extended_bucket = clib_net_to_host_u32(a->extended_bucket);
    a->last_update_time = clib_net_to_host_u64(a->last_update_time);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_policer_calcsizefun
#define included_policer_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_bind_t_calc_size (vl_api_policer_bind_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_bind_reply_t_calc_size (vl_api_policer_bind_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_bind_v2_t_calc_size (vl_api_policer_bind_v2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_bind_v2_reply_t_calc_size (vl_api_policer_bind_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_input_t_calc_size (vl_api_policer_input_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_input_reply_t_calc_size (vl_api_policer_input_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_input_v2_t_calc_size (vl_api_policer_input_v2_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_input_v2_reply_t_calc_size (vl_api_policer_input_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_output_t_calc_size (vl_api_policer_output_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_output_reply_t_calc_size (vl_api_policer_output_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_output_v2_t_calc_size (vl_api_policer_output_v2_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_output_v2_reply_t_calc_size (vl_api_policer_output_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_add_del_t_calc_size (vl_api_policer_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->rate_type) + vl_api_sse2_qos_rate_type_t_calc_size(&a->rate_type) - sizeof(a->round_type) + vl_api_sse2_qos_round_type_t_calc_size(&a->round_type) - sizeof(a->type) + vl_api_sse2_qos_policer_type_t_calc_size(&a->type) - sizeof(a->conform_action) + vl_api_sse2_qos_action_t_calc_size(&a->conform_action) - sizeof(a->exceed_action) + vl_api_sse2_qos_action_t_calc_size(&a->exceed_action) - sizeof(a->violate_action) + vl_api_sse2_qos_action_t_calc_size(&a->violate_action);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_add_t_calc_size (vl_api_policer_add_t *a)
{
      return sizeof(*a) - sizeof(a->infos) + vl_api_policer_config_t_calc_size(&a->infos);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_del_t_calc_size (vl_api_policer_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_del_reply_t_calc_size (vl_api_policer_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_update_t_calc_size (vl_api_policer_update_t *a)
{
      return sizeof(*a) - sizeof(a->infos) + vl_api_policer_config_t_calc_size(&a->infos);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_update_reply_t_calc_size (vl_api_policer_update_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_reset_t_calc_size (vl_api_policer_reset_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_reset_reply_t_calc_size (vl_api_policer_reset_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_add_del_reply_t_calc_size (vl_api_policer_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_add_reply_t_calc_size (vl_api_policer_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_dump_t_calc_size (vl_api_policer_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_dump_v2_t_calc_size (vl_api_policer_dump_v2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_policer_details_t_calc_size (vl_api_policer_details_t *a)
{
      return sizeof(*a) - sizeof(a->rate_type) + vl_api_sse2_qos_rate_type_t_calc_size(&a->rate_type) - sizeof(a->round_type) + vl_api_sse2_qos_round_type_t_calc_size(&a->round_type) - sizeof(a->type) + vl_api_sse2_qos_policer_type_t_calc_size(&a->type) - sizeof(a->conform_action) + vl_api_sse2_qos_action_t_calc_size(&a->conform_action) - sizeof(a->exceed_action) + vl_api_sse2_qos_action_t_calc_size(&a->exceed_action) - sizeof(a->violate_action) + vl_api_sse2_qos_action_t_calc_size(&a->violate_action);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(policer.api, 3, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(policer.api, 0x68c02844)

#endif

