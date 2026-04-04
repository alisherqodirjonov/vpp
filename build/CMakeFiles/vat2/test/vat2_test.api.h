/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: vat2_test.api
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
#warning no content included from vat2_test.api
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
#include <vnet/ip/ip_types.api.h>
#include <vnet/interface_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_TEST_PREFIX, vl_api_test_prefix_t_handler)
vl_msg_id(VL_API_TEST_PREFIX_REPLY, vl_api_test_prefix_reply_t_handler)
vl_msg_id(VL_API_TEST_ENUM, vl_api_test_enum_t_handler)
vl_msg_id(VL_API_TEST_ENUM_REPLY, vl_api_test_enum_reply_t_handler)
vl_msg_id(VL_API_TEST_STRING, vl_api_test_string_t_handler)
vl_msg_id(VL_API_TEST_STRING_REPLY, vl_api_test_string_reply_t_handler)
vl_msg_id(VL_API_TEST_STRING2, vl_api_test_string2_t_handler)
vl_msg_id(VL_API_TEST_STRING2_REPLY, vl_api_test_string2_reply_t_handler)
vl_msg_id(VL_API_TEST_VLA, vl_api_test_vla_t_handler)
vl_msg_id(VL_API_TEST_VLA_REPLY, vl_api_test_vla_reply_t_handler)
vl_msg_id(VL_API_TEST_VLA2, vl_api_test_vla2_t_handler)
vl_msg_id(VL_API_TEST_VLA2_REPLY, vl_api_test_vla2_reply_t_handler)
vl_msg_id(VL_API_TEST_VLA3, vl_api_test_vla3_t_handler)
vl_msg_id(VL_API_TEST_VLA3_REPLY, vl_api_test_vla3_reply_t_handler)
vl_msg_id(VL_API_TEST_VLA4, vl_api_test_vla4_t_handler)
vl_msg_id(VL_API_TEST_VLA4_REPLY, vl_api_test_vla4_reply_t_handler)
vl_msg_id(VL_API_TEST_VLA5, vl_api_test_vla5_t_handler)
vl_msg_id(VL_API_TEST_VLA5_REPLY, vl_api_test_vla5_reply_t_handler)
vl_msg_id(VL_API_TEST_ADDRESSES, vl_api_test_addresses_t_handler)
vl_msg_id(VL_API_TEST_ADDRESSES_REPLY, vl_api_test_addresses_reply_t_handler)
vl_msg_id(VL_API_TEST_ADDRESSES2, vl_api_test_addresses2_t_handler)
vl_msg_id(VL_API_TEST_ADDRESSES2_REPLY, vl_api_test_addresses2_reply_t_handler)
vl_msg_id(VL_API_TEST_ADDRESSES3, vl_api_test_addresses3_t_handler)
vl_msg_id(VL_API_TEST_ADDRESSES3_REPLY, vl_api_test_addresses3_reply_t_handler)
vl_msg_id(VL_API_TEST_EMPTY, vl_api_test_empty_t_handler)
vl_msg_id(VL_API_TEST_EMPTY_REPLY, vl_api_test_empty_reply_t_handler)
vl_msg_id(VL_API_TEST_INTERFACE, vl_api_test_interface_t_handler)
vl_msg_id(VL_API_TEST_INTERFACE_REPLY, vl_api_test_interface_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_test_prefix_t, 1)
vl_msg_name(vl_api_test_prefix_reply_t, 1)
vl_msg_name(vl_api_test_enum_t, 1)
vl_msg_name(vl_api_test_enum_reply_t, 1)
vl_msg_name(vl_api_test_string_t, 1)
vl_msg_name(vl_api_test_string_reply_t, 1)
vl_msg_name(vl_api_test_string2_t, 1)
vl_msg_name(vl_api_test_string2_reply_t, 1)
vl_msg_name(vl_api_test_vla_t, 1)
vl_msg_name(vl_api_test_vla_reply_t, 1)
vl_msg_name(vl_api_test_vla2_t, 1)
vl_msg_name(vl_api_test_vla2_reply_t, 1)
vl_msg_name(vl_api_test_vla3_t, 1)
vl_msg_name(vl_api_test_vla3_reply_t, 1)
vl_msg_name(vl_api_test_vla4_t, 1)
vl_msg_name(vl_api_test_vla4_reply_t, 1)
vl_msg_name(vl_api_test_vla5_t, 1)
vl_msg_name(vl_api_test_vla5_reply_t, 1)
vl_msg_name(vl_api_test_addresses_t, 1)
vl_msg_name(vl_api_test_addresses_reply_t, 1)
vl_msg_name(vl_api_test_addresses2_t, 1)
vl_msg_name(vl_api_test_addresses2_reply_t, 1)
vl_msg_name(vl_api_test_addresses3_t, 1)
vl_msg_name(vl_api_test_addresses3_reply_t, 1)
vl_msg_name(vl_api_test_empty_t, 1)
vl_msg_name(vl_api_test_empty_reply_t, 1)
vl_msg_name(vl_api_test_interface_t, 1)
vl_msg_name(vl_api_test_interface_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vat2_test \
_(VL_API_TEST_PREFIX, test_prefix, d866c1a9) \
_(VL_API_TEST_PREFIX_REPLY, test_prefix_reply, e8d4e804) \
_(VL_API_TEST_ENUM, test_enum, e3190a2e) \
_(VL_API_TEST_ENUM_REPLY, test_enum_reply, e8d4e804) \
_(VL_API_TEST_STRING, test_string, 3955d673) \
_(VL_API_TEST_STRING_REPLY, test_string_reply, e8d4e804) \
_(VL_API_TEST_STRING2, test_string2, 64a8785b) \
_(VL_API_TEST_STRING2_REPLY, test_string2_reply, e8d4e804) \
_(VL_API_TEST_VLA, test_vla, 5d944dfc) \
_(VL_API_TEST_VLA_REPLY, test_vla_reply, e8d4e804) \
_(VL_API_TEST_VLA2, test_vla2, 471f6687) \
_(VL_API_TEST_VLA2_REPLY, test_vla2_reply, e8d4e804) \
_(VL_API_TEST_VLA3, test_vla3, bac4a968) \
_(VL_API_TEST_VLA3_REPLY, test_vla3_reply, e8d4e804) \
_(VL_API_TEST_VLA4, test_vla4, c061d9d1) \
_(VL_API_TEST_VLA4_REPLY, test_vla4_reply, e8d4e804) \
_(VL_API_TEST_VLA5, test_vla5, 09b0e1f3) \
_(VL_API_TEST_VLA5_REPLY, test_vla5_reply, e8d4e804) \
_(VL_API_TEST_ADDRESSES, test_addresses, 2bef955c) \
_(VL_API_TEST_ADDRESSES_REPLY, test_addresses_reply, e8d4e804) \
_(VL_API_TEST_ADDRESSES2, test_addresses2, ff01dd23) \
_(VL_API_TEST_ADDRESSES2_REPLY, test_addresses2_reply, e8d4e804) \
_(VL_API_TEST_ADDRESSES3, test_addresses3, 7f3e48a1) \
_(VL_API_TEST_ADDRESSES3_REPLY, test_addresses3_reply, e8d4e804) \
_(VL_API_TEST_EMPTY, test_empty, 51077d14) \
_(VL_API_TEST_EMPTY_REPLY, test_empty_reply, e8d4e804) \
_(VL_API_TEST_INTERFACE, test_interface, 00e34dc0) \
_(VL_API_TEST_INTERFACE_REPLY, test_interface_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vat2_test.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vat2_test_printfun_types
#define included_vat2_test_printfun_types

static inline u8 *format_vl_api_test_enumflags_t (u8 *s, va_list * args)
{
    vl_api_test_enumflags_t *a = va_arg (*args, vl_api_test_enumflags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 1:
        return format(s, "RED");
    case 2:
        return format(s, "BLUE");
    case 4:
        return format(s, "GREEN");
    }
    return s;
}

static inline u8 *format_vl_api_test_stringtype_t (u8 *s, va_list * args)
{
    vl_api_test_stringtype_t *a = va_arg (*args, vl_api_test_stringtype_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    if (vl_api_string_len(&a->str) > 0) {
        s = format(s, "\n%Ustr: %U", format_white_space, indent, vl_api_format_string, (&a->str));
    } else {
        s = format(s, "\n%Ustr:", format_white_space, indent);
    }
    return s;
}

static inline u8 *format_vl_api_test_vlatype_t (u8 *s, va_list * args)
{
    vl_api_test_vlatype_t *a = va_arg (*args, vl_api_test_vlatype_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Udata: %u", format_white_space, indent, a->data);
    return s;
}

static inline u8 *format_vl_api_test_vlatype2_t (u8 *s, va_list * args)
{
    vl_api_test_vlatype2_t *a = va_arg (*args, vl_api_test_vlatype2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uvla: %u",
                   format_white_space, indent, a->vla[i]);
    }
    return s;
}

static inline u8 *format_vl_api_test_vlatype3_t (u8 *s, va_list * args)
{
    vl_api_test_vlatype3_t *a = va_arg (*args, vl_api_test_vlatype3_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Uvla: %U", format_white_space, indent, format_hex_bytes, a->vla, a->count);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vat2_test_printfun
#define included_vat2_test_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vat2_test.api_tojson.h"
#include "vat2_test.api_fromjson.h"

static inline u8 *vl_api_test_prefix_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_prefix_t *a = va_arg (*args, vl_api_test_prefix_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_prefix_t: */
    s = format(s, "vl_api_test_prefix_t:");
    s = format(s, "\n%Upref: %U", format_white_space, indent, format_vl_api_prefix_t, &a->pref, indent);
    return s;
}

static inline u8 *vl_api_test_prefix_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_prefix_reply_t *a = va_arg (*args, vl_api_test_prefix_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_prefix_reply_t: */
    s = format(s, "vl_api_test_prefix_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_enum_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_enum_t *a = va_arg (*args, vl_api_test_enum_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_enum_t: */
    s = format(s, "vl_api_test_enum_t:");
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_test_enumflags_t, &a->flags, indent);
    return s;
}

static inline u8 *vl_api_test_enum_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_enum_reply_t *a = va_arg (*args, vl_api_test_enum_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_enum_reply_t: */
    s = format(s, "vl_api_test_enum_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_string_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_string_t *a = va_arg (*args, vl_api_test_string_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_string_t: */
    s = format(s, "vl_api_test_string_t:");
    s = format(s, "\n%Ustr: %U", format_white_space, indent, format_vl_api_test_stringtype_t, &a->str, indent);
    return s;
}

static inline u8 *vl_api_test_string_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_string_reply_t *a = va_arg (*args, vl_api_test_string_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_string_reply_t: */
    s = format(s, "vl_api_test_string_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_string2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_string2_t *a = va_arg (*args, vl_api_test_string2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_string2_t: */
    s = format(s, "vl_api_test_string2_t:");
    if (vl_api_string_len(&a->str) > 0) {
        s = format(s, "\n%Ustr: %U", format_white_space, indent, vl_api_format_string, (&a->str));
    } else {
        s = format(s, "\n%Ustr:", format_white_space, indent);
    }
    return s;
}

static inline u8 *vl_api_test_string2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_string2_reply_t *a = va_arg (*args, vl_api_test_string2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_string2_reply_t: */
    s = format(s, "vl_api_test_string2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_vla_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla_t *a = va_arg (*args, vl_api_test_vla_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla_t: */
    s = format(s, "vl_api_test_vla_t:");
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uvla: %u",
                   format_white_space, indent, a->vla[i]);
    }
    return s;
}

static inline u8 *vl_api_test_vla_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla_reply_t *a = va_arg (*args, vl_api_test_vla_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla_reply_t: */
    s = format(s, "vl_api_test_vla_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_vla2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla2_t *a = va_arg (*args, vl_api_test_vla2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla2_t: */
    s = format(s, "vl_api_test_vla2_t:");
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    s = format(s, "\n%Uvla: %U", format_white_space, indent, format_hex_bytes, a->vla, a->count);
    return s;
}

static inline u8 *vl_api_test_vla2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla2_reply_t *a = va_arg (*args, vl_api_test_vla2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla2_reply_t: */
    s = format(s, "vl_api_test_vla2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_vla3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla3_t *a = va_arg (*args, vl_api_test_vla3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla3_t: */
    s = format(s, "vl_api_test_vla3_t:");
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uvla: %U",
                   format_white_space, indent, format_vl_api_test_vlatype_t, &a->vla[i], indent);
    }
    return s;
}

static inline u8 *vl_api_test_vla3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla3_reply_t *a = va_arg (*args, vl_api_test_vla3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla3_reply_t: */
    s = format(s, "vl_api_test_vla3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_vla4_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla4_t *a = va_arg (*args, vl_api_test_vla4_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla4_t: */
    s = format(s, "vl_api_test_vla4_t:");
    s = format(s, "\n%Udata: %U", format_white_space, indent, format_vl_api_test_vlatype2_t, &a->data, indent);
    return s;
}

static inline u8 *vl_api_test_vla4_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla4_reply_t *a = va_arg (*args, vl_api_test_vla4_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla4_reply_t: */
    s = format(s, "vl_api_test_vla4_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_vla5_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla5_t *a = va_arg (*args, vl_api_test_vla5_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla5_t: */
    s = format(s, "vl_api_test_vla5_t:");
    s = format(s, "\n%Udata: %U", format_white_space, indent, format_vl_api_test_vlatype3_t, &a->data, indent);
    return s;
}

static inline u8 *vl_api_test_vla5_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_vla5_reply_t *a = va_arg (*args, vl_api_test_vla5_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_vla5_reply_t: */
    s = format(s, "vl_api_test_vla5_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_addresses_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_addresses_t *a = va_arg (*args, vl_api_test_addresses_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_addresses_t: */
    s = format(s, "vl_api_test_addresses_t:");
    s = format(s, "\n%Ua: %U", format_white_space, indent, format_vl_api_address_t, &a->a, indent);
    return s;
}

static inline u8 *vl_api_test_addresses_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_addresses_reply_t *a = va_arg (*args, vl_api_test_addresses_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_addresses_reply_t: */
    s = format(s, "vl_api_test_addresses_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_addresses2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_addresses2_t *a = va_arg (*args, vl_api_test_addresses2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_addresses2_t: */
    s = format(s, "vl_api_test_addresses2_t:");
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Ua: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->a[i], indent);
    }
    return s;
}

static inline u8 *vl_api_test_addresses2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_addresses2_reply_t *a = va_arg (*args, vl_api_test_addresses2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_addresses2_reply_t: */
    s = format(s, "vl_api_test_addresses2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_addresses3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_addresses3_t *a = va_arg (*args, vl_api_test_addresses3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_addresses3_t: */
    s = format(s, "vl_api_test_addresses3_t:");
    s = format(s, "\n%Un: %u", format_white_space, indent, a->n);
    for (i = 0; i < a->n; i++) {
        s = format(s, "\n%Ua: %U",
                   format_white_space, indent, format_vl_api_address_t, &a->a[i], indent);
    }
    return s;
}

static inline u8 *vl_api_test_addresses3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_addresses3_reply_t *a = va_arg (*args, vl_api_test_addresses3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_addresses3_reply_t: */
    s = format(s, "vl_api_test_addresses3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_empty_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_empty_t *a = va_arg (*args, vl_api_test_empty_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_empty_t: */
    s = format(s, "vl_api_test_empty_t:");
    return s;
}

static inline u8 *vl_api_test_empty_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_empty_reply_t *a = va_arg (*args, vl_api_test_empty_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_empty_reply_t: */
    s = format(s, "vl_api_test_empty_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_test_interface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_interface_t *a = va_arg (*args, vl_api_test_interface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_interface_t: */
    s = format(s, "vl_api_test_interface_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_test_interface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_test_interface_reply_t *a = va_arg (*args, vl_api_test_interface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_test_interface_reply_t: */
    s = format(s, "vl_api_test_interface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vat2_test_endianfun
#define included_vat2_test_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_test_enumflags_t_endian (vl_api_test_enumflags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_test_stringtype_t_endian (vl_api_test_stringtype_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->str = a->str (no-op) */
}

static inline void vl_api_test_vlatype_t_endian (vl_api_test_vlatype_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->data = clib_net_to_host_u32(a->data);
}

static inline void vl_api_test_vlatype2_t_endian (vl_api_test_vlatype2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->vla[i] = clib_net_to_host_u32(a->vla[i]);
    }
}

static inline void vl_api_test_vlatype3_t_endian (vl_api_test_vlatype3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->count = clib_net_to_host_u32(a->count);
    /* a->vla = a->vla (no-op) */
}

static inline void vl_api_test_prefix_t_endian (vl_api_test_prefix_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_prefix_t_endian(&a->pref, to_net);
}

static inline void vl_api_test_prefix_reply_t_endian (vl_api_test_prefix_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_enum_t_endian (vl_api_test_enum_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_test_enumflags_t_endian(&a->flags, to_net);
}

static inline void vl_api_test_enum_reply_t_endian (vl_api_test_enum_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_string_t_endian (vl_api_test_string_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_test_stringtype_t_endian(&a->str, to_net);
}

static inline void vl_api_test_string_reply_t_endian (vl_api_test_string_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_string2_t_endian (vl_api_test_string2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->str = a->str (no-op) */
}

static inline void vl_api_test_string2_reply_t_endian (vl_api_test_string2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_vla_t_endian (vl_api_test_vla_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->vla[i] = clib_net_to_host_u32(a->vla[i]);
    }
}

static inline void vl_api_test_vla_reply_t_endian (vl_api_test_vla_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_vla2_t_endian (vl_api_test_vla2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->count = clib_net_to_host_u32(a->count);
    /* a->vla = a->vla (no-op) */
}

static inline void vl_api_test_vla2_reply_t_endian (vl_api_test_vla2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_vla3_t_endian (vl_api_test_vla3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_test_vlatype_t_endian(&a->vla[i], to_net);
    }
}

static inline void vl_api_test_vla3_reply_t_endian (vl_api_test_vla3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_vla4_t_endian (vl_api_test_vla4_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_test_vlatype2_t_endian(&a->data, to_net);
}

static inline void vl_api_test_vla4_reply_t_endian (vl_api_test_vla4_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_vla5_t_endian (vl_api_test_vla5_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_test_vlatype3_t_endian(&a->data, to_net);
}

static inline void vl_api_test_vla5_reply_t_endian (vl_api_test_vla5_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_addresses_t_endian (vl_api_test_addresses_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_address_t_endian(&a->a, to_net);
}

static inline void vl_api_test_addresses_reply_t_endian (vl_api_test_addresses_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_addresses2_t_endian (vl_api_test_addresses2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    for (i = 0; i < 2; i++) {
        vl_api_address_t_endian(&a->a[i], to_net);
    }
}

static inline void vl_api_test_addresses2_reply_t_endian (vl_api_test_addresses2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_addresses3_t_endian (vl_api_test_addresses3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->n = clib_net_to_host_u32(a->n);
    u32 count = to_net ? clib_net_to_host_u32(a->n) : a->n;
    for (i = 0; i < count; i++) {
        vl_api_address_t_endian(&a->a[i], to_net);
    }
}

static inline void vl_api_test_addresses3_reply_t_endian (vl_api_test_addresses3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_empty_t_endian (vl_api_test_empty_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_test_empty_reply_t_endian (vl_api_test_empty_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_test_interface_t_endian (vl_api_test_interface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_test_interface_reply_t_endian (vl_api_test_interface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_vat2_test_calcsizefun
#define included_vat2_test_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_test_enumflags_t_calc_size (vl_api_test_enumflags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_stringtype_t_calc_size (vl_api_test_stringtype_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->str);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vlatype_t_calc_size (vl_api_test_vlatype_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vlatype2_t_calc_size (vl_api_test_vlatype2_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->vla[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vlatype3_t_calc_size (vl_api_test_vlatype3_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->vla[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_prefix_t_calc_size (vl_api_test_prefix_t *a)
{
      return sizeof(*a) - sizeof(a->pref) + vl_api_prefix_t_calc_size(&a->pref);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_prefix_reply_t_calc_size (vl_api_test_prefix_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_enum_t_calc_size (vl_api_test_enum_t *a)
{
      return sizeof(*a) - sizeof(a->flags) + vl_api_test_enumflags_t_calc_size(&a->flags);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_enum_reply_t_calc_size (vl_api_test_enum_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_string_t_calc_size (vl_api_test_string_t *a)
{
      return sizeof(*a) - sizeof(a->str) + vl_api_test_stringtype_t_calc_size(&a->str);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_string_reply_t_calc_size (vl_api_test_string_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_string2_t_calc_size (vl_api_test_string2_t *a)
{
      return sizeof(*a) + vl_api_string_len(&a->str);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_string2_reply_t_calc_size (vl_api_test_string2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla_t_calc_size (vl_api_test_vla_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->vla[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla_reply_t_calc_size (vl_api_test_vla_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla2_t_calc_size (vl_api_test_vla2_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->vla[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla2_reply_t_calc_size (vl_api_test_vla2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla3_t_calc_size (vl_api_test_vla3_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->vla[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla3_reply_t_calc_size (vl_api_test_vla3_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla4_t_calc_size (vl_api_test_vla4_t *a)
{
      return sizeof(*a) - sizeof(a->data) + vl_api_test_vlatype2_t_calc_size(&a->data);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla4_reply_t_calc_size (vl_api_test_vla4_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla5_t_calc_size (vl_api_test_vla5_t *a)
{
      return sizeof(*a) - sizeof(a->data) + vl_api_test_vlatype3_t_calc_size(&a->data);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_vla5_reply_t_calc_size (vl_api_test_vla5_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_addresses_t_calc_size (vl_api_test_addresses_t *a)
{
      return sizeof(*a) - sizeof(a->a) + vl_api_address_t_calc_size(&a->a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_addresses_reply_t_calc_size (vl_api_test_addresses_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_addresses2_t_calc_size (vl_api_test_addresses2_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_addresses2_reply_t_calc_size (vl_api_test_addresses2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_addresses3_t_calc_size (vl_api_test_addresses3_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->n) * sizeof(a->a[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_addresses3_reply_t_calc_size (vl_api_test_addresses3_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_empty_t_calc_size (vl_api_test_empty_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_empty_reply_t_calc_size (vl_api_test_empty_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_interface_t_calc_size (vl_api_test_interface_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_test_interface_reply_t_calc_size (vl_api_test_interface_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vat2_test.api, 0, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vat2_test.api, 0x6787fedc)

#endif

