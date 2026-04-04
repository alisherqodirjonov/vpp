/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: fib_types.api
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
#warning no content included from fib_types.api
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
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_fib_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "fib_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_fib_types_printfun_types
#define included_fib_types_printfun_types

static inline u8 *format_vl_api_fib_mpls_label_t (u8 *s, va_list * args)
{
    vl_api_fib_mpls_label_t *a = va_arg (*args, vl_api_fib_mpls_label_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uis_uniform: %u", format_white_space, indent, a->is_uniform);
    s = format(s, "\n%Ulabel: %u", format_white_space, indent, a->label);
    s = format(s, "\n%Uttl: %u", format_white_space, indent, a->ttl);
    s = format(s, "\n%Uexp: %u", format_white_space, indent, a->exp);
    return s;
}

static inline u8 *format_vl_api_fib_path_nh_proto_t (u8 *s, va_list * args)
{
    vl_api_fib_path_nh_proto_t *a = va_arg (*args, vl_api_fib_path_nh_proto_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "FIB_API_PATH_NH_PROTO_IP4");
    case 1:
        return format(s, "FIB_API_PATH_NH_PROTO_IP6");
    case 2:
        return format(s, "FIB_API_PATH_NH_PROTO_MPLS");
    case 3:
        return format(s, "FIB_API_PATH_NH_PROTO_ETHERNET");
    case 4:
        return format(s, "FIB_API_PATH_NH_PROTO_BIER");
    }
    return s;
}

static inline u8 *format_vl_api_fib_path_flags_t (u8 *s, va_list * args)
{
    vl_api_fib_path_flags_t *a = va_arg (*args, vl_api_fib_path_flags_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "FIB_API_PATH_FLAG_NONE");
    case 1:
        return format(s, "FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED");
    case 2:
        return format(s, "FIB_API_PATH_FLAG_RESOLVE_VIA_HOST");
    case 4:
        return format(s, "FIB_API_PATH_FLAG_POP_PW_CW");
    }
    return s;
}

static inline u8 *format_vl_api_fib_path_nh_t (u8 *s, va_list * args)
{
    vl_api_fib_path_nh_t *a = va_arg (*args, vl_api_fib_path_nh_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uaddress: %U", format_white_space, indent, format_vl_api_address_union_t, &a->address, indent);
    s = format(s, "\n%Uvia_label: %u", format_white_space, indent, a->via_label);
    s = format(s, "\n%Uobj_id: %u", format_white_space, indent, a->obj_id);
    s = format(s, "\n%Uclassify_table_index: %u", format_white_space, indent, a->classify_table_index);
    return s;
}

static inline u8 *format_vl_api_fib_path_type_t (u8 *s, va_list * args)
{
    vl_api_fib_path_type_t *a = va_arg (*args, vl_api_fib_path_type_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "FIB_API_PATH_TYPE_NORMAL");
    case 1:
        return format(s, "FIB_API_PATH_TYPE_LOCAL");
    case 2:
        return format(s, "FIB_API_PATH_TYPE_DROP");
    case 3:
        return format(s, "FIB_API_PATH_TYPE_UDP_ENCAP");
    case 4:
        return format(s, "FIB_API_PATH_TYPE_BIER_IMP");
    case 5:
        return format(s, "FIB_API_PATH_TYPE_ICMP_UNREACH");
    case 6:
        return format(s, "FIB_API_PATH_TYPE_ICMP_PROHIBIT");
    case 7:
        return format(s, "FIB_API_PATH_TYPE_SOURCE_LOOKUP");
    case 8:
        return format(s, "FIB_API_PATH_TYPE_DVR");
    case 9:
        return format(s, "FIB_API_PATH_TYPE_INTERFACE_RX");
    case 10:
        return format(s, "FIB_API_PATH_TYPE_CLASSIFY");
    }
    return s;
}

static inline u8 *format_vl_api_fib_path_t (u8 *s, va_list * args)
{
    vl_api_fib_path_t *a = va_arg (*args, vl_api_fib_path_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %u", format_white_space, indent, a->sw_if_index);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Urpf_id: %u", format_white_space, indent, a->rpf_id);
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Upreference: %u", format_white_space, indent, a->preference);
    s = format(s, "\n%Utype: %U", format_white_space, indent, format_vl_api_fib_path_type_t, &a->type, indent);
    s = format(s, "\n%Uflags: %U", format_white_space, indent, format_vl_api_fib_path_flags_t, &a->flags, indent);
    s = format(s, "\n%Uproto: %U", format_white_space, indent, format_vl_api_fib_path_nh_proto_t, &a->proto, indent);
    s = format(s, "\n%Unh: %U", format_white_space, indent, format_vl_api_fib_path_nh_t, &a->nh, indent);
    s = format(s, "\n%Un_labels: %u", format_white_space, indent, a->n_labels);
    for (i = 0; i < 16; i++) {
        s = format(s, "\n%Ulabel_stack: %U",
                   format_white_space, indent, format_vl_api_fib_mpls_label_t, &a->label_stack[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_fib_types_printfun
#define included_fib_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "fib_types.api_tojson.h"
#include "fib_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_fib_types_endianfun
#define included_fib_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_fib_mpls_label_t_endian (vl_api_fib_mpls_label_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->is_uniform = a->is_uniform (no-op) */
    a->label = clib_net_to_host_u32(a->label);
    /* a->ttl = a->ttl (no-op) */
    /* a->exp = a->exp (no-op) */
}

static inline void vl_api_fib_path_nh_proto_t_endian (vl_api_fib_path_nh_proto_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_fib_path_flags_t_endian (vl_api_fib_path_flags_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_fib_path_nh_t_endian (vl_api_fib_path_nh_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_address_union_t_endian(&a->address, to_net);
    a->via_label = clib_net_to_host_u32(a->via_label);
    a->obj_id = clib_net_to_host_u32(a->obj_id);
    a->classify_table_index = clib_net_to_host_u32(a->classify_table_index);
}

static inline void vl_api_fib_path_type_t_endian (vl_api_fib_path_type_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_fib_path_t_endian (vl_api_fib_path_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    a->table_id = clib_net_to_host_u32(a->table_id);
    a->rpf_id = clib_net_to_host_u32(a->rpf_id);
    /* a->weight = a->weight (no-op) */
    /* a->preference = a->preference (no-op) */
    vl_api_fib_path_type_t_endian(&a->type, to_net);
    vl_api_fib_path_flags_t_endian(&a->flags, to_net);
    vl_api_fib_path_nh_proto_t_endian(&a->proto, to_net);
    vl_api_fib_path_nh_t_endian(&a->nh, to_net);
    /* a->n_labels = a->n_labels (no-op) */
    for (i = 0; i < 16; i++) {
        vl_api_fib_mpls_label_t_endian(&a->label_stack[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_fib_types_calcsizefun
#define included_fib_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_fib_mpls_label_t_calc_size (vl_api_fib_mpls_label_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_fib_path_nh_proto_t_calc_size (vl_api_fib_path_nh_proto_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_fib_path_flags_t_calc_size (vl_api_fib_path_flags_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_fib_path_nh_t_calc_size (vl_api_fib_path_nh_t *a)
{
      return sizeof(*a) - sizeof(a->address) + vl_api_address_union_t_calc_size(&a->address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_fib_path_type_t_calc_size (vl_api_fib_path_type_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_fib_path_t_calc_size (vl_api_fib_path_t *a)
{
      return sizeof(*a) - sizeof(a->type) + vl_api_fib_path_type_t_calc_size(&a->type) - sizeof(a->flags) + vl_api_fib_path_flags_t_calc_size(&a->flags) - sizeof(a->proto) + vl_api_fib_path_nh_proto_t_calc_size(&a->proto) - sizeof(a->nh) + vl_api_fib_path_nh_t_calc_size(&a->nh);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(fib_types.api, 2, 0, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(fib_types.api, 0xa82060a8)

#endif

