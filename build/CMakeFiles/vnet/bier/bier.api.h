/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: bier.api
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
#warning no content included from bier.api
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
#include <vnet/fib/fib_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_BIER_TABLE_ADD_DEL, vl_api_bier_table_add_del_t_handler)
vl_msg_id(VL_API_BIER_TABLE_ADD_DEL_REPLY, vl_api_bier_table_add_del_reply_t_handler)
vl_msg_id(VL_API_BIER_TABLE_DUMP, vl_api_bier_table_dump_t_handler)
vl_msg_id(VL_API_BIER_TABLE_DETAILS, vl_api_bier_table_details_t_handler)
vl_msg_id(VL_API_BIER_ROUTE_ADD_DEL, vl_api_bier_route_add_del_t_handler)
vl_msg_id(VL_API_BIER_ROUTE_ADD_DEL_REPLY, vl_api_bier_route_add_del_reply_t_handler)
vl_msg_id(VL_API_BIER_ROUTE_DUMP, vl_api_bier_route_dump_t_handler)
vl_msg_id(VL_API_BIER_ROUTE_DETAILS, vl_api_bier_route_details_t_handler)
vl_msg_id(VL_API_BIER_IMP_ADD, vl_api_bier_imp_add_t_handler)
vl_msg_id(VL_API_BIER_IMP_ADD_REPLY, vl_api_bier_imp_add_reply_t_handler)
vl_msg_id(VL_API_BIER_IMP_DEL, vl_api_bier_imp_del_t_handler)
vl_msg_id(VL_API_BIER_IMP_DEL_REPLY, vl_api_bier_imp_del_reply_t_handler)
vl_msg_id(VL_API_BIER_IMP_DUMP, vl_api_bier_imp_dump_t_handler)
vl_msg_id(VL_API_BIER_IMP_DETAILS, vl_api_bier_imp_details_t_handler)
vl_msg_id(VL_API_BIER_DISP_TABLE_ADD_DEL, vl_api_bier_disp_table_add_del_t_handler)
vl_msg_id(VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY, vl_api_bier_disp_table_add_del_reply_t_handler)
vl_msg_id(VL_API_BIER_DISP_TABLE_DUMP, vl_api_bier_disp_table_dump_t_handler)
vl_msg_id(VL_API_BIER_DISP_TABLE_DETAILS, vl_api_bier_disp_table_details_t_handler)
vl_msg_id(VL_API_BIER_DISP_ENTRY_ADD_DEL, vl_api_bier_disp_entry_add_del_t_handler)
vl_msg_id(VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY, vl_api_bier_disp_entry_add_del_reply_t_handler)
vl_msg_id(VL_API_BIER_DISP_ENTRY_DUMP, vl_api_bier_disp_entry_dump_t_handler)
vl_msg_id(VL_API_BIER_DISP_ENTRY_DETAILS, vl_api_bier_disp_entry_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_bier_table_add_del_t, 1)
vl_msg_name(vl_api_bier_table_add_del_reply_t, 1)
vl_msg_name(vl_api_bier_table_dump_t, 1)
vl_msg_name(vl_api_bier_table_details_t, 1)
vl_msg_name(vl_api_bier_route_add_del_t, 1)
vl_msg_name(vl_api_bier_route_add_del_reply_t, 1)
vl_msg_name(vl_api_bier_route_dump_t, 1)
vl_msg_name(vl_api_bier_route_details_t, 1)
vl_msg_name(vl_api_bier_imp_add_t, 1)
vl_msg_name(vl_api_bier_imp_add_reply_t, 1)
vl_msg_name(vl_api_bier_imp_del_t, 1)
vl_msg_name(vl_api_bier_imp_del_reply_t, 1)
vl_msg_name(vl_api_bier_imp_dump_t, 1)
vl_msg_name(vl_api_bier_imp_details_t, 1)
vl_msg_name(vl_api_bier_disp_table_add_del_t, 1)
vl_msg_name(vl_api_bier_disp_table_add_del_reply_t, 1)
vl_msg_name(vl_api_bier_disp_table_dump_t, 1)
vl_msg_name(vl_api_bier_disp_table_details_t, 1)
vl_msg_name(vl_api_bier_disp_entry_add_del_t, 1)
vl_msg_name(vl_api_bier_disp_entry_add_del_reply_t, 1)
vl_msg_name(vl_api_bier_disp_entry_dump_t, 1)
vl_msg_name(vl_api_bier_disp_entry_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_bier \
_(VL_API_BIER_TABLE_ADD_DEL, bier_table_add_del, 35e59209) \
_(VL_API_BIER_TABLE_ADD_DEL_REPLY, bier_table_add_del_reply, e8d4e804) \
_(VL_API_BIER_TABLE_DUMP, bier_table_dump, 51077d14) \
_(VL_API_BIER_TABLE_DETAILS, bier_table_details, fc44a9dd) \
_(VL_API_BIER_ROUTE_ADD_DEL, bier_route_add_del, fd02f3ea) \
_(VL_API_BIER_ROUTE_ADD_DEL_REPLY, bier_route_add_del_reply, e8d4e804) \
_(VL_API_BIER_ROUTE_DUMP, bier_route_dump, 38339846) \
_(VL_API_BIER_ROUTE_DETAILS, bier_route_details, 4008caee) \
_(VL_API_BIER_IMP_ADD, bier_imp_add, 3856dc3d) \
_(VL_API_BIER_IMP_ADD_REPLY, bier_imp_add_reply, d49c5793) \
_(VL_API_BIER_IMP_DEL, bier_imp_del, 7d45edf6) \
_(VL_API_BIER_IMP_DEL_REPLY, bier_imp_del_reply, e8d4e804) \
_(VL_API_BIER_IMP_DUMP, bier_imp_dump, 51077d14) \
_(VL_API_BIER_IMP_DETAILS, bier_imp_details, b76192df) \
_(VL_API_BIER_DISP_TABLE_ADD_DEL, bier_disp_table_add_del, 889657ac) \
_(VL_API_BIER_DISP_TABLE_ADD_DEL_REPLY, bier_disp_table_add_del_reply, e8d4e804) \
_(VL_API_BIER_DISP_TABLE_DUMP, bier_disp_table_dump, 51077d14) \
_(VL_API_BIER_DISP_TABLE_DETAILS, bier_disp_table_details, d27942c0) \
_(VL_API_BIER_DISP_ENTRY_ADD_DEL, bier_disp_entry_add_del, 9eb80cb4) \
_(VL_API_BIER_DISP_ENTRY_ADD_DEL_REPLY, bier_disp_entry_add_del_reply, e8d4e804) \
_(VL_API_BIER_DISP_ENTRY_DUMP, bier_disp_entry_dump, b5fa54ad) \
_(VL_API_BIER_DISP_ENTRY_DETAILS, bier_disp_entry_details, 84c218f1) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "bier.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_bier_printfun_types
#define included_bier_printfun_types

static inline u8 *format_vl_api_bier_table_id_t (u8 *s, va_list * args)
{
    vl_api_bier_table_id_t *a = va_arg (*args, vl_api_bier_table_id_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ubt_set: %u", format_white_space, indent, a->bt_set);
    s = format(s, "\n%Ubt_sub_domain: %u", format_white_space, indent, a->bt_sub_domain);
    s = format(s, "\n%Ubt_hdr_len_id: %u", format_white_space, indent, a->bt_hdr_len_id);
    return s;
}

static inline u8 *format_vl_api_bier_route_t (u8 *s, va_list * args)
{
    vl_api_bier_route_t *a = va_arg (*args, vl_api_bier_route_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ubr_bp: %u", format_white_space, indent, a->br_bp);
    s = format(s, "\n%Ubr_tbl_id: %U", format_white_space, indent, format_vl_api_bier_table_id_t, &a->br_tbl_id, indent);
    s = format(s, "\n%Ubr_n_paths: %u", format_white_space, indent, a->br_n_paths);
    for (i = 0; i < a->br_n_paths; i++) {
        s = format(s, "\n%Ubr_paths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->br_paths[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_bier_printfun
#define included_bier_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "bier.api_tojson.h"
#include "bier.api_fromjson.h"

static inline u8 *vl_api_bier_table_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_table_add_del_t *a = va_arg (*args, vl_api_bier_table_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_table_add_del_t: */
    s = format(s, "vl_api_bier_table_add_del_t:");
    s = format(s, "\n%Ubt_tbl_id: %U", format_white_space, indent, format_vl_api_bier_table_id_t, &a->bt_tbl_id, indent);
    s = format(s, "\n%Ubt_label: %u", format_white_space, indent, a->bt_label);
    s = format(s, "\n%Ubt_is_add: %u", format_white_space, indent, a->bt_is_add);
    return s;
}

static inline u8 *vl_api_bier_table_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_table_add_del_reply_t *a = va_arg (*args, vl_api_bier_table_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_table_add_del_reply_t: */
    s = format(s, "vl_api_bier_table_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bier_table_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_table_dump_t *a = va_arg (*args, vl_api_bier_table_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_table_dump_t: */
    s = format(s, "vl_api_bier_table_dump_t:");
    return s;
}

static inline u8 *vl_api_bier_table_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_table_details_t *a = va_arg (*args, vl_api_bier_table_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_table_details_t: */
    s = format(s, "vl_api_bier_table_details_t:");
    s = format(s, "\n%Ubt_label: %u", format_white_space, indent, a->bt_label);
    s = format(s, "\n%Ubt_tbl_id: %U", format_white_space, indent, format_vl_api_bier_table_id_t, &a->bt_tbl_id, indent);
    return s;
}

static inline u8 *vl_api_bier_route_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_route_add_del_t *a = va_arg (*args, vl_api_bier_route_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_route_add_del_t: */
    s = format(s, "vl_api_bier_route_add_del_t:");
    s = format(s, "\n%Ubr_is_add: %u", format_white_space, indent, a->br_is_add);
    s = format(s, "\n%Ubr_is_replace: %u", format_white_space, indent, a->br_is_replace);
    s = format(s, "\n%Ubr_route: %U", format_white_space, indent, format_vl_api_bier_route_t, &a->br_route, indent);
    return s;
}

static inline u8 *vl_api_bier_route_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_route_add_del_reply_t *a = va_arg (*args, vl_api_bier_route_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_route_add_del_reply_t: */
    s = format(s, "vl_api_bier_route_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bier_route_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_route_dump_t *a = va_arg (*args, vl_api_bier_route_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_route_dump_t: */
    s = format(s, "vl_api_bier_route_dump_t:");
    s = format(s, "\n%Ubr_tbl_id: %U", format_white_space, indent, format_vl_api_bier_table_id_t, &a->br_tbl_id, indent);
    return s;
}

static inline u8 *vl_api_bier_route_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_route_details_t *a = va_arg (*args, vl_api_bier_route_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_route_details_t: */
    s = format(s, "vl_api_bier_route_details_t:");
    s = format(s, "\n%Ubr_route: %U", format_white_space, indent, format_vl_api_bier_route_t, &a->br_route, indent);
    return s;
}

static inline u8 *vl_api_bier_imp_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_imp_add_t *a = va_arg (*args, vl_api_bier_imp_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_imp_add_t: */
    s = format(s, "vl_api_bier_imp_add_t:");
    s = format(s, "\n%Ubi_tbl_id: %U", format_white_space, indent, format_vl_api_bier_table_id_t, &a->bi_tbl_id, indent);
    s = format(s, "\n%Ubi_src: %u", format_white_space, indent, a->bi_src);
    s = format(s, "\n%Ubi_n_bytes: %u", format_white_space, indent, a->bi_n_bytes);
    s = format(s, "\n%Ubi_bytes: %U", format_white_space, indent, format_hex_bytes, a->bi_bytes, a->bi_n_bytes);
    return s;
}

static inline u8 *vl_api_bier_imp_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_imp_add_reply_t *a = va_arg (*args, vl_api_bier_imp_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_imp_add_reply_t: */
    s = format(s, "vl_api_bier_imp_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ubi_index: %u", format_white_space, indent, a->bi_index);
    return s;
}

static inline u8 *vl_api_bier_imp_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_imp_del_t *a = va_arg (*args, vl_api_bier_imp_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_imp_del_t: */
    s = format(s, "vl_api_bier_imp_del_t:");
    s = format(s, "\n%Ubi_index: %u", format_white_space, indent, a->bi_index);
    return s;
}

static inline u8 *vl_api_bier_imp_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_imp_del_reply_t *a = va_arg (*args, vl_api_bier_imp_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_imp_del_reply_t: */
    s = format(s, "vl_api_bier_imp_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bier_imp_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_imp_dump_t *a = va_arg (*args, vl_api_bier_imp_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_imp_dump_t: */
    s = format(s, "vl_api_bier_imp_dump_t:");
    return s;
}

static inline u8 *vl_api_bier_imp_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_imp_details_t *a = va_arg (*args, vl_api_bier_imp_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_imp_details_t: */
    s = format(s, "vl_api_bier_imp_details_t:");
    s = format(s, "\n%Ubi_tbl_id: %U", format_white_space, indent, format_vl_api_bier_table_id_t, &a->bi_tbl_id, indent);
    s = format(s, "\n%Ubi_src: %u", format_white_space, indent, a->bi_src);
    s = format(s, "\n%Ubi_n_bytes: %u", format_white_space, indent, a->bi_n_bytes);
    s = format(s, "\n%Ubi_bytes: %U", format_white_space, indent, format_hex_bytes, a->bi_bytes, a->bi_n_bytes);
    return s;
}

static inline u8 *vl_api_bier_disp_table_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_table_add_del_t *a = va_arg (*args, vl_api_bier_disp_table_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_table_add_del_t: */
    s = format(s, "vl_api_bier_disp_table_add_del_t:");
    s = format(s, "\n%Ubdt_tbl_id: %u", format_white_space, indent, a->bdt_tbl_id);
    s = format(s, "\n%Ubdt_is_add: %u", format_white_space, indent, a->bdt_is_add);
    return s;
}

static inline u8 *vl_api_bier_disp_table_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_table_add_del_reply_t *a = va_arg (*args, vl_api_bier_disp_table_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_table_add_del_reply_t: */
    s = format(s, "vl_api_bier_disp_table_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bier_disp_table_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_table_dump_t *a = va_arg (*args, vl_api_bier_disp_table_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_table_dump_t: */
    s = format(s, "vl_api_bier_disp_table_dump_t:");
    return s;
}

static inline u8 *vl_api_bier_disp_table_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_table_details_t *a = va_arg (*args, vl_api_bier_disp_table_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_table_details_t: */
    s = format(s, "vl_api_bier_disp_table_details_t:");
    s = format(s, "\n%Ubdt_tbl_id: %u", format_white_space, indent, a->bdt_tbl_id);
    return s;
}

static inline u8 *vl_api_bier_disp_entry_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_entry_add_del_t *a = va_arg (*args, vl_api_bier_disp_entry_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_entry_add_del_t: */
    s = format(s, "vl_api_bier_disp_entry_add_del_t:");
    s = format(s, "\n%Ubde_bp: %u", format_white_space, indent, a->bde_bp);
    s = format(s, "\n%Ubde_tbl_id: %u", format_white_space, indent, a->bde_tbl_id);
    s = format(s, "\n%Ubde_is_add: %u", format_white_space, indent, a->bde_is_add);
    s = format(s, "\n%Ubde_payload_proto: %u", format_white_space, indent, a->bde_payload_proto);
    s = format(s, "\n%Ubde_n_paths: %u", format_white_space, indent, a->bde_n_paths);
    for (i = 0; i < a->bde_n_paths; i++) {
        s = format(s, "\n%Ubde_paths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->bde_paths[i], indent);
    }
    return s;
}

static inline u8 *vl_api_bier_disp_entry_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_entry_add_del_reply_t *a = va_arg (*args, vl_api_bier_disp_entry_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_entry_add_del_reply_t: */
    s = format(s, "vl_api_bier_disp_entry_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_bier_disp_entry_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_entry_dump_t *a = va_arg (*args, vl_api_bier_disp_entry_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_entry_dump_t: */
    s = format(s, "vl_api_bier_disp_entry_dump_t:");
    s = format(s, "\n%Ubde_tbl_id: %u", format_white_space, indent, a->bde_tbl_id);
    return s;
}

static inline u8 *vl_api_bier_disp_entry_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_bier_disp_entry_details_t *a = va_arg (*args, vl_api_bier_disp_entry_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_bier_disp_entry_details_t: */
    s = format(s, "vl_api_bier_disp_entry_details_t:");
    s = format(s, "\n%Ubde_bp: %u", format_white_space, indent, a->bde_bp);
    s = format(s, "\n%Ubde_tbl_id: %u", format_white_space, indent, a->bde_tbl_id);
    s = format(s, "\n%Ubde_is_add: %u", format_white_space, indent, a->bde_is_add);
    s = format(s, "\n%Ubde_payload_proto: %u", format_white_space, indent, a->bde_payload_proto);
    s = format(s, "\n%Ubde_n_paths: %u", format_white_space, indent, a->bde_n_paths);
    for (i = 0; i < a->bde_n_paths; i++) {
        s = format(s, "\n%Ubde_paths: %U",
                   format_white_space, indent, format_vl_api_fib_path_t, &a->bde_paths[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_bier_endianfun
#define included_bier_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_bier_table_id_t_endian (vl_api_bier_table_id_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->bt_set = a->bt_set (no-op) */
    /* a->bt_sub_domain = a->bt_sub_domain (no-op) */
    /* a->bt_hdr_len_id = a->bt_hdr_len_id (no-op) */
}

static inline void vl_api_bier_route_t_endian (vl_api_bier_route_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->br_bp = clib_net_to_host_u32(a->br_bp);
    vl_api_bier_table_id_t_endian(&a->br_tbl_id, to_net);
    /* a->br_n_paths = a->br_n_paths (no-op) */
    u32 count = a->br_n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->br_paths[i], to_net);
    }
}

static inline void vl_api_bier_table_add_del_t_endian (vl_api_bier_table_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_bier_table_id_t_endian(&a->bt_tbl_id, to_net);
    a->bt_label = clib_net_to_host_u32(a->bt_label);
    /* a->bt_is_add = a->bt_is_add (no-op) */
}

static inline void vl_api_bier_table_add_del_reply_t_endian (vl_api_bier_table_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bier_table_dump_t_endian (vl_api_bier_table_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_bier_table_details_t_endian (vl_api_bier_table_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->bt_label = clib_net_to_host_u32(a->bt_label);
    vl_api_bier_table_id_t_endian(&a->bt_tbl_id, to_net);
}

static inline void vl_api_bier_route_add_del_t_endian (vl_api_bier_route_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->br_is_add = a->br_is_add (no-op) */
    /* a->br_is_replace = a->br_is_replace (no-op) */
    vl_api_bier_route_t_endian(&a->br_route, to_net);
}

static inline void vl_api_bier_route_add_del_reply_t_endian (vl_api_bier_route_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bier_route_dump_t_endian (vl_api_bier_route_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_bier_table_id_t_endian(&a->br_tbl_id, to_net);
}

static inline void vl_api_bier_route_details_t_endian (vl_api_bier_route_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_bier_route_t_endian(&a->br_route, to_net);
}

static inline void vl_api_bier_imp_add_t_endian (vl_api_bier_imp_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_bier_table_id_t_endian(&a->bi_tbl_id, to_net);
    a->bi_src = clib_net_to_host_u16(a->bi_src);
    /* a->bi_n_bytes = a->bi_n_bytes (no-op) */
    /* a->bi_bytes = a->bi_bytes (no-op) */
}

static inline void vl_api_bier_imp_add_reply_t_endian (vl_api_bier_imp_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->bi_index = clib_net_to_host_u32(a->bi_index);
}

static inline void vl_api_bier_imp_del_t_endian (vl_api_bier_imp_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bi_index = clib_net_to_host_u32(a->bi_index);
}

static inline void vl_api_bier_imp_del_reply_t_endian (vl_api_bier_imp_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bier_imp_dump_t_endian (vl_api_bier_imp_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_bier_imp_details_t_endian (vl_api_bier_imp_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_bier_table_id_t_endian(&a->bi_tbl_id, to_net);
    a->bi_src = clib_net_to_host_u16(a->bi_src);
    /* a->bi_n_bytes = a->bi_n_bytes (no-op) */
    /* a->bi_bytes = a->bi_bytes (no-op) */
}

static inline void vl_api_bier_disp_table_add_del_t_endian (vl_api_bier_disp_table_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bdt_tbl_id = clib_net_to_host_u32(a->bdt_tbl_id);
    /* a->bdt_is_add = a->bdt_is_add (no-op) */
}

static inline void vl_api_bier_disp_table_add_del_reply_t_endian (vl_api_bier_disp_table_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bier_disp_table_dump_t_endian (vl_api_bier_disp_table_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_bier_disp_table_details_t_endian (vl_api_bier_disp_table_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->bdt_tbl_id = clib_net_to_host_u32(a->bdt_tbl_id);
}

static inline void vl_api_bier_disp_entry_add_del_t_endian (vl_api_bier_disp_entry_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bde_bp = clib_net_to_host_u16(a->bde_bp);
    a->bde_tbl_id = clib_net_to_host_u32(a->bde_tbl_id);
    /* a->bde_is_add = a->bde_is_add (no-op) */
    /* a->bde_payload_proto = a->bde_payload_proto (no-op) */
    /* a->bde_n_paths = a->bde_n_paths (no-op) */
    u32 count = a->bde_n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->bde_paths[i], to_net);
    }
}

static inline void vl_api_bier_disp_entry_add_del_reply_t_endian (vl_api_bier_disp_entry_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_bier_disp_entry_dump_t_endian (vl_api_bier_disp_entry_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->bde_tbl_id = clib_net_to_host_u32(a->bde_tbl_id);
}

static inline void vl_api_bier_disp_entry_details_t_endian (vl_api_bier_disp_entry_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->bde_bp = clib_net_to_host_u16(a->bde_bp);
    a->bde_tbl_id = clib_net_to_host_u32(a->bde_tbl_id);
    /* a->bde_is_add = a->bde_is_add (no-op) */
    /* a->bde_payload_proto = a->bde_payload_proto (no-op) */
    /* a->bde_n_paths = a->bde_n_paths (no-op) */
    u32 count = a->bde_n_paths;
    for (i = 0; i < count; i++) {
        vl_api_fib_path_t_endian(&a->bde_paths[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_bier_calcsizefun
#define included_bier_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_table_id_t_calc_size (vl_api_bier_table_id_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_route_t_calc_size (vl_api_bier_route_t *a)
{
      return sizeof(*a) - sizeof(a->br_tbl_id) + vl_api_bier_table_id_t_calc_size(&a->br_tbl_id) + a->br_n_paths * sizeof(a->br_paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_table_add_del_t_calc_size (vl_api_bier_table_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->bt_tbl_id) + vl_api_bier_table_id_t_calc_size(&a->bt_tbl_id);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_table_add_del_reply_t_calc_size (vl_api_bier_table_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_table_dump_t_calc_size (vl_api_bier_table_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_table_details_t_calc_size (vl_api_bier_table_details_t *a)
{
      return sizeof(*a) - sizeof(a->bt_tbl_id) + vl_api_bier_table_id_t_calc_size(&a->bt_tbl_id);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_route_add_del_t_calc_size (vl_api_bier_route_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->br_route) + vl_api_bier_route_t_calc_size(&a->br_route);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_route_add_del_reply_t_calc_size (vl_api_bier_route_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_route_dump_t_calc_size (vl_api_bier_route_dump_t *a)
{
      return sizeof(*a) - sizeof(a->br_tbl_id) + vl_api_bier_table_id_t_calc_size(&a->br_tbl_id);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_route_details_t_calc_size (vl_api_bier_route_details_t *a)
{
      return sizeof(*a) - sizeof(a->br_route) + vl_api_bier_route_t_calc_size(&a->br_route);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_imp_add_t_calc_size (vl_api_bier_imp_add_t *a)
{
      return sizeof(*a) - sizeof(a->bi_tbl_id) + vl_api_bier_table_id_t_calc_size(&a->bi_tbl_id) + a->bi_n_bytes * sizeof(a->bi_bytes[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_imp_add_reply_t_calc_size (vl_api_bier_imp_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_imp_del_t_calc_size (vl_api_bier_imp_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_imp_del_reply_t_calc_size (vl_api_bier_imp_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_imp_dump_t_calc_size (vl_api_bier_imp_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_imp_details_t_calc_size (vl_api_bier_imp_details_t *a)
{
      return sizeof(*a) - sizeof(a->bi_tbl_id) + vl_api_bier_table_id_t_calc_size(&a->bi_tbl_id) + a->bi_n_bytes * sizeof(a->bi_bytes[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_table_add_del_t_calc_size (vl_api_bier_disp_table_add_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_table_add_del_reply_t_calc_size (vl_api_bier_disp_table_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_table_dump_t_calc_size (vl_api_bier_disp_table_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_table_details_t_calc_size (vl_api_bier_disp_table_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_entry_add_del_t_calc_size (vl_api_bier_disp_entry_add_del_t *a)
{
      return sizeof(*a) + a->bde_n_paths * sizeof(a->bde_paths[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_entry_add_del_reply_t_calc_size (vl_api_bier_disp_entry_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_entry_dump_t_calc_size (vl_api_bier_disp_entry_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_bier_disp_entry_details_t_calc_size (vl_api_bier_disp_entry_details_t *a)
{
      return sizeof(*a) + a->bde_n_paths * sizeof(a->bde_paths[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(bier.api, 1, 2, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(bier.api, 0x48fa264f)

#endif

