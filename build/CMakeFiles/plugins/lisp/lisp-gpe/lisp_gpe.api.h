/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: lisp_gpe.api
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
#warning no content included from lisp_gpe.api
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
#include <lisp/lisp-cp/lisp_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_GPE_ADD_DEL_FWD_ENTRY, vl_api_gpe_add_del_fwd_entry_t_handler)
vl_msg_id(VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY, vl_api_gpe_add_del_fwd_entry_reply_t_handler)
vl_msg_id(VL_API_GPE_ENABLE_DISABLE, vl_api_gpe_enable_disable_t_handler)
vl_msg_id(VL_API_GPE_ENABLE_DISABLE_REPLY, vl_api_gpe_enable_disable_reply_t_handler)
vl_msg_id(VL_API_GPE_ADD_DEL_IFACE, vl_api_gpe_add_del_iface_t_handler)
vl_msg_id(VL_API_GPE_ADD_DEL_IFACE_REPLY, vl_api_gpe_add_del_iface_reply_t_handler)
vl_msg_id(VL_API_GPE_FWD_ENTRY_VNIS_GET, vl_api_gpe_fwd_entry_vnis_get_t_handler)
vl_msg_id(VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY, vl_api_gpe_fwd_entry_vnis_get_reply_t_handler)
vl_msg_id(VL_API_GPE_FWD_ENTRIES_GET, vl_api_gpe_fwd_entries_get_t_handler)
vl_msg_id(VL_API_GPE_FWD_ENTRIES_GET_REPLY, vl_api_gpe_fwd_entries_get_reply_t_handler)
vl_msg_id(VL_API_GPE_FWD_ENTRY_PATH_DUMP, vl_api_gpe_fwd_entry_path_dump_t_handler)
vl_msg_id(VL_API_GPE_FWD_ENTRY_PATH_DETAILS, vl_api_gpe_fwd_entry_path_details_t_handler)
vl_msg_id(VL_API_GPE_SET_ENCAP_MODE, vl_api_gpe_set_encap_mode_t_handler)
vl_msg_id(VL_API_GPE_SET_ENCAP_MODE_REPLY, vl_api_gpe_set_encap_mode_reply_t_handler)
vl_msg_id(VL_API_GPE_GET_ENCAP_MODE, vl_api_gpe_get_encap_mode_t_handler)
vl_msg_id(VL_API_GPE_GET_ENCAP_MODE_REPLY, vl_api_gpe_get_encap_mode_reply_t_handler)
vl_msg_id(VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH, vl_api_gpe_add_del_native_fwd_rpath_t_handler)
vl_msg_id(VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY, vl_api_gpe_add_del_native_fwd_rpath_reply_t_handler)
vl_msg_id(VL_API_GPE_NATIVE_FWD_RPATHS_GET, vl_api_gpe_native_fwd_rpaths_get_t_handler)
vl_msg_id(VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY, vl_api_gpe_native_fwd_rpaths_get_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_gpe_add_del_fwd_entry_t, 1)
vl_msg_name(vl_api_gpe_add_del_fwd_entry_reply_t, 1)
vl_msg_name(vl_api_gpe_enable_disable_t, 1)
vl_msg_name(vl_api_gpe_enable_disable_reply_t, 1)
vl_msg_name(vl_api_gpe_add_del_iface_t, 1)
vl_msg_name(vl_api_gpe_add_del_iface_reply_t, 1)
vl_msg_name(vl_api_gpe_fwd_entry_vnis_get_t, 1)
vl_msg_name(vl_api_gpe_fwd_entry_vnis_get_reply_t, 1)
vl_msg_name(vl_api_gpe_fwd_entries_get_t, 1)
vl_msg_name(vl_api_gpe_fwd_entries_get_reply_t, 1)
vl_msg_name(vl_api_gpe_fwd_entry_path_dump_t, 1)
vl_msg_name(vl_api_gpe_fwd_entry_path_details_t, 1)
vl_msg_name(vl_api_gpe_set_encap_mode_t, 1)
vl_msg_name(vl_api_gpe_set_encap_mode_reply_t, 1)
vl_msg_name(vl_api_gpe_get_encap_mode_t, 1)
vl_msg_name(vl_api_gpe_get_encap_mode_reply_t, 1)
vl_msg_name(vl_api_gpe_add_del_native_fwd_rpath_t, 1)
vl_msg_name(vl_api_gpe_add_del_native_fwd_rpath_reply_t, 1)
vl_msg_name(vl_api_gpe_native_fwd_rpaths_get_t, 1)
vl_msg_name(vl_api_gpe_native_fwd_rpaths_get_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_lisp_gpe \
_(VL_API_GPE_ADD_DEL_FWD_ENTRY, gpe_add_del_fwd_entry, f0847644) \
_(VL_API_GPE_ADD_DEL_FWD_ENTRY_REPLY, gpe_add_del_fwd_entry_reply, efe5f176) \
_(VL_API_GPE_ENABLE_DISABLE, gpe_enable_disable, c264d7bf) \
_(VL_API_GPE_ENABLE_DISABLE_REPLY, gpe_enable_disable_reply, e8d4e804) \
_(VL_API_GPE_ADD_DEL_IFACE, gpe_add_del_iface, 3ccff273) \
_(VL_API_GPE_ADD_DEL_IFACE_REPLY, gpe_add_del_iface_reply, e8d4e804) \
_(VL_API_GPE_FWD_ENTRY_VNIS_GET, gpe_fwd_entry_vnis_get, 51077d14) \
_(VL_API_GPE_FWD_ENTRY_VNIS_GET_REPLY, gpe_fwd_entry_vnis_get_reply, aa70da20) \
_(VL_API_GPE_FWD_ENTRIES_GET, gpe_fwd_entries_get, 8d1f2fe9) \
_(VL_API_GPE_FWD_ENTRIES_GET_REPLY, gpe_fwd_entries_get_reply, c4844876) \
_(VL_API_GPE_FWD_ENTRY_PATH_DUMP, gpe_fwd_entry_path_dump, 39bce980) \
_(VL_API_GPE_FWD_ENTRY_PATH_DETAILS, gpe_fwd_entry_path_details, 483df51a) \
_(VL_API_GPE_SET_ENCAP_MODE, gpe_set_encap_mode, bd819eac) \
_(VL_API_GPE_SET_ENCAP_MODE_REPLY, gpe_set_encap_mode_reply, e8d4e804) \
_(VL_API_GPE_GET_ENCAP_MODE, gpe_get_encap_mode, 51077d14) \
_(VL_API_GPE_GET_ENCAP_MODE_REPLY, gpe_get_encap_mode_reply, 36e3f7ca) \
_(VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH, gpe_add_del_native_fwd_rpath, 43fc8b54) \
_(VL_API_GPE_ADD_DEL_NATIVE_FWD_RPATH_REPLY, gpe_add_del_native_fwd_rpath_reply, e8d4e804) \
_(VL_API_GPE_NATIVE_FWD_RPATHS_GET, gpe_native_fwd_rpaths_get, f652ceb4) \
_(VL_API_GPE_NATIVE_FWD_RPATHS_GET_REPLY, gpe_native_fwd_rpaths_get_reply, 7a1ca5a2) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "lisp_gpe.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lisp_gpe_printfun_types
#define included_lisp_gpe_printfun_types

static inline u8 *format_vl_api_gpe_locator_t (u8 *s, va_list * args)
{
    vl_api_gpe_locator_t *a = va_arg (*args, vl_api_gpe_locator_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uweight: %u", format_white_space, indent, a->weight);
    s = format(s, "\n%Uaddr: %U", format_white_space, indent, format_vl_api_address_t, &a->addr, indent);
    return s;
}

static inline u8 *format_vl_api_gpe_fwd_entry_t (u8 *s, va_list * args)
{
    vl_api_gpe_fwd_entry_t *a = va_arg (*args, vl_api_gpe_fwd_entry_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufwd_entry_index: %u", format_white_space, indent, a->fwd_entry_index);
    s = format(s, "\n%Udp_table: %u", format_white_space, indent, a->dp_table);
    s = format(s, "\n%Uleid: %U", format_white_space, indent, format_vl_api_eid_t, &a->leid, indent);
    s = format(s, "\n%Ureid: %U", format_white_space, indent, format_vl_api_eid_t, &a->reid, indent);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Uaction: %u", format_white_space, indent, a->action);
    return s;
}

static inline u8 *format_vl_api_gpe_native_fwd_rpath_t (u8 *s, va_list * args)
{
    vl_api_gpe_native_fwd_rpath_t *a = va_arg (*args, vl_api_gpe_native_fwd_rpath_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ufib_index: %u", format_white_space, indent, a->fib_index);
    s = format(s, "\n%Unh_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->nh_sw_if_index, indent);
    s = format(s, "\n%Unh_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->nh_addr, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_lisp_gpe_printfun
#define included_lisp_gpe_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "lisp_gpe.api_tojson.h"
#include "lisp_gpe.api_fromjson.h"

static inline u8 *vl_api_gpe_add_del_fwd_entry_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_add_del_fwd_entry_t *a = va_arg (*args, vl_api_gpe_add_del_fwd_entry_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_add_del_fwd_entry_t: */
    s = format(s, "vl_api_gpe_add_del_fwd_entry_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Urmt_eid: %U", format_white_space, indent, format_vl_api_eid_t, &a->rmt_eid, indent);
    s = format(s, "\n%Ulcl_eid: %U", format_white_space, indent, format_vl_api_eid_t, &a->lcl_eid, indent);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    s = format(s, "\n%Udp_table: %u", format_white_space, indent, a->dp_table);
    s = format(s, "\n%Uaction: %u", format_white_space, indent, a->action);
    s = format(s, "\n%Uloc_num: %u", format_white_space, indent, a->loc_num);
    for (i = 0; i < a->loc_num; i++) {
        s = format(s, "\n%Ulocs: %U",
                   format_white_space, indent, format_vl_api_gpe_locator_t, &a->locs[i], indent);
    }
    return s;
}

static inline u8 *vl_api_gpe_add_del_fwd_entry_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_add_del_fwd_entry_reply_t *a = va_arg (*args, vl_api_gpe_add_del_fwd_entry_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_add_del_fwd_entry_reply_t: */
    s = format(s, "vl_api_gpe_add_del_fwd_entry_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ufwd_entry_index: %u", format_white_space, indent, a->fwd_entry_index);
    return s;
}

static inline u8 *vl_api_gpe_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_enable_disable_t *a = va_arg (*args, vl_api_gpe_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_enable_disable_t: */
    s = format(s, "vl_api_gpe_enable_disable_t:");
    s = format(s, "\n%Uis_enable: %u", format_white_space, indent, a->is_enable);
    return s;
}

static inline u8 *vl_api_gpe_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_enable_disable_reply_t *a = va_arg (*args, vl_api_gpe_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_enable_disable_reply_t: */
    s = format(s, "vl_api_gpe_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gpe_add_del_iface_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_add_del_iface_t *a = va_arg (*args, vl_api_gpe_add_del_iface_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_add_del_iface_t: */
    s = format(s, "vl_api_gpe_add_del_iface_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uis_l2: %u", format_white_space, indent, a->is_l2);
    s = format(s, "\n%Udp_table: %u", format_white_space, indent, a->dp_table);
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_gpe_add_del_iface_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_add_del_iface_reply_t *a = va_arg (*args, vl_api_gpe_add_del_iface_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_add_del_iface_reply_t: */
    s = format(s, "vl_api_gpe_add_del_iface_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gpe_fwd_entry_vnis_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_fwd_entry_vnis_get_t *a = va_arg (*args, vl_api_gpe_fwd_entry_vnis_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_fwd_entry_vnis_get_t: */
    s = format(s, "vl_api_gpe_fwd_entry_vnis_get_t:");
    return s;
}

static inline u8 *vl_api_gpe_fwd_entry_vnis_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_fwd_entry_vnis_get_reply_t *a = va_arg (*args, vl_api_gpe_fwd_entry_vnis_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_fwd_entry_vnis_get_reply_t: */
    s = format(s, "vl_api_gpe_fwd_entry_vnis_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uvnis: %u",
                   format_white_space, indent, a->vnis[i]);
    }
    return s;
}

static inline u8 *vl_api_gpe_fwd_entries_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_fwd_entries_get_t *a = va_arg (*args, vl_api_gpe_fwd_entries_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_fwd_entries_get_t: */
    s = format(s, "vl_api_gpe_fwd_entries_get_t:");
    s = format(s, "\n%Uvni: %u", format_white_space, indent, a->vni);
    return s;
}

static inline u8 *vl_api_gpe_fwd_entries_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_fwd_entries_get_reply_t *a = va_arg (*args, vl_api_gpe_fwd_entries_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_fwd_entries_get_reply_t: */
    s = format(s, "vl_api_gpe_fwd_entries_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uentries: %U",
                   format_white_space, indent, format_vl_api_gpe_fwd_entry_t, &a->entries[i], indent);
    }
    return s;
}

static inline u8 *vl_api_gpe_fwd_entry_path_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_fwd_entry_path_dump_t *a = va_arg (*args, vl_api_gpe_fwd_entry_path_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_fwd_entry_path_dump_t: */
    s = format(s, "vl_api_gpe_fwd_entry_path_dump_t:");
    s = format(s, "\n%Ufwd_entry_index: %u", format_white_space, indent, a->fwd_entry_index);
    return s;
}

static inline u8 *vl_api_gpe_fwd_entry_path_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_fwd_entry_path_details_t *a = va_arg (*args, vl_api_gpe_fwd_entry_path_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_fwd_entry_path_details_t: */
    s = format(s, "vl_api_gpe_fwd_entry_path_details_t:");
    s = format(s, "\n%Ulcl_loc: %U", format_white_space, indent, format_vl_api_gpe_locator_t, &a->lcl_loc, indent);
    s = format(s, "\n%Urmt_loc: %U", format_white_space, indent, format_vl_api_gpe_locator_t, &a->rmt_loc, indent);
    return s;
}

static inline u8 *vl_api_gpe_set_encap_mode_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_set_encap_mode_t *a = va_arg (*args, vl_api_gpe_set_encap_mode_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_set_encap_mode_t: */
    s = format(s, "vl_api_gpe_set_encap_mode_t:");
    s = format(s, "\n%Uis_vxlan: %u", format_white_space, indent, a->is_vxlan);
    return s;
}

static inline u8 *vl_api_gpe_set_encap_mode_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_set_encap_mode_reply_t *a = va_arg (*args, vl_api_gpe_set_encap_mode_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_set_encap_mode_reply_t: */
    s = format(s, "vl_api_gpe_set_encap_mode_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gpe_get_encap_mode_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_get_encap_mode_t *a = va_arg (*args, vl_api_gpe_get_encap_mode_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_get_encap_mode_t: */
    s = format(s, "vl_api_gpe_get_encap_mode_t:");
    return s;
}

static inline u8 *vl_api_gpe_get_encap_mode_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_get_encap_mode_reply_t *a = va_arg (*args, vl_api_gpe_get_encap_mode_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_get_encap_mode_reply_t: */
    s = format(s, "vl_api_gpe_get_encap_mode_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uencap_mode: %u", format_white_space, indent, a->encap_mode);
    return s;
}

static inline u8 *vl_api_gpe_add_del_native_fwd_rpath_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_add_del_native_fwd_rpath_t *a = va_arg (*args, vl_api_gpe_add_del_native_fwd_rpath_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_add_del_native_fwd_rpath_t: */
    s = format(s, "vl_api_gpe_add_del_native_fwd_rpath_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Utable_id: %u", format_white_space, indent, a->table_id);
    s = format(s, "\n%Unh_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->nh_sw_if_index, indent);
    s = format(s, "\n%Unh_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->nh_addr, indent);
    return s;
}

static inline u8 *vl_api_gpe_add_del_native_fwd_rpath_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_add_del_native_fwd_rpath_reply_t *a = va_arg (*args, vl_api_gpe_add_del_native_fwd_rpath_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_add_del_native_fwd_rpath_reply_t: */
    s = format(s, "vl_api_gpe_add_del_native_fwd_rpath_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_gpe_native_fwd_rpaths_get_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_native_fwd_rpaths_get_t *a = va_arg (*args, vl_api_gpe_native_fwd_rpaths_get_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_native_fwd_rpaths_get_t: */
    s = format(s, "vl_api_gpe_native_fwd_rpaths_get_t:");
    s = format(s, "\n%Uis_ip4: %u", format_white_space, indent, a->is_ip4);
    return s;
}

static inline u8 *vl_api_gpe_native_fwd_rpaths_get_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_gpe_native_fwd_rpaths_get_reply_t *a = va_arg (*args, vl_api_gpe_native_fwd_rpaths_get_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_gpe_native_fwd_rpaths_get_reply_t: */
    s = format(s, "vl_api_gpe_native_fwd_rpaths_get_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ucount: %u", format_white_space, indent, a->count);
    for (i = 0; i < a->count; i++) {
        s = format(s, "\n%Uentries: %U",
                   format_white_space, indent, format_vl_api_gpe_native_fwd_rpath_t, &a->entries[i], indent);
    }
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_lisp_gpe_endianfun
#define included_lisp_gpe_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_gpe_locator_t_endian (vl_api_gpe_locator_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->weight = a->weight (no-op) */
    vl_api_address_t_endian(&a->addr, to_net);
}

static inline void vl_api_gpe_fwd_entry_t_endian (vl_api_gpe_fwd_entry_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->fwd_entry_index = clib_net_to_host_u32(a->fwd_entry_index);
    a->dp_table = clib_net_to_host_u32(a->dp_table);
    vl_api_eid_t_endian(&a->leid, to_net);
    vl_api_eid_t_endian(&a->reid, to_net);
    a->vni = clib_net_to_host_u32(a->vni);
    /* a->action = a->action (no-op) */
}

static inline void vl_api_gpe_native_fwd_rpath_t_endian (vl_api_gpe_native_fwd_rpath_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->fib_index = clib_net_to_host_u32(a->fib_index);
    vl_api_interface_index_t_endian(&a->nh_sw_if_index, to_net);
    vl_api_address_t_endian(&a->nh_addr, to_net);
}

static inline void vl_api_gpe_add_del_fwd_entry_t_endian (vl_api_gpe_add_del_fwd_entry_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_eid_t_endian(&a->rmt_eid, to_net);
    vl_api_eid_t_endian(&a->lcl_eid, to_net);
    a->vni = clib_net_to_host_u32(a->vni);
    a->dp_table = clib_net_to_host_u32(a->dp_table);
    /* a->action = a->action (no-op) */
    a->loc_num = clib_net_to_host_u32(a->loc_num);
    u32 count = to_net ? clib_net_to_host_u32(a->loc_num) : a->loc_num;
    for (i = 0; i < count; i++) {
        vl_api_gpe_locator_t_endian(&a->locs[i], to_net);
    }
}

static inline void vl_api_gpe_add_del_fwd_entry_reply_t_endian (vl_api_gpe_add_del_fwd_entry_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->fwd_entry_index = clib_net_to_host_u32(a->fwd_entry_index);
}

static inline void vl_api_gpe_enable_disable_t_endian (vl_api_gpe_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_enable = a->is_enable (no-op) */
}

static inline void vl_api_gpe_enable_disable_reply_t_endian (vl_api_gpe_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gpe_add_del_iface_t_endian (vl_api_gpe_add_del_iface_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->is_l2 = a->is_l2 (no-op) */
    a->dp_table = clib_net_to_host_u32(a->dp_table);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_gpe_add_del_iface_reply_t_endian (vl_api_gpe_add_del_iface_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gpe_fwd_entry_vnis_get_t_endian (vl_api_gpe_fwd_entry_vnis_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_gpe_fwd_entry_vnis_get_reply_t_endian (vl_api_gpe_fwd_entry_vnis_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->vnis[i] = clib_net_to_host_u32(a->vnis[i]);
    }
}

static inline void vl_api_gpe_fwd_entries_get_t_endian (vl_api_gpe_fwd_entries_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->vni = clib_net_to_host_u32(a->vni);
}

static inline void vl_api_gpe_fwd_entries_get_reply_t_endian (vl_api_gpe_fwd_entries_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_gpe_fwd_entry_t_endian(&a->entries[i], to_net);
    }
}

static inline void vl_api_gpe_fwd_entry_path_dump_t_endian (vl_api_gpe_fwd_entry_path_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->fwd_entry_index = clib_net_to_host_u32(a->fwd_entry_index);
}

static inline void vl_api_gpe_fwd_entry_path_details_t_endian (vl_api_gpe_fwd_entry_path_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_gpe_locator_t_endian(&a->lcl_loc, to_net);
    vl_api_gpe_locator_t_endian(&a->rmt_loc, to_net);
}

static inline void vl_api_gpe_set_encap_mode_t_endian (vl_api_gpe_set_encap_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_vxlan = a->is_vxlan (no-op) */
}

static inline void vl_api_gpe_set_encap_mode_reply_t_endian (vl_api_gpe_set_encap_mode_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gpe_get_encap_mode_t_endian (vl_api_gpe_get_encap_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_gpe_get_encap_mode_reply_t_endian (vl_api_gpe_get_encap_mode_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    /* a->encap_mode = a->encap_mode (no-op) */
}

static inline void vl_api_gpe_add_del_native_fwd_rpath_t_endian (vl_api_gpe_add_del_native_fwd_rpath_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->table_id = clib_net_to_host_u32(a->table_id);
    vl_api_interface_index_t_endian(&a->nh_sw_if_index, to_net);
    vl_api_address_t_endian(&a->nh_addr, to_net);
}

static inline void vl_api_gpe_add_del_native_fwd_rpath_reply_t_endian (vl_api_gpe_add_del_native_fwd_rpath_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_gpe_native_fwd_rpaths_get_t_endian (vl_api_gpe_native_fwd_rpaths_get_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_ip4 = a->is_ip4 (no-op) */
}

static inline void vl_api_gpe_native_fwd_rpaths_get_reply_t_endian (vl_api_gpe_native_fwd_rpaths_get_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->count = clib_net_to_host_u32(a->count);
    u32 count = to_net ? clib_net_to_host_u32(a->count) : a->count;
    for (i = 0; i < count; i++) {
        vl_api_gpe_native_fwd_rpath_t_endian(&a->entries[i], to_net);
    }
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_lisp_gpe_calcsizefun
#define included_lisp_gpe_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_locator_t_calc_size (vl_api_gpe_locator_t *a)
{
      return sizeof(*a) - sizeof(a->addr) + vl_api_address_t_calc_size(&a->addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entry_t_calc_size (vl_api_gpe_fwd_entry_t *a)
{
      return sizeof(*a) - sizeof(a->leid) + vl_api_eid_t_calc_size(&a->leid) - sizeof(a->reid) + vl_api_eid_t_calc_size(&a->reid);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_native_fwd_rpath_t_calc_size (vl_api_gpe_native_fwd_rpath_t *a)
{
      return sizeof(*a) - sizeof(a->nh_sw_if_index) + vl_api_interface_index_t_calc_size(&a->nh_sw_if_index) - sizeof(a->nh_addr) + vl_api_address_t_calc_size(&a->nh_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_add_del_fwd_entry_t_calc_size (vl_api_gpe_add_del_fwd_entry_t *a)
{
      return sizeof(*a) - sizeof(a->rmt_eid) + vl_api_eid_t_calc_size(&a->rmt_eid) - sizeof(a->lcl_eid) + vl_api_eid_t_calc_size(&a->lcl_eid) + clib_net_to_host_u32(a->loc_num) * sizeof(a->locs[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_add_del_fwd_entry_reply_t_calc_size (vl_api_gpe_add_del_fwd_entry_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_enable_disable_t_calc_size (vl_api_gpe_enable_disable_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_enable_disable_reply_t_calc_size (vl_api_gpe_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_add_del_iface_t_calc_size (vl_api_gpe_add_del_iface_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_add_del_iface_reply_t_calc_size (vl_api_gpe_add_del_iface_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entry_vnis_get_t_calc_size (vl_api_gpe_fwd_entry_vnis_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entry_vnis_get_reply_t_calc_size (vl_api_gpe_fwd_entry_vnis_get_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->vnis[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entries_get_t_calc_size (vl_api_gpe_fwd_entries_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entries_get_reply_t_calc_size (vl_api_gpe_fwd_entries_get_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->entries[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entry_path_dump_t_calc_size (vl_api_gpe_fwd_entry_path_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_fwd_entry_path_details_t_calc_size (vl_api_gpe_fwd_entry_path_details_t *a)
{
      return sizeof(*a) - sizeof(a->lcl_loc) + vl_api_gpe_locator_t_calc_size(&a->lcl_loc) - sizeof(a->rmt_loc) + vl_api_gpe_locator_t_calc_size(&a->rmt_loc);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_set_encap_mode_t_calc_size (vl_api_gpe_set_encap_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_set_encap_mode_reply_t_calc_size (vl_api_gpe_set_encap_mode_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_get_encap_mode_t_calc_size (vl_api_gpe_get_encap_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_get_encap_mode_reply_t_calc_size (vl_api_gpe_get_encap_mode_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_add_del_native_fwd_rpath_t_calc_size (vl_api_gpe_add_del_native_fwd_rpath_t *a)
{
      return sizeof(*a) - sizeof(a->nh_sw_if_index) + vl_api_interface_index_t_calc_size(&a->nh_sw_if_index) - sizeof(a->nh_addr) + vl_api_address_t_calc_size(&a->nh_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_add_del_native_fwd_rpath_reply_t_calc_size (vl_api_gpe_add_del_native_fwd_rpath_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_native_fwd_rpaths_get_t_calc_size (vl_api_gpe_native_fwd_rpaths_get_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_gpe_native_fwd_rpaths_get_reply_t_calc_size (vl_api_gpe_native_fwd_rpaths_get_reply_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->count) * sizeof(a->entries[0]);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(lisp_gpe.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(lisp_gpe.api, 0x29addfc9)

#endif

