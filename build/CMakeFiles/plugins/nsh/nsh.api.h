/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: nsh.api
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
#warning no content included from nsh.api
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
vl_msg_id(VL_API_NSH_ADD_DEL_ENTRY, vl_api_nsh_add_del_entry_t_handler)
vl_msg_id(VL_API_NSH_ADD_DEL_ENTRY_REPLY, vl_api_nsh_add_del_entry_reply_t_handler)
vl_msg_id(VL_API_NSH_ENTRY_DUMP, vl_api_nsh_entry_dump_t_handler)
vl_msg_id(VL_API_NSH_ENTRY_DETAILS, vl_api_nsh_entry_details_t_handler)
vl_msg_id(VL_API_NSH_ADD_DEL_MAP, vl_api_nsh_add_del_map_t_handler)
vl_msg_id(VL_API_NSH_ADD_DEL_MAP_REPLY, vl_api_nsh_add_del_map_reply_t_handler)
vl_msg_id(VL_API_NSH_MAP_DUMP, vl_api_nsh_map_dump_t_handler)
vl_msg_id(VL_API_NSH_MAP_DETAILS, vl_api_nsh_map_details_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_nsh_add_del_entry_t, 1)
vl_msg_name(vl_api_nsh_add_del_entry_reply_t, 1)
vl_msg_name(vl_api_nsh_entry_dump_t, 1)
vl_msg_name(vl_api_nsh_entry_details_t, 1)
vl_msg_name(vl_api_nsh_add_del_map_t, 1)
vl_msg_name(vl_api_nsh_add_del_map_reply_t, 1)
vl_msg_name(vl_api_nsh_map_dump_t, 1)
vl_msg_name(vl_api_nsh_map_details_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_nsh \
_(VL_API_NSH_ADD_DEL_ENTRY, nsh_add_del_entry, 7dea480b) \
_(VL_API_NSH_ADD_DEL_ENTRY_REPLY, nsh_add_del_entry_reply, 6296a9eb) \
_(VL_API_NSH_ENTRY_DUMP, nsh_entry_dump, cdaf8ccb) \
_(VL_API_NSH_ENTRY_DETAILS, nsh_entry_details, 046fb556) \
_(VL_API_NSH_ADD_DEL_MAP, nsh_add_del_map, 0a0f42b0) \
_(VL_API_NSH_ADD_DEL_MAP_REPLY, nsh_add_del_map_reply, b2b127ef) \
_(VL_API_NSH_MAP_DUMP, nsh_map_dump, 8fc06b82) \
_(VL_API_NSH_MAP_DETAILS, nsh_map_details, 2fefcf49) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "nsh.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nsh_printfun_types
#define included_nsh_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_nsh_printfun
#define included_nsh_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "nsh.api_tojson.h"
#include "nsh.api_fromjson.h"

static inline u8 *vl_api_nsh_add_del_entry_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_add_del_entry_t *a = va_arg (*args, vl_api_nsh_add_del_entry_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_add_del_entry_t: */
    s = format(s, "vl_api_nsh_add_del_entry_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Unsp_nsi: %u", format_white_space, indent, a->nsp_nsi);
    s = format(s, "\n%Umd_type: %u", format_white_space, indent, a->md_type);
    s = format(s, "\n%Uver_o_c: %u", format_white_space, indent, a->ver_o_c);
    s = format(s, "\n%Uttl: %u", format_white_space, indent, a->ttl);
    s = format(s, "\n%Ulength: %u", format_white_space, indent, a->length);
    s = format(s, "\n%Unext_protocol: %u", format_white_space, indent, a->next_protocol);
    s = format(s, "\n%Uc1: %u", format_white_space, indent, a->c1);
    s = format(s, "\n%Uc2: %u", format_white_space, indent, a->c2);
    s = format(s, "\n%Uc3: %u", format_white_space, indent, a->c3);
    s = format(s, "\n%Uc4: %u", format_white_space, indent, a->c4);
    s = format(s, "\n%Utlv_length: %u", format_white_space, indent, a->tlv_length);
    s = format(s, "\n%Utlv: %U", format_white_space, indent, format_hex_bytes, a, 248);
    return s;
}

static inline u8 *vl_api_nsh_add_del_entry_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_add_del_entry_reply_t *a = va_arg (*args, vl_api_nsh_add_del_entry_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_add_del_entry_reply_t: */
    s = format(s, "vl_api_nsh_add_del_entry_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Uentry_index: %u", format_white_space, indent, a->entry_index);
    return s;
}

static inline u8 *vl_api_nsh_entry_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_entry_dump_t *a = va_arg (*args, vl_api_nsh_entry_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_entry_dump_t: */
    s = format(s, "vl_api_nsh_entry_dump_t:");
    s = format(s, "\n%Uentry_index: %u", format_white_space, indent, a->entry_index);
    return s;
}

static inline u8 *vl_api_nsh_entry_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_entry_details_t *a = va_arg (*args, vl_api_nsh_entry_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_entry_details_t: */
    s = format(s, "vl_api_nsh_entry_details_t:");
    s = format(s, "\n%Uentry_index: %u", format_white_space, indent, a->entry_index);
    s = format(s, "\n%Unsp_nsi: %u", format_white_space, indent, a->nsp_nsi);
    s = format(s, "\n%Umd_type: %u", format_white_space, indent, a->md_type);
    s = format(s, "\n%Uver_o_c: %u", format_white_space, indent, a->ver_o_c);
    s = format(s, "\n%Uttl: %u", format_white_space, indent, a->ttl);
    s = format(s, "\n%Ulength: %u", format_white_space, indent, a->length);
    s = format(s, "\n%Unext_protocol: %u", format_white_space, indent, a->next_protocol);
    s = format(s, "\n%Uc1: %u", format_white_space, indent, a->c1);
    s = format(s, "\n%Uc2: %u", format_white_space, indent, a->c2);
    s = format(s, "\n%Uc3: %u", format_white_space, indent, a->c3);
    s = format(s, "\n%Uc4: %u", format_white_space, indent, a->c4);
    s = format(s, "\n%Utlv_length: %u", format_white_space, indent, a->tlv_length);
    s = format(s, "\n%Utlv: %U", format_white_space, indent, format_hex_bytes, a, 248);
    return s;
}

static inline u8 *vl_api_nsh_add_del_map_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_add_del_map_t *a = va_arg (*args, vl_api_nsh_add_del_map_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_add_del_map_t: */
    s = format(s, "vl_api_nsh_add_del_map_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Unsp_nsi: %u", format_white_space, indent, a->nsp_nsi);
    s = format(s, "\n%Umapped_nsp_nsi: %u", format_white_space, indent, a->mapped_nsp_nsi);
    s = format(s, "\n%Unsh_action: %u", format_white_space, indent, a->nsh_action);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Urx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->rx_sw_if_index, indent);
    s = format(s, "\n%Unext_node: %u", format_white_space, indent, a->next_node);
    return s;
}

static inline u8 *vl_api_nsh_add_del_map_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_add_del_map_reply_t *a = va_arg (*args, vl_api_nsh_add_del_map_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_add_del_map_reply_t: */
    s = format(s, "vl_api_nsh_add_del_map_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Umap_index: %u", format_white_space, indent, a->map_index);
    return s;
}

static inline u8 *vl_api_nsh_map_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_map_dump_t *a = va_arg (*args, vl_api_nsh_map_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_map_dump_t: */
    s = format(s, "vl_api_nsh_map_dump_t:");
    s = format(s, "\n%Umap_index: %u", format_white_space, indent, a->map_index);
    return s;
}

static inline u8 *vl_api_nsh_map_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_nsh_map_details_t *a = va_arg (*args, vl_api_nsh_map_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_nsh_map_details_t: */
    s = format(s, "vl_api_nsh_map_details_t:");
    s = format(s, "\n%Umap_index: %u", format_white_space, indent, a->map_index);
    s = format(s, "\n%Unsp_nsi: %u", format_white_space, indent, a->nsp_nsi);
    s = format(s, "\n%Umapped_nsp_nsi: %u", format_white_space, indent, a->mapped_nsp_nsi);
    s = format(s, "\n%Unsh_action: %u", format_white_space, indent, a->nsh_action);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Urx_sw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->rx_sw_if_index, indent);
    s = format(s, "\n%Unext_node: %u", format_white_space, indent, a->next_node);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_nsh_endianfun
#define included_nsh_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_nsh_add_del_entry_t_endian (vl_api_nsh_add_del_entry_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->nsp_nsi = clib_net_to_host_u32(a->nsp_nsi);
    /* a->md_type = a->md_type (no-op) */
    /* a->ver_o_c = a->ver_o_c (no-op) */
    /* a->ttl = a->ttl (no-op) */
    /* a->length = a->length (no-op) */
    /* a->next_protocol = a->next_protocol (no-op) */
    a->c1 = clib_net_to_host_u32(a->c1);
    a->c2 = clib_net_to_host_u32(a->c2);
    a->c3 = clib_net_to_host_u32(a->c3);
    a->c4 = clib_net_to_host_u32(a->c4);
    /* a->tlv_length = a->tlv_length (no-op) */
    /* a->tlv = a->tlv (no-op) */
}

static inline void vl_api_nsh_add_del_entry_reply_t_endian (vl_api_nsh_add_del_entry_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->entry_index = clib_net_to_host_u32(a->entry_index);
}

static inline void vl_api_nsh_entry_dump_t_endian (vl_api_nsh_entry_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->entry_index = clib_net_to_host_u32(a->entry_index);
}

static inline void vl_api_nsh_entry_details_t_endian (vl_api_nsh_entry_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->entry_index = clib_net_to_host_u32(a->entry_index);
    a->nsp_nsi = clib_net_to_host_u32(a->nsp_nsi);
    /* a->md_type = a->md_type (no-op) */
    /* a->ver_o_c = a->ver_o_c (no-op) */
    /* a->ttl = a->ttl (no-op) */
    /* a->length = a->length (no-op) */
    /* a->next_protocol = a->next_protocol (no-op) */
    a->c1 = clib_net_to_host_u32(a->c1);
    a->c2 = clib_net_to_host_u32(a->c2);
    a->c3 = clib_net_to_host_u32(a->c3);
    a->c4 = clib_net_to_host_u32(a->c4);
    /* a->tlv_length = a->tlv_length (no-op) */
    /* a->tlv = a->tlv (no-op) */
}

static inline void vl_api_nsh_add_del_map_t_endian (vl_api_nsh_add_del_map_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->nsp_nsi = clib_net_to_host_u32(a->nsp_nsi);
    a->mapped_nsp_nsi = clib_net_to_host_u32(a->mapped_nsp_nsi);
    a->nsh_action = clib_net_to_host_u32(a->nsh_action);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->rx_sw_if_index, to_net);
    a->next_node = clib_net_to_host_u32(a->next_node);
}

static inline void vl_api_nsh_add_del_map_reply_t_endian (vl_api_nsh_add_del_map_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->map_index = clib_net_to_host_u32(a->map_index);
}

static inline void vl_api_nsh_map_dump_t_endian (vl_api_nsh_map_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->map_index = clib_net_to_host_u32(a->map_index);
}

static inline void vl_api_nsh_map_details_t_endian (vl_api_nsh_map_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->map_index = clib_net_to_host_u32(a->map_index);
    a->nsp_nsi = clib_net_to_host_u32(a->nsp_nsi);
    a->mapped_nsp_nsi = clib_net_to_host_u32(a->mapped_nsp_nsi);
    a->nsh_action = clib_net_to_host_u32(a->nsh_action);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_interface_index_t_endian(&a->rx_sw_if_index, to_net);
    a->next_node = clib_net_to_host_u32(a->next_node);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_nsh_calcsizefun
#define included_nsh_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_add_del_entry_t_calc_size (vl_api_nsh_add_del_entry_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_add_del_entry_reply_t_calc_size (vl_api_nsh_add_del_entry_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_entry_dump_t_calc_size (vl_api_nsh_entry_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_entry_details_t_calc_size (vl_api_nsh_entry_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_add_del_map_t_calc_size (vl_api_nsh_add_del_map_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->rx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->rx_sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_add_del_map_reply_t_calc_size (vl_api_nsh_add_del_map_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_map_dump_t_calc_size (vl_api_nsh_map_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_nsh_map_details_t_calc_size (vl_api_nsh_map_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->rx_sw_if_index) + vl_api_interface_index_t_calc_size(&a->rx_sw_if_index);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(nsh.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(nsh.api, 0x2d586141)

#endif

