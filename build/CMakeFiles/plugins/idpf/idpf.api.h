/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: idpf.api
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
#warning no content included from idpf.api
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
vl_msg_id(VL_API_IDPF_CREATE, vl_api_idpf_create_t_handler)
vl_msg_id(VL_API_IDPF_CREATE_REPLY, vl_api_idpf_create_reply_t_handler)
vl_msg_id(VL_API_IDPF_DELETE, vl_api_idpf_delete_t_handler)
vl_msg_id(VL_API_IDPF_DELETE_REPLY, vl_api_idpf_delete_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_idpf_create_t, 1)
vl_msg_name(vl_api_idpf_create_reply_t, 1)
vl_msg_name(vl_api_idpf_delete_t, 1)
vl_msg_name(vl_api_idpf_delete_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_idpf \
_(VL_API_IDPF_CREATE, idpf_create, 2ba86d91) \
_(VL_API_IDPF_CREATE_REPLY, idpf_create_reply, 5383d31f) \
_(VL_API_IDPF_DELETE, idpf_delete, f9e6675e) \
_(VL_API_IDPF_DELETE_REPLY, idpf_delete_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "idpf.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_idpf_printfun_types
#define included_idpf_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_idpf_printfun
#define included_idpf_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "idpf.api_tojson.h"
#include "idpf.api_fromjson.h"

static inline u8 *vl_api_idpf_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_idpf_create_t *a = va_arg (*args, vl_api_idpf_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_idpf_create_t: */
    s = format(s, "vl_api_idpf_create_t:");
    s = format(s, "\n%Upci_addr: %u", format_white_space, indent, a->pci_addr);
    s = format(s, "\n%Urxq_single: %u", format_white_space, indent, a->rxq_single);
    s = format(s, "\n%Utxq_single: %u", format_white_space, indent, a->txq_single);
    s = format(s, "\n%Urxq_num: %u", format_white_space, indent, a->rxq_num);
    s = format(s, "\n%Utxq_num: %u", format_white_space, indent, a->txq_num);
    s = format(s, "\n%Urxq_size: %u", format_white_space, indent, a->rxq_size);
    s = format(s, "\n%Utxq_size: %u", format_white_space, indent, a->txq_size);
    s = format(s, "\n%Ureq_vport_nb: %u", format_white_space, indent, a->req_vport_nb);
    return s;
}

static inline u8 *vl_api_idpf_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_idpf_create_reply_t *a = va_arg (*args, vl_api_idpf_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_idpf_create_reply_t: */
    s = format(s, "vl_api_idpf_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_idpf_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_idpf_delete_t *a = va_arg (*args, vl_api_idpf_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_idpf_delete_t: */
    s = format(s, "vl_api_idpf_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_idpf_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_idpf_delete_reply_t *a = va_arg (*args, vl_api_idpf_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_idpf_delete_reply_t: */
    s = format(s, "vl_api_idpf_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_idpf_endianfun
#define included_idpf_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_idpf_create_t_endian (vl_api_idpf_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->pci_addr = clib_net_to_host_u32(a->pci_addr);
    a->rxq_single = clib_net_to_host_u16(a->rxq_single);
    a->txq_single = clib_net_to_host_u16(a->txq_single);
    a->rxq_num = clib_net_to_host_u16(a->rxq_num);
    a->txq_num = clib_net_to_host_u16(a->txq_num);
    a->rxq_size = clib_net_to_host_u16(a->rxq_size);
    a->txq_size = clib_net_to_host_u16(a->txq_size);
    a->req_vport_nb = clib_net_to_host_u16(a->req_vport_nb);
}

static inline void vl_api_idpf_create_reply_t_endian (vl_api_idpf_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_idpf_delete_t_endian (vl_api_idpf_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_idpf_delete_reply_t_endian (vl_api_idpf_delete_reply_t *a, bool to_net)
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
#ifndef included_idpf_calcsizefun
#define included_idpf_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_idpf_create_t_calc_size (vl_api_idpf_create_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_idpf_create_reply_t_calc_size (vl_api_idpf_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_idpf_delete_t_calc_size (vl_api_idpf_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_idpf_delete_reply_t_calc_size (vl_api_idpf_delete_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(idpf.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(idpf.api, 0x7bc56cb6)

#endif

