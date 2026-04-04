/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: l2tp.api
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
#warning no content included from l2tp.api
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
#include <vnet/ethernet/ethernet_types.api.h>
#include <vnet/ip/ip_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_L2TPV3_CREATE_TUNNEL, vl_api_l2tpv3_create_tunnel_t_handler)
vl_msg_id(VL_API_L2TPV3_CREATE_TUNNEL_REPLY, vl_api_l2tpv3_create_tunnel_reply_t_handler)
vl_msg_id(VL_API_L2TPV3_SET_TUNNEL_COOKIES, vl_api_l2tpv3_set_tunnel_cookies_t_handler)
vl_msg_id(VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY, vl_api_l2tpv3_set_tunnel_cookies_reply_t_handler)
vl_msg_id(VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS, vl_api_sw_if_l2tpv3_tunnel_details_t_handler)
vl_msg_id(VL_API_SW_IF_L2TPV3_TUNNEL_DUMP, vl_api_sw_if_l2tpv3_tunnel_dump_t_handler)
vl_msg_id(VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE, vl_api_l2tpv3_interface_enable_disable_t_handler)
vl_msg_id(VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY, vl_api_l2tpv3_interface_enable_disable_reply_t_handler)
vl_msg_id(VL_API_L2TPV3_SET_LOOKUP_KEY, vl_api_l2tpv3_set_lookup_key_t_handler)
vl_msg_id(VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY, vl_api_l2tpv3_set_lookup_key_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_l2tpv3_create_tunnel_t, 1)
vl_msg_name(vl_api_l2tpv3_create_tunnel_reply_t, 1)
vl_msg_name(vl_api_l2tpv3_set_tunnel_cookies_t, 1)
vl_msg_name(vl_api_l2tpv3_set_tunnel_cookies_reply_t, 1)
vl_msg_name(vl_api_sw_if_l2tpv3_tunnel_details_t, 1)
vl_msg_name(vl_api_sw_if_l2tpv3_tunnel_dump_t, 1)
vl_msg_name(vl_api_l2tpv3_interface_enable_disable_t, 1)
vl_msg_name(vl_api_l2tpv3_interface_enable_disable_reply_t, 1)
vl_msg_name(vl_api_l2tpv3_set_lookup_key_t, 1)
vl_msg_name(vl_api_l2tpv3_set_lookup_key_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_l2tp \
_(VL_API_L2TPV3_CREATE_TUNNEL, l2tpv3_create_tunnel, 15bed0c2) \
_(VL_API_L2TPV3_CREATE_TUNNEL_REPLY, l2tpv3_create_tunnel_reply, 5383d31f) \
_(VL_API_L2TPV3_SET_TUNNEL_COOKIES, l2tpv3_set_tunnel_cookies, b3f4faf7) \
_(VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY, l2tpv3_set_tunnel_cookies_reply, e8d4e804) \
_(VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS, sw_if_l2tpv3_tunnel_details, 50b88993) \
_(VL_API_SW_IF_L2TPV3_TUNNEL_DUMP, sw_if_l2tpv3_tunnel_dump, 51077d14) \
_(VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE, l2tpv3_interface_enable_disable, 3865946c) \
_(VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY, l2tpv3_interface_enable_disable_reply, e8d4e804) \
_(VL_API_L2TPV3_SET_LOOKUP_KEY, l2tpv3_set_lookup_key, c9892c86) \
_(VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY, l2tpv3_set_lookup_key_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "l2tp.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_l2tp_printfun_types
#define included_l2tp_printfun_types

static inline u8 *format_vl_api_l2t_lookup_key_t (u8 *s, va_list * args)
{
    vl_api_l2t_lookup_key_t *a = va_arg (*args, vl_api_l2t_lookup_key_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "L2T_LOOKUP_KEY_API_SRC_ADDR");
    case 1:
        return format(s, "L2T_LOOKUP_KEY_API_DST_ADDR");
    case 2:
        return format(s, "L2T_LOOKUP_KEY_API_SESSION_ID");
    }
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_l2tp_printfun
#define included_l2tp_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "l2tp.api_tojson.h"
#include "l2tp.api_fromjson.h"

static inline u8 *vl_api_l2tpv3_create_tunnel_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_create_tunnel_t *a = va_arg (*args, vl_api_l2tpv3_create_tunnel_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_create_tunnel_t: */
    s = format(s, "vl_api_l2tpv3_create_tunnel_t:");
    s = format(s, "\n%Uclient_address: %U", format_white_space, indent, format_vl_api_address_t, &a->client_address, indent);
    s = format(s, "\n%Uour_address: %U", format_white_space, indent, format_vl_api_address_t, &a->our_address, indent);
    s = format(s, "\n%Ulocal_session_id: %u", format_white_space, indent, a->local_session_id);
    s = format(s, "\n%Uremote_session_id: %u", format_white_space, indent, a->remote_session_id);
    s = format(s, "\n%Ulocal_cookie: %llu", format_white_space, indent, a->local_cookie);
    s = format(s, "\n%Uremote_cookie: %llu", format_white_space, indent, a->remote_cookie);
    s = format(s, "\n%Ul2_sublayer_present: %u", format_white_space, indent, a->l2_sublayer_present);
    s = format(s, "\n%Uencap_vrf_id: %u", format_white_space, indent, a->encap_vrf_id);
    return s;
}

static inline u8 *vl_api_l2tpv3_create_tunnel_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_create_tunnel_reply_t *a = va_arg (*args, vl_api_l2tpv3_create_tunnel_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_create_tunnel_reply_t: */
    s = format(s, "vl_api_l2tpv3_create_tunnel_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_l2tpv3_set_tunnel_cookies_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_set_tunnel_cookies_t *a = va_arg (*args, vl_api_l2tpv3_set_tunnel_cookies_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_set_tunnel_cookies_t: */
    s = format(s, "vl_api_l2tpv3_set_tunnel_cookies_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Unew_local_cookie: %llu", format_white_space, indent, a->new_local_cookie);
    s = format(s, "\n%Unew_remote_cookie: %llu", format_white_space, indent, a->new_remote_cookie);
    return s;
}

static inline u8 *vl_api_l2tpv3_set_tunnel_cookies_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_set_tunnel_cookies_reply_t *a = va_arg (*args, vl_api_l2tpv3_set_tunnel_cookies_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_set_tunnel_cookies_reply_t: */
    s = format(s, "vl_api_l2tpv3_set_tunnel_cookies_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_if_l2tpv3_tunnel_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_if_l2tpv3_tunnel_details_t *a = va_arg (*args, vl_api_sw_if_l2tpv3_tunnel_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_if_l2tpv3_tunnel_details_t: */
    s = format(s, "vl_api_sw_if_l2tpv3_tunnel_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uinterface_name: %s", format_white_space, indent, a->interface_name);
    s = format(s, "\n%Uclient_address: %U", format_white_space, indent, format_vl_api_address_t, &a->client_address, indent);
    s = format(s, "\n%Uour_address: %U", format_white_space, indent, format_vl_api_address_t, &a->our_address, indent);
    s = format(s, "\n%Ulocal_session_id: %u", format_white_space, indent, a->local_session_id);
    s = format(s, "\n%Uremote_session_id: %u", format_white_space, indent, a->remote_session_id);
    for (i = 0; i < 2; i++) {
        s = format(s, "\n%Ulocal_cookie: %llu",
                   format_white_space, indent, a->local_cookie[i]);
    }
    s = format(s, "\n%Uremote_cookie: %llu", format_white_space, indent, a->remote_cookie);
    s = format(s, "\n%Ul2_sublayer_present: %u", format_white_space, indent, a->l2_sublayer_present);
    return s;
}

static inline u8 *vl_api_sw_if_l2tpv3_tunnel_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_if_l2tpv3_tunnel_dump_t *a = va_arg (*args, vl_api_sw_if_l2tpv3_tunnel_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_if_l2tpv3_tunnel_dump_t: */
    s = format(s, "vl_api_sw_if_l2tpv3_tunnel_dump_t:");
    return s;
}

static inline u8 *vl_api_l2tpv3_interface_enable_disable_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_interface_enable_disable_t *a = va_arg (*args, vl_api_l2tpv3_interface_enable_disable_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_interface_enable_disable_t: */
    s = format(s, "vl_api_l2tpv3_interface_enable_disable_t:");
    s = format(s, "\n%Uenable_disable: %u", format_white_space, indent, a->enable_disable);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_l2tpv3_interface_enable_disable_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_interface_enable_disable_reply_t *a = va_arg (*args, vl_api_l2tpv3_interface_enable_disable_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_interface_enable_disable_reply_t: */
    s = format(s, "vl_api_l2tpv3_interface_enable_disable_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_l2tpv3_set_lookup_key_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_set_lookup_key_t *a = va_arg (*args, vl_api_l2tpv3_set_lookup_key_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_set_lookup_key_t: */
    s = format(s, "vl_api_l2tpv3_set_lookup_key_t:");
    s = format(s, "\n%Ukey: %U", format_white_space, indent, format_vl_api_l2t_lookup_key_t, &a->key, indent);
    return s;
}

static inline u8 *vl_api_l2tpv3_set_lookup_key_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_l2tpv3_set_lookup_key_reply_t *a = va_arg (*args, vl_api_l2tpv3_set_lookup_key_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_l2tpv3_set_lookup_key_reply_t: */
    s = format(s, "vl_api_l2tpv3_set_lookup_key_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_l2tp_endianfun
#define included_l2tp_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_l2t_lookup_key_t_endian (vl_api_l2t_lookup_key_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->l2t_lookup_key = a->l2t_lookup_key (no-op) */
}

static inline void vl_api_l2tpv3_create_tunnel_t_endian (vl_api_l2tpv3_create_tunnel_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_address_t_endian(&a->client_address, to_net);
    vl_api_address_t_endian(&a->our_address, to_net);
    a->local_session_id = clib_net_to_host_u32(a->local_session_id);
    a->remote_session_id = clib_net_to_host_u32(a->remote_session_id);
    a->local_cookie = clib_net_to_host_u64(a->local_cookie);
    a->remote_cookie = clib_net_to_host_u64(a->remote_cookie);
    /* a->l2_sublayer_present = a->l2_sublayer_present (no-op) */
    a->encap_vrf_id = clib_net_to_host_u32(a->encap_vrf_id);
}

static inline void vl_api_l2tpv3_create_tunnel_reply_t_endian (vl_api_l2tpv3_create_tunnel_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_l2tpv3_set_tunnel_cookies_t_endian (vl_api_l2tpv3_set_tunnel_cookies_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->new_local_cookie = clib_net_to_host_u64(a->new_local_cookie);
    a->new_remote_cookie = clib_net_to_host_u64(a->new_remote_cookie);
}

static inline void vl_api_l2tpv3_set_tunnel_cookies_reply_t_endian (vl_api_l2tpv3_set_tunnel_cookies_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_if_l2tpv3_tunnel_details_t_endian (vl_api_sw_if_l2tpv3_tunnel_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->interface_name = a->interface_name (no-op) */
    vl_api_address_t_endian(&a->client_address, to_net);
    vl_api_address_t_endian(&a->our_address, to_net);
    a->local_session_id = clib_net_to_host_u32(a->local_session_id);
    a->remote_session_id = clib_net_to_host_u32(a->remote_session_id);
    ASSERT((u32)2 <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < 2; i++) {
        a->local_cookie[i] = clib_net_to_host_u64(a->local_cookie[i]);
    }
    a->remote_cookie = clib_net_to_host_u64(a->remote_cookie);
    /* a->l2_sublayer_present = a->l2_sublayer_present (no-op) */
}

static inline void vl_api_sw_if_l2tpv3_tunnel_dump_t_endian (vl_api_sw_if_l2tpv3_tunnel_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_l2tpv3_interface_enable_disable_t_endian (vl_api_l2tpv3_interface_enable_disable_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->enable_disable = a->enable_disable (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_l2tpv3_interface_enable_disable_reply_t_endian (vl_api_l2tpv3_interface_enable_disable_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_l2tpv3_set_lookup_key_t_endian (vl_api_l2tpv3_set_lookup_key_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_l2t_lookup_key_t_endian(&a->key, to_net);
}

static inline void vl_api_l2tpv3_set_lookup_key_reply_t_endian (vl_api_l2tpv3_set_lookup_key_reply_t *a, bool to_net)
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
#ifndef included_l2tp_calcsizefun
#define included_l2tp_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_l2t_lookup_key_t_calc_size (vl_api_l2t_lookup_key_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_create_tunnel_t_calc_size (vl_api_l2tpv3_create_tunnel_t *a)
{
      return sizeof(*a) - sizeof(a->client_address) + vl_api_address_t_calc_size(&a->client_address) - sizeof(a->our_address) + vl_api_address_t_calc_size(&a->our_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_create_tunnel_reply_t_calc_size (vl_api_l2tpv3_create_tunnel_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_set_tunnel_cookies_t_calc_size (vl_api_l2tpv3_set_tunnel_cookies_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_set_tunnel_cookies_reply_t_calc_size (vl_api_l2tpv3_set_tunnel_cookies_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_if_l2tpv3_tunnel_details_t_calc_size (vl_api_sw_if_l2tpv3_tunnel_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->client_address) + vl_api_address_t_calc_size(&a->client_address) - sizeof(a->our_address) + vl_api_address_t_calc_size(&a->our_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_if_l2tpv3_tunnel_dump_t_calc_size (vl_api_sw_if_l2tpv3_tunnel_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_interface_enable_disable_t_calc_size (vl_api_l2tpv3_interface_enable_disable_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_interface_enable_disable_reply_t_calc_size (vl_api_l2tpv3_interface_enable_disable_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_set_lookup_key_t_calc_size (vl_api_l2tpv3_set_lookup_key_t *a)
{
      return sizeof(*a) - sizeof(a->key) + vl_api_l2t_lookup_key_t_calc_size(&a->key);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_l2tpv3_set_lookup_key_reply_t_calc_size (vl_api_l2tpv3_set_lookup_key_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(l2tp.api, 2, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(l2tp.api, 0xf73ff6b9)

#endif

