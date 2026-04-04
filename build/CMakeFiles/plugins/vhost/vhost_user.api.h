/*
 * VLIB API definitions 2026-04-04 08:32:00
 * Input file: vhost_user.api
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
#warning no content included from vhost_user.api
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
#include <vnet/devices/virtio/virtio_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_CREATE_VHOST_USER_IF, vl_api_create_vhost_user_if_t_handler)
vl_msg_id(VL_API_CREATE_VHOST_USER_IF_REPLY, vl_api_create_vhost_user_if_reply_t_handler)
vl_msg_id(VL_API_MODIFY_VHOST_USER_IF, vl_api_modify_vhost_user_if_t_handler)
vl_msg_id(VL_API_MODIFY_VHOST_USER_IF_REPLY, vl_api_modify_vhost_user_if_reply_t_handler)
vl_msg_id(VL_API_CREATE_VHOST_USER_IF_V2, vl_api_create_vhost_user_if_v2_t_handler)
vl_msg_id(VL_API_CREATE_VHOST_USER_IF_V2_REPLY, vl_api_create_vhost_user_if_v2_reply_t_handler)
vl_msg_id(VL_API_MODIFY_VHOST_USER_IF_V2, vl_api_modify_vhost_user_if_v2_t_handler)
vl_msg_id(VL_API_MODIFY_VHOST_USER_IF_V2_REPLY, vl_api_modify_vhost_user_if_v2_reply_t_handler)
vl_msg_id(VL_API_DELETE_VHOST_USER_IF, vl_api_delete_vhost_user_if_t_handler)
vl_msg_id(VL_API_DELETE_VHOST_USER_IF_REPLY, vl_api_delete_vhost_user_if_reply_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_VHOST_USER_DETAILS, vl_api_sw_interface_vhost_user_details_t_handler)
vl_msg_id(VL_API_SW_INTERFACE_VHOST_USER_DUMP, vl_api_sw_interface_vhost_user_dump_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_create_vhost_user_if_t, 1)
vl_msg_name(vl_api_create_vhost_user_if_reply_t, 1)
vl_msg_name(vl_api_modify_vhost_user_if_t, 1)
vl_msg_name(vl_api_modify_vhost_user_if_reply_t, 1)
vl_msg_name(vl_api_create_vhost_user_if_v2_t, 1)
vl_msg_name(vl_api_create_vhost_user_if_v2_reply_t, 1)
vl_msg_name(vl_api_modify_vhost_user_if_v2_t, 1)
vl_msg_name(vl_api_modify_vhost_user_if_v2_reply_t, 1)
vl_msg_name(vl_api_delete_vhost_user_if_t, 1)
vl_msg_name(vl_api_delete_vhost_user_if_reply_t, 1)
vl_msg_name(vl_api_sw_interface_vhost_user_details_t, 1)
vl_msg_name(vl_api_sw_interface_vhost_user_dump_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_vhost_user \
_(VL_API_CREATE_VHOST_USER_IF, create_vhost_user_if, c785c6fc) \
_(VL_API_CREATE_VHOST_USER_IF_REPLY, create_vhost_user_if_reply, 5383d31f) \
_(VL_API_MODIFY_VHOST_USER_IF, modify_vhost_user_if, 0e71d40b) \
_(VL_API_MODIFY_VHOST_USER_IF_REPLY, modify_vhost_user_if_reply, e8d4e804) \
_(VL_API_CREATE_VHOST_USER_IF_V2, create_vhost_user_if_v2, dba1cc1d) \
_(VL_API_CREATE_VHOST_USER_IF_V2_REPLY, create_vhost_user_if_v2_reply, 5383d31f) \
_(VL_API_MODIFY_VHOST_USER_IF_V2, modify_vhost_user_if_v2, b2483771) \
_(VL_API_MODIFY_VHOST_USER_IF_V2_REPLY, modify_vhost_user_if_v2_reply, e8d4e804) \
_(VL_API_DELETE_VHOST_USER_IF, delete_vhost_user_if, f9e6675e) \
_(VL_API_DELETE_VHOST_USER_IF_REPLY, delete_vhost_user_if_reply, e8d4e804) \
_(VL_API_SW_INTERFACE_VHOST_USER_DETAILS, sw_interface_vhost_user_details, 0cee1e53) \
_(VL_API_SW_INTERFACE_VHOST_USER_DUMP, sw_interface_vhost_user_dump, f9e6675e) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "vhost_user.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vhost_user_printfun_types
#define included_vhost_user_printfun_types


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_vhost_user_printfun
#define included_vhost_user_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "vhost_user.api_tojson.h"
#include "vhost_user.api_fromjson.h"

static inline u8 *vl_api_create_vhost_user_if_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_create_vhost_user_if_t *a = va_arg (*args, vl_api_create_vhost_user_if_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_create_vhost_user_if_t: */
    s = format(s, "vl_api_create_vhost_user_if_t:");
    s = format(s, "\n%Uis_server: %u", format_white_space, indent, a->is_server);
    s = format(s, "\n%Usock_filename: %s", format_white_space, indent, a->sock_filename);
    s = format(s, "\n%Urenumber: %u", format_white_space, indent, a->renumber);
    s = format(s, "\n%Udisable_mrg_rxbuf: %u", format_white_space, indent, a->disable_mrg_rxbuf);
    s = format(s, "\n%Udisable_indirect_desc: %u", format_white_space, indent, a->disable_indirect_desc);
    s = format(s, "\n%Uenable_gso: %u", format_white_space, indent, a->enable_gso);
    s = format(s, "\n%Uenable_packed: %u", format_white_space, indent, a->enable_packed);
    s = format(s, "\n%Ucustom_dev_instance: %u", format_white_space, indent, a->custom_dev_instance);
    s = format(s, "\n%Uuse_custom_mac: %u", format_white_space, indent, a->use_custom_mac);
    s = format(s, "\n%Umac_address: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_address, indent);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_create_vhost_user_if_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_create_vhost_user_if_reply_t *a = va_arg (*args, vl_api_create_vhost_user_if_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_create_vhost_user_if_reply_t: */
    s = format(s, "vl_api_create_vhost_user_if_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_modify_vhost_user_if_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_modify_vhost_user_if_t *a = va_arg (*args, vl_api_modify_vhost_user_if_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_modify_vhost_user_if_t: */
    s = format(s, "vl_api_modify_vhost_user_if_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_server: %u", format_white_space, indent, a->is_server);
    s = format(s, "\n%Usock_filename: %s", format_white_space, indent, a->sock_filename);
    s = format(s, "\n%Urenumber: %u", format_white_space, indent, a->renumber);
    s = format(s, "\n%Uenable_gso: %u", format_white_space, indent, a->enable_gso);
    s = format(s, "\n%Uenable_packed: %u", format_white_space, indent, a->enable_packed);
    s = format(s, "\n%Ucustom_dev_instance: %u", format_white_space, indent, a->custom_dev_instance);
    return s;
}

static inline u8 *vl_api_modify_vhost_user_if_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_modify_vhost_user_if_reply_t *a = va_arg (*args, vl_api_modify_vhost_user_if_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_modify_vhost_user_if_reply_t: */
    s = format(s, "vl_api_modify_vhost_user_if_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_create_vhost_user_if_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_create_vhost_user_if_v2_t *a = va_arg (*args, vl_api_create_vhost_user_if_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_create_vhost_user_if_v2_t: */
    s = format(s, "vl_api_create_vhost_user_if_v2_t:");
    s = format(s, "\n%Uis_server: %u", format_white_space, indent, a->is_server);
    s = format(s, "\n%Usock_filename: %s", format_white_space, indent, a->sock_filename);
    s = format(s, "\n%Urenumber: %u", format_white_space, indent, a->renumber);
    s = format(s, "\n%Udisable_mrg_rxbuf: %u", format_white_space, indent, a->disable_mrg_rxbuf);
    s = format(s, "\n%Udisable_indirect_desc: %u", format_white_space, indent, a->disable_indirect_desc);
    s = format(s, "\n%Uenable_gso: %u", format_white_space, indent, a->enable_gso);
    s = format(s, "\n%Uenable_packed: %u", format_white_space, indent, a->enable_packed);
    s = format(s, "\n%Uenable_event_idx: %u", format_white_space, indent, a->enable_event_idx);
    s = format(s, "\n%Ucustom_dev_instance: %u", format_white_space, indent, a->custom_dev_instance);
    s = format(s, "\n%Uuse_custom_mac: %u", format_white_space, indent, a->use_custom_mac);
    s = format(s, "\n%Umac_address: %U", format_white_space, indent, format_vl_api_mac_address_t, &a->mac_address, indent);
    s = format(s, "\n%Utag: %s", format_white_space, indent, a->tag);
    return s;
}

static inline u8 *vl_api_create_vhost_user_if_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_create_vhost_user_if_v2_reply_t *a = va_arg (*args, vl_api_create_vhost_user_if_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_create_vhost_user_if_v2_reply_t: */
    s = format(s, "vl_api_create_vhost_user_if_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_modify_vhost_user_if_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_modify_vhost_user_if_v2_t *a = va_arg (*args, vl_api_modify_vhost_user_if_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_modify_vhost_user_if_v2_t: */
    s = format(s, "vl_api_modify_vhost_user_if_v2_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uis_server: %u", format_white_space, indent, a->is_server);
    s = format(s, "\n%Usock_filename: %s", format_white_space, indent, a->sock_filename);
    s = format(s, "\n%Urenumber: %u", format_white_space, indent, a->renumber);
    s = format(s, "\n%Uenable_gso: %u", format_white_space, indent, a->enable_gso);
    s = format(s, "\n%Uenable_packed: %u", format_white_space, indent, a->enable_packed);
    s = format(s, "\n%Uenable_event_idx: %u", format_white_space, indent, a->enable_event_idx);
    s = format(s, "\n%Ucustom_dev_instance: %u", format_white_space, indent, a->custom_dev_instance);
    return s;
}

static inline u8 *vl_api_modify_vhost_user_if_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_modify_vhost_user_if_v2_reply_t *a = va_arg (*args, vl_api_modify_vhost_user_if_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_modify_vhost_user_if_v2_reply_t: */
    s = format(s, "vl_api_modify_vhost_user_if_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_delete_vhost_user_if_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_delete_vhost_user_if_t *a = va_arg (*args, vl_api_delete_vhost_user_if_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_delete_vhost_user_if_t: */
    s = format(s, "vl_api_delete_vhost_user_if_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_delete_vhost_user_if_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_delete_vhost_user_if_reply_t *a = va_arg (*args, vl_api_delete_vhost_user_if_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_delete_vhost_user_if_reply_t: */
    s = format(s, "vl_api_delete_vhost_user_if_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_sw_interface_vhost_user_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_vhost_user_details_t *a = va_arg (*args, vl_api_sw_interface_vhost_user_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_vhost_user_details_t: */
    s = format(s, "vl_api_sw_interface_vhost_user_details_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uinterface_name: %s", format_white_space, indent, a->interface_name);
    s = format(s, "\n%Uvirtio_net_hdr_sz: %u", format_white_space, indent, a->virtio_net_hdr_sz);
    s = format(s, "\n%Ufeatures_first_32: %U", format_white_space, indent, format_vl_api_virtio_net_features_first_32_t, &a->features_first_32, indent);
    s = format(s, "\n%Ufeatures_last_32: %U", format_white_space, indent, format_vl_api_virtio_net_features_last_32_t, &a->features_last_32, indent);
    s = format(s, "\n%Uis_server: %u", format_white_space, indent, a->is_server);
    s = format(s, "\n%Usock_filename: %s", format_white_space, indent, a->sock_filename);
    s = format(s, "\n%Unum_regions: %u", format_white_space, indent, a->num_regions);
    s = format(s, "\n%Usock_errno: %ld", format_white_space, indent, a->sock_errno);
    return s;
}

static inline u8 *vl_api_sw_interface_vhost_user_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_sw_interface_vhost_user_dump_t *a = va_arg (*args, vl_api_sw_interface_vhost_user_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_sw_interface_vhost_user_dump_t: */
    s = format(s, "vl_api_sw_interface_vhost_user_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_vhost_user_endianfun
#define included_vhost_user_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_create_vhost_user_if_t_endian (vl_api_create_vhost_user_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_server = a->is_server (no-op) */
    /* a->sock_filename = a->sock_filename (no-op) */
    /* a->renumber = a->renumber (no-op) */
    /* a->disable_mrg_rxbuf = a->disable_mrg_rxbuf (no-op) */
    /* a->disable_indirect_desc = a->disable_indirect_desc (no-op) */
    /* a->enable_gso = a->enable_gso (no-op) */
    /* a->enable_packed = a->enable_packed (no-op) */
    a->custom_dev_instance = clib_net_to_host_u32(a->custom_dev_instance);
    /* a->use_custom_mac = a->use_custom_mac (no-op) */
    vl_api_mac_address_t_endian(&a->mac_address, to_net);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_create_vhost_user_if_reply_t_endian (vl_api_create_vhost_user_if_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_modify_vhost_user_if_t_endian (vl_api_modify_vhost_user_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_server = a->is_server (no-op) */
    /* a->sock_filename = a->sock_filename (no-op) */
    /* a->renumber = a->renumber (no-op) */
    /* a->enable_gso = a->enable_gso (no-op) */
    /* a->enable_packed = a->enable_packed (no-op) */
    a->custom_dev_instance = clib_net_to_host_u32(a->custom_dev_instance);
}

static inline void vl_api_modify_vhost_user_if_reply_t_endian (vl_api_modify_vhost_user_if_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_create_vhost_user_if_v2_t_endian (vl_api_create_vhost_user_if_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_server = a->is_server (no-op) */
    /* a->sock_filename = a->sock_filename (no-op) */
    /* a->renumber = a->renumber (no-op) */
    /* a->disable_mrg_rxbuf = a->disable_mrg_rxbuf (no-op) */
    /* a->disable_indirect_desc = a->disable_indirect_desc (no-op) */
    /* a->enable_gso = a->enable_gso (no-op) */
    /* a->enable_packed = a->enable_packed (no-op) */
    /* a->enable_event_idx = a->enable_event_idx (no-op) */
    a->custom_dev_instance = clib_net_to_host_u32(a->custom_dev_instance);
    /* a->use_custom_mac = a->use_custom_mac (no-op) */
    vl_api_mac_address_t_endian(&a->mac_address, to_net);
    /* a->tag = a->tag (no-op) */
}

static inline void vl_api_create_vhost_user_if_v2_reply_t_endian (vl_api_create_vhost_user_if_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_modify_vhost_user_if_v2_t_endian (vl_api_modify_vhost_user_if_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->is_server = a->is_server (no-op) */
    /* a->sock_filename = a->sock_filename (no-op) */
    /* a->renumber = a->renumber (no-op) */
    /* a->enable_gso = a->enable_gso (no-op) */
    /* a->enable_packed = a->enable_packed (no-op) */
    /* a->enable_event_idx = a->enable_event_idx (no-op) */
    a->custom_dev_instance = clib_net_to_host_u32(a->custom_dev_instance);
}

static inline void vl_api_modify_vhost_user_if_v2_reply_t_endian (vl_api_modify_vhost_user_if_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_delete_vhost_user_if_t_endian (vl_api_delete_vhost_user_if_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_delete_vhost_user_if_reply_t_endian (vl_api_delete_vhost_user_if_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_sw_interface_vhost_user_details_t_endian (vl_api_sw_interface_vhost_user_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    /* a->interface_name = a->interface_name (no-op) */
    a->virtio_net_hdr_sz = clib_net_to_host_u32(a->virtio_net_hdr_sz);
    vl_api_virtio_net_features_first_32_t_endian(&a->features_first_32, to_net);
    vl_api_virtio_net_features_last_32_t_endian(&a->features_last_32, to_net);
    /* a->is_server = a->is_server (no-op) */
    /* a->sock_filename = a->sock_filename (no-op) */
    a->num_regions = clib_net_to_host_u32(a->num_regions);
    a->sock_errno = clib_net_to_host_i32(a->sock_errno);
}

static inline void vl_api_sw_interface_vhost_user_dump_t_endian (vl_api_sw_interface_vhost_user_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_vhost_user_calcsizefun
#define included_vhost_user_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_create_vhost_user_if_t_calc_size (vl_api_create_vhost_user_if_t *a)
{
      return sizeof(*a) - sizeof(a->mac_address) + vl_api_mac_address_t_calc_size(&a->mac_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_create_vhost_user_if_reply_t_calc_size (vl_api_create_vhost_user_if_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_modify_vhost_user_if_t_calc_size (vl_api_modify_vhost_user_if_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_modify_vhost_user_if_reply_t_calc_size (vl_api_modify_vhost_user_if_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_create_vhost_user_if_v2_t_calc_size (vl_api_create_vhost_user_if_v2_t *a)
{
      return sizeof(*a) - sizeof(a->mac_address) + vl_api_mac_address_t_calc_size(&a->mac_address);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_create_vhost_user_if_v2_reply_t_calc_size (vl_api_create_vhost_user_if_v2_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_modify_vhost_user_if_v2_t_calc_size (vl_api_modify_vhost_user_if_v2_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_modify_vhost_user_if_v2_reply_t_calc_size (vl_api_modify_vhost_user_if_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_delete_vhost_user_if_t_calc_size (vl_api_delete_vhost_user_if_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_delete_vhost_user_if_reply_t_calc_size (vl_api_delete_vhost_user_if_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_vhost_user_details_t_calc_size (vl_api_sw_interface_vhost_user_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->features_first_32) + vl_api_virtio_net_features_first_32_t_calc_size(&a->features_first_32) - sizeof(a->features_last_32) + vl_api_virtio_net_features_last_32_t_calc_size(&a->features_last_32);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_sw_interface_vhost_user_dump_t_calc_size (vl_api_sw_interface_vhost_user_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(vhost_user.api, 4, 1, 1)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(vhost_user.api, 0x30000028)

#endif

