/*
 * VLIB API definitions 2026-04-04 08:31:58
 * Input file: ipsec.api
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
#warning no content included from ipsec.api
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
#include <vnet/ipsec/ipsec_types.api.h>
#include <vnet/interface_types.api.h>
#include <vnet/ip/ip_types.api.h>
#include <vnet/interface_types.api.h>
#include <vnet/tunnel/tunnel_types.api.h>
#endif

/****** Message ID / handler enum ******/

#ifdef vl_msg_id
vl_msg_id(VL_API_IPSEC_SPD_ADD_DEL, vl_api_ipsec_spd_add_del_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_ADD_DEL_REPLY, vl_api_ipsec_spd_add_del_reply_t_handler)
vl_msg_id(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD, vl_api_ipsec_interface_add_del_spd_t_handler)
vl_msg_id(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY, vl_api_ipsec_interface_add_del_spd_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_ENTRY_ADD_DEL, vl_api_ipsec_spd_entry_add_del_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2, vl_api_ipsec_spd_entry_add_del_v2_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY, vl_api_ipsec_spd_entry_add_del_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY, vl_api_ipsec_spd_entry_add_del_v2_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SPDS_DUMP, vl_api_ipsec_spds_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SPDS_DETAILS, vl_api_ipsec_spds_details_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_DUMP, vl_api_ipsec_spd_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_DETAILS, vl_api_ipsec_spd_details_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_DEL, vl_api_ipsec_sad_entry_add_del_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2, vl_api_ipsec_sad_entry_add_del_v2_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3, vl_api_ipsec_sad_entry_add_del_v3_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD, vl_api_ipsec_sad_entry_add_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_V2, vl_api_ipsec_sad_entry_add_v2_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_DEL, vl_api_ipsec_sad_entry_del_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_DEL_REPLY, vl_api_ipsec_sad_entry_del_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_BIND, vl_api_ipsec_sad_bind_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_BIND_REPLY, vl_api_ipsec_sad_bind_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_UNBIND, vl_api_ipsec_sad_unbind_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_UNBIND_REPLY, vl_api_ipsec_sad_unbind_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_UPDATE, vl_api_ipsec_sad_entry_update_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY, vl_api_ipsec_sad_entry_update_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY, vl_api_ipsec_sad_entry_add_del_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY, vl_api_ipsec_sad_entry_add_del_v2_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY, vl_api_ipsec_sad_entry_add_del_v3_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_REPLY, vl_api_ipsec_sad_entry_add_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY, vl_api_ipsec_sad_entry_add_v2_reply_t_handler)
vl_msg_id(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE, vl_api_ipsec_tunnel_protect_update_t_handler)
vl_msg_id(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY, vl_api_ipsec_tunnel_protect_update_reply_t_handler)
vl_msg_id(VL_API_IPSEC_TUNNEL_PROTECT_DEL, vl_api_ipsec_tunnel_protect_del_t_handler)
vl_msg_id(VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY, vl_api_ipsec_tunnel_protect_del_reply_t_handler)
vl_msg_id(VL_API_IPSEC_TUNNEL_PROTECT_DUMP, vl_api_ipsec_tunnel_protect_dump_t_handler)
vl_msg_id(VL_API_IPSEC_TUNNEL_PROTECT_DETAILS, vl_api_ipsec_tunnel_protect_details_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_INTERFACE_DUMP, vl_api_ipsec_spd_interface_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SPD_INTERFACE_DETAILS, vl_api_ipsec_spd_interface_details_t_handler)
vl_msg_id(VL_API_IPSEC_ITF_CREATE, vl_api_ipsec_itf_create_t_handler)
vl_msg_id(VL_API_IPSEC_ITF_CREATE_REPLY, vl_api_ipsec_itf_create_reply_t_handler)
vl_msg_id(VL_API_IPSEC_ITF_DELETE, vl_api_ipsec_itf_delete_t_handler)
vl_msg_id(VL_API_IPSEC_ITF_DELETE_REPLY, vl_api_ipsec_itf_delete_reply_t_handler)
vl_msg_id(VL_API_IPSEC_ITF_DUMP, vl_api_ipsec_itf_dump_t_handler)
vl_msg_id(VL_API_IPSEC_ITF_DETAILS, vl_api_ipsec_itf_details_t_handler)
vl_msg_id(VL_API_IPSEC_SA_DUMP, vl_api_ipsec_sa_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V2_DUMP, vl_api_ipsec_sa_v2_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V3_DUMP, vl_api_ipsec_sa_v3_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V4_DUMP, vl_api_ipsec_sa_v4_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V5_DUMP, vl_api_ipsec_sa_v5_dump_t_handler)
vl_msg_id(VL_API_IPSEC_SA_DETAILS, vl_api_ipsec_sa_details_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V2_DETAILS, vl_api_ipsec_sa_v2_details_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V3_DETAILS, vl_api_ipsec_sa_v3_details_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V4_DETAILS, vl_api_ipsec_sa_v4_details_t_handler)
vl_msg_id(VL_API_IPSEC_SA_V5_DETAILS, vl_api_ipsec_sa_v5_details_t_handler)
vl_msg_id(VL_API_IPSEC_BACKEND_DUMP, vl_api_ipsec_backend_dump_t_handler)
vl_msg_id(VL_API_IPSEC_BACKEND_DETAILS, vl_api_ipsec_backend_details_t_handler)
vl_msg_id(VL_API_IPSEC_SELECT_BACKEND, vl_api_ipsec_select_backend_t_handler)
vl_msg_id(VL_API_IPSEC_SELECT_BACKEND_REPLY, vl_api_ipsec_select_backend_reply_t_handler)
vl_msg_id(VL_API_IPSEC_SET_ASYNC_MODE, vl_api_ipsec_set_async_mode_t_handler)
vl_msg_id(VL_API_IPSEC_SET_ASYNC_MODE_REPLY, vl_api_ipsec_set_async_mode_reply_t_handler)
#endif
/****** Message names ******/

#ifdef vl_msg_name
vl_msg_name(vl_api_ipsec_spd_add_del_t, 1)
vl_msg_name(vl_api_ipsec_spd_add_del_reply_t, 1)
vl_msg_name(vl_api_ipsec_interface_add_del_spd_t, 1)
vl_msg_name(vl_api_ipsec_interface_add_del_spd_reply_t, 1)
vl_msg_name(vl_api_ipsec_spd_entry_add_del_t, 1)
vl_msg_name(vl_api_ipsec_spd_entry_add_del_v2_t, 1)
vl_msg_name(vl_api_ipsec_spd_entry_add_del_reply_t, 1)
vl_msg_name(vl_api_ipsec_spd_entry_add_del_v2_reply_t, 1)
vl_msg_name(vl_api_ipsec_spds_dump_t, 1)
vl_msg_name(vl_api_ipsec_spds_details_t, 1)
vl_msg_name(vl_api_ipsec_spd_dump_t, 1)
vl_msg_name(vl_api_ipsec_spd_details_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_del_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_del_v2_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_del_v3_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_v2_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_del_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_del_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_bind_t, 1)
vl_msg_name(vl_api_ipsec_sad_bind_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_unbind_t, 1)
vl_msg_name(vl_api_ipsec_sad_unbind_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_update_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_update_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_del_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_del_v2_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_del_v3_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_reply_t, 1)
vl_msg_name(vl_api_ipsec_sad_entry_add_v2_reply_t, 1)
vl_msg_name(vl_api_ipsec_tunnel_protect_update_t, 1)
vl_msg_name(vl_api_ipsec_tunnel_protect_update_reply_t, 1)
vl_msg_name(vl_api_ipsec_tunnel_protect_del_t, 1)
vl_msg_name(vl_api_ipsec_tunnel_protect_del_reply_t, 1)
vl_msg_name(vl_api_ipsec_tunnel_protect_dump_t, 1)
vl_msg_name(vl_api_ipsec_tunnel_protect_details_t, 1)
vl_msg_name(vl_api_ipsec_spd_interface_dump_t, 1)
vl_msg_name(vl_api_ipsec_spd_interface_details_t, 1)
vl_msg_name(vl_api_ipsec_itf_create_t, 1)
vl_msg_name(vl_api_ipsec_itf_create_reply_t, 1)
vl_msg_name(vl_api_ipsec_itf_delete_t, 1)
vl_msg_name(vl_api_ipsec_itf_delete_reply_t, 1)
vl_msg_name(vl_api_ipsec_itf_dump_t, 1)
vl_msg_name(vl_api_ipsec_itf_details_t, 1)
vl_msg_name(vl_api_ipsec_sa_dump_t, 1)
vl_msg_name(vl_api_ipsec_sa_v2_dump_t, 1)
vl_msg_name(vl_api_ipsec_sa_v3_dump_t, 1)
vl_msg_name(vl_api_ipsec_sa_v4_dump_t, 1)
vl_msg_name(vl_api_ipsec_sa_v5_dump_t, 1)
vl_msg_name(vl_api_ipsec_sa_details_t, 1)
vl_msg_name(vl_api_ipsec_sa_v2_details_t, 1)
vl_msg_name(vl_api_ipsec_sa_v3_details_t, 1)
vl_msg_name(vl_api_ipsec_sa_v4_details_t, 1)
vl_msg_name(vl_api_ipsec_sa_v5_details_t, 1)
vl_msg_name(vl_api_ipsec_backend_dump_t, 1)
vl_msg_name(vl_api_ipsec_backend_details_t, 1)
vl_msg_name(vl_api_ipsec_select_backend_t, 1)
vl_msg_name(vl_api_ipsec_select_backend_reply_t, 1)
vl_msg_name(vl_api_ipsec_set_async_mode_t, 1)
vl_msg_name(vl_api_ipsec_set_async_mode_reply_t, 1)
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ipsec \
_(VL_API_IPSEC_SPD_ADD_DEL, ipsec_spd_add_del, 20e89a95) \
_(VL_API_IPSEC_SPD_ADD_DEL_REPLY, ipsec_spd_add_del_reply, e8d4e804) \
_(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD, ipsec_interface_add_del_spd, 80f80cbb) \
_(VL_API_IPSEC_INTERFACE_ADD_DEL_SPD_REPLY, ipsec_interface_add_del_spd_reply, e8d4e804) \
_(VL_API_IPSEC_SPD_ENTRY_ADD_DEL, ipsec_spd_entry_add_del, 338b7411) \
_(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2, ipsec_spd_entry_add_del_v2, 7bfe69fc) \
_(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_REPLY, ipsec_spd_entry_add_del_reply, 9ffac24b) \
_(VL_API_IPSEC_SPD_ENTRY_ADD_DEL_V2_REPLY, ipsec_spd_entry_add_del_v2_reply, 9ffac24b) \
_(VL_API_IPSEC_SPDS_DUMP, ipsec_spds_dump, 51077d14) \
_(VL_API_IPSEC_SPDS_DETAILS, ipsec_spds_details, a04bb254) \
_(VL_API_IPSEC_SPD_DUMP, ipsec_spd_dump, afefbf7d) \
_(VL_API_IPSEC_SPD_DETAILS, ipsec_spd_details, 5813d7a2) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_DEL, ipsec_sad_entry_add_del, ab64b5c6) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2, ipsec_sad_entry_add_del_v2, aca78b27) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3, ipsec_sad_entry_add_del_v3, c77ebd92) \
_(VL_API_IPSEC_SAD_ENTRY_ADD, ipsec_sad_entry_add, 50229353) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_V2, ipsec_sad_entry_add_v2, 9611297a) \
_(VL_API_IPSEC_SAD_ENTRY_DEL, ipsec_sad_entry_del, 3a91bde5) \
_(VL_API_IPSEC_SAD_ENTRY_DEL_REPLY, ipsec_sad_entry_del_reply, e8d4e804) \
_(VL_API_IPSEC_SAD_BIND, ipsec_sad_bind, 0649c0d9) \
_(VL_API_IPSEC_SAD_BIND_REPLY, ipsec_sad_bind_reply, e8d4e804) \
_(VL_API_IPSEC_SAD_UNBIND, ipsec_sad_unbind, 2076c2f4) \
_(VL_API_IPSEC_SAD_UNBIND_REPLY, ipsec_sad_unbind_reply, e8d4e804) \
_(VL_API_IPSEC_SAD_ENTRY_UPDATE, ipsec_sad_entry_update, 1412af86) \
_(VL_API_IPSEC_SAD_ENTRY_UPDATE_REPLY, ipsec_sad_entry_update_reply, e8d4e804) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_REPLY, ipsec_sad_entry_add_del_reply, 9ffac24b) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V2_REPLY, ipsec_sad_entry_add_del_v2_reply, 9ffac24b) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_DEL_V3_REPLY, ipsec_sad_entry_add_del_v3_reply, 9ffac24b) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_REPLY, ipsec_sad_entry_add_reply, 9ffac24b) \
_(VL_API_IPSEC_SAD_ENTRY_ADD_V2_REPLY, ipsec_sad_entry_add_v2_reply, 9ffac24b) \
_(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE, ipsec_tunnel_protect_update, 30d5f133) \
_(VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_REPLY, ipsec_tunnel_protect_update_reply, e8d4e804) \
_(VL_API_IPSEC_TUNNEL_PROTECT_DEL, ipsec_tunnel_protect_del, cd239930) \
_(VL_API_IPSEC_TUNNEL_PROTECT_DEL_REPLY, ipsec_tunnel_protect_del_reply, e8d4e804) \
_(VL_API_IPSEC_TUNNEL_PROTECT_DUMP, ipsec_tunnel_protect_dump, f9e6675e) \
_(VL_API_IPSEC_TUNNEL_PROTECT_DETAILS, ipsec_tunnel_protect_details, 21663a50) \
_(VL_API_IPSEC_SPD_INTERFACE_DUMP, ipsec_spd_interface_dump, 8971de19) \
_(VL_API_IPSEC_SPD_INTERFACE_DETAILS, ipsec_spd_interface_details, 7a0bcf3e) \
_(VL_API_IPSEC_ITF_CREATE, ipsec_itf_create, 6f50b3bc) \
_(VL_API_IPSEC_ITF_CREATE_REPLY, ipsec_itf_create_reply, 5383d31f) \
_(VL_API_IPSEC_ITF_DELETE, ipsec_itf_delete, f9e6675e) \
_(VL_API_IPSEC_ITF_DELETE_REPLY, ipsec_itf_delete_reply, e8d4e804) \
_(VL_API_IPSEC_ITF_DUMP, ipsec_itf_dump, f9e6675e) \
_(VL_API_IPSEC_ITF_DETAILS, ipsec_itf_details, 548a73b8) \
_(VL_API_IPSEC_SA_DUMP, ipsec_sa_dump, 2076c2f4) \
_(VL_API_IPSEC_SA_V2_DUMP, ipsec_sa_v2_dump, 2076c2f4) \
_(VL_API_IPSEC_SA_V3_DUMP, ipsec_sa_v3_dump, 2076c2f4) \
_(VL_API_IPSEC_SA_V4_DUMP, ipsec_sa_v4_dump, 2076c2f4) \
_(VL_API_IPSEC_SA_V5_DUMP, ipsec_sa_v5_dump, 2076c2f4) \
_(VL_API_IPSEC_SA_DETAILS, ipsec_sa_details, 345d14a7) \
_(VL_API_IPSEC_SA_V2_DETAILS, ipsec_sa_v2_details, e2130051) \
_(VL_API_IPSEC_SA_V3_DETAILS, ipsec_sa_v3_details, 2fc991ee) \
_(VL_API_IPSEC_SA_V4_DETAILS, ipsec_sa_v4_details, 87a322d7) \
_(VL_API_IPSEC_SA_V5_DETAILS, ipsec_sa_v5_details, 3cfecfbd) \
_(VL_API_IPSEC_BACKEND_DUMP, ipsec_backend_dump, 51077d14) \
_(VL_API_IPSEC_BACKEND_DETAILS, ipsec_backend_details, ee601c29) \
_(VL_API_IPSEC_SELECT_BACKEND, ipsec_select_backend, 5bcfd3b7) \
_(VL_API_IPSEC_SELECT_BACKEND_REPLY, ipsec_select_backend_reply, e8d4e804) \
_(VL_API_IPSEC_SET_ASYNC_MODE, ipsec_set_async_mode, a6465f7c) \
_(VL_API_IPSEC_SET_ASYNC_MODE_REPLY, ipsec_set_async_mode_reply, e8d4e804) 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ipsec.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ipsec_printfun_types
#define included_ipsec_printfun_types

static inline u8 *format_vl_api_ipsec_tunnel_protect_t (u8 *s, va_list * args)
{
    vl_api_ipsec_tunnel_protect_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Unh: %U", format_white_space, indent, format_vl_api_address_t, &a->nh, indent);
    s = format(s, "\n%Usa_out: %u", format_white_space, indent, a->sa_out);
    s = format(s, "\n%Un_sa_in: %u", format_white_space, indent, a->n_sa_in);
    for (i = 0; i < a->n_sa_in; i++) {
        s = format(s, "\n%Usa_in: %u",
                   format_white_space, indent, a->sa_in[i]);
    }
    return s;
}

static inline u8 *format_vl_api_ipsec_itf_t (u8 *s, va_list * args)
{
    vl_api_ipsec_itf_t *a = va_arg (*args, vl_api_ipsec_itf_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uuser_instance: %u", format_white_space, indent, a->user_instance);
    s = format(s, "\n%Umode: %U", format_white_space, indent, format_vl_api_tunnel_mode_t, &a->mode, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ipsec_printfun
#define included_ipsec_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ipsec.api_tojson.h"
#include "ipsec.api_fromjson.h"

static inline u8 *vl_api_ipsec_spd_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_add_del_t *a = va_arg (*args, vl_api_ipsec_spd_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_add_del_t: */
    s = format(s, "vl_api_ipsec_spd_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uspd_id: %u", format_white_space, indent, a->spd_id);
    return s;
}

static inline u8 *vl_api_ipsec_spd_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_add_del_reply_t *a = va_arg (*args, vl_api_ipsec_spd_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_add_del_reply_t: */
    s = format(s, "vl_api_ipsec_spd_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_interface_add_del_spd_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_interface_add_del_spd_t *a = va_arg (*args, vl_api_ipsec_interface_add_del_spd_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_interface_add_del_spd_t: */
    s = format(s, "vl_api_ipsec_interface_add_del_spd_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uspd_id: %u", format_white_space, indent, a->spd_id);
    return s;
}

static inline u8 *vl_api_ipsec_interface_add_del_spd_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_interface_add_del_spd_reply_t *a = va_arg (*args, vl_api_ipsec_interface_add_del_spd_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_interface_add_del_spd_reply_t: */
    s = format(s, "vl_api_ipsec_interface_add_del_spd_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_spd_entry_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_entry_add_del_t *a = va_arg (*args, vl_api_ipsec_spd_entry_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_entry_add_del_t: */
    s = format(s, "vl_api_ipsec_spd_entry_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_spd_entry_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_spd_entry_add_del_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_entry_add_del_v2_t *a = va_arg (*args, vl_api_ipsec_spd_entry_add_del_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_entry_add_del_v2_t: */
    s = format(s, "vl_api_ipsec_spd_entry_add_del_v2_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_spd_entry_v2_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_spd_entry_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_entry_add_del_reply_t *a = va_arg (*args, vl_api_ipsec_spd_entry_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_entry_add_del_reply_t: */
    s = format(s, "vl_api_ipsec_spd_entry_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_spd_entry_add_del_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_entry_add_del_v2_reply_t *a = va_arg (*args, vl_api_ipsec_spd_entry_add_del_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_entry_add_del_v2_reply_t: */
    s = format(s, "vl_api_ipsec_spd_entry_add_del_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_spds_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spds_dump_t *a = va_arg (*args, vl_api_ipsec_spds_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spds_dump_t: */
    s = format(s, "vl_api_ipsec_spds_dump_t:");
    return s;
}

static inline u8 *vl_api_ipsec_spds_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spds_details_t *a = va_arg (*args, vl_api_ipsec_spds_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spds_details_t: */
    s = format(s, "vl_api_ipsec_spds_details_t:");
    s = format(s, "\n%Uspd_id: %u", format_white_space, indent, a->spd_id);
    s = format(s, "\n%Unpolicies: %u", format_white_space, indent, a->npolicies);
    return s;
}

static inline u8 *vl_api_ipsec_spd_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_dump_t *a = va_arg (*args, vl_api_ipsec_spd_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_dump_t: */
    s = format(s, "vl_api_ipsec_spd_dump_t:");
    s = format(s, "\n%Uspd_id: %u", format_white_space, indent, a->spd_id);
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_spd_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_details_t *a = va_arg (*args, vl_api_ipsec_spd_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_details_t: */
    s = format(s, "vl_api_ipsec_spd_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_spd_entry_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_del_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_del_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_del_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_del_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_del_v2_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_del_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_del_v2_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_del_v2_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v2_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_del_v3_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_del_v3_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_del_v3_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_del_v3_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_del_v3_t:");
    s = format(s, "\n%Uis_add: %u", format_white_space, indent, a->is_add);
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v3_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v3_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_v2_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_v2_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_v2_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_v2_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_v2_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v4_t, &a->entry, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_del_t *a = va_arg (*args, vl_api_ipsec_sad_entry_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_del_t: */
    s = format(s, "vl_api_ipsec_sad_entry_del_t:");
    s = format(s, "\n%Uid: %u", format_white_space, indent, a->id);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_del_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_del_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_sad_bind_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_bind_t *a = va_arg (*args, vl_api_ipsec_sad_bind_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_bind_t: */
    s = format(s, "vl_api_ipsec_sad_bind_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    s = format(s, "\n%Uworker: %u", format_white_space, indent, a->worker);
    return s;
}

static inline u8 *vl_api_ipsec_sad_bind_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_bind_reply_t *a = va_arg (*args, vl_api_ipsec_sad_bind_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_bind_reply_t: */
    s = format(s, "vl_api_ipsec_sad_bind_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_sad_unbind_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_unbind_t *a = va_arg (*args, vl_api_ipsec_sad_unbind_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_unbind_t: */
    s = format(s, "vl_api_ipsec_sad_unbind_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_sad_unbind_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_unbind_reply_t *a = va_arg (*args, vl_api_ipsec_sad_unbind_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_unbind_reply_t: */
    s = format(s, "vl_api_ipsec_sad_unbind_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_update_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_update_t *a = va_arg (*args, vl_api_ipsec_sad_entry_update_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_update_t: */
    s = format(s, "vl_api_ipsec_sad_entry_update_t:");
    s = format(s, "\n%Usad_id: %u", format_white_space, indent, a->sad_id);
    s = format(s, "\n%Uis_tun: %u", format_white_space, indent, a->is_tun);
    s = format(s, "\n%Utunnel: %U", format_white_space, indent, format_vl_api_tunnel_t, &a->tunnel, indent);
    s = format(s, "\n%Uudp_src_port: %u", format_white_space, indent, a->udp_src_port);
    s = format(s, "\n%Uudp_dst_port: %u", format_white_space, indent, a->udp_dst_port);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_update_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_update_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_update_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_update_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_update_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_del_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_del_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_del_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_del_v2_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_del_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_del_v2_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_del_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_del_v3_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_del_v3_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_del_v3_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_del_v3_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_del_v3_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sad_entry_add_v2_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sad_entry_add_v2_reply_t *a = va_arg (*args, vl_api_ipsec_sad_entry_add_v2_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sad_entry_add_v2_reply_t: */
    s = format(s, "vl_api_ipsec_sad_entry_add_v2_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_tunnel_protect_update_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_tunnel_protect_update_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_update_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_tunnel_protect_update_t: */
    s = format(s, "vl_api_ipsec_tunnel_protect_update_t:");
    s = format(s, "\n%Utunnel: %U", format_white_space, indent, format_vl_api_ipsec_tunnel_protect_t, &a->tunnel, indent);
    return s;
}

static inline u8 *vl_api_ipsec_tunnel_protect_update_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_tunnel_protect_update_reply_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_update_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_tunnel_protect_update_reply_t: */
    s = format(s, "vl_api_ipsec_tunnel_protect_update_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_tunnel_protect_del_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_tunnel_protect_del_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_del_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_tunnel_protect_del_t: */
    s = format(s, "vl_api_ipsec_tunnel_protect_del_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Unh: %U", format_white_space, indent, format_vl_api_address_t, &a->nh, indent);
    return s;
}

static inline u8 *vl_api_ipsec_tunnel_protect_del_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_tunnel_protect_del_reply_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_del_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_tunnel_protect_del_reply_t: */
    s = format(s, "vl_api_ipsec_tunnel_protect_del_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_tunnel_protect_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_tunnel_protect_dump_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_tunnel_protect_dump_t: */
    s = format(s, "vl_api_ipsec_tunnel_protect_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipsec_tunnel_protect_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_tunnel_protect_details_t *a = va_arg (*args, vl_api_ipsec_tunnel_protect_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_tunnel_protect_details_t: */
    s = format(s, "vl_api_ipsec_tunnel_protect_details_t:");
    s = format(s, "\n%Utun: %U", format_white_space, indent, format_vl_api_ipsec_tunnel_protect_t, &a->tun, indent);
    return s;
}

static inline u8 *vl_api_ipsec_spd_interface_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_interface_dump_t *a = va_arg (*args, vl_api_ipsec_spd_interface_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_interface_dump_t: */
    s = format(s, "vl_api_ipsec_spd_interface_dump_t:");
    s = format(s, "\n%Uspd_index: %u", format_white_space, indent, a->spd_index);
    s = format(s, "\n%Uspd_index_valid: %u", format_white_space, indent, a->spd_index_valid);
    return s;
}

static inline u8 *vl_api_ipsec_spd_interface_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_spd_interface_details_t *a = va_arg (*args, vl_api_ipsec_spd_interface_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_spd_interface_details_t: */
    s = format(s, "vl_api_ipsec_spd_interface_details_t:");
    s = format(s, "\n%Uspd_index: %u", format_white_space, indent, a->spd_index);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipsec_itf_create_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_itf_create_t *a = va_arg (*args, vl_api_ipsec_itf_create_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_itf_create_t: */
    s = format(s, "vl_api_ipsec_itf_create_t:");
    s = format(s, "\n%Uitf: %U", format_white_space, indent, format_vl_api_ipsec_itf_t, &a->itf, indent);
    return s;
}

static inline u8 *vl_api_ipsec_itf_create_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_itf_create_reply_t *a = va_arg (*args, vl_api_ipsec_itf_create_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_itf_create_reply_t: */
    s = format(s, "vl_api_ipsec_itf_create_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipsec_itf_delete_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_itf_delete_t *a = va_arg (*args, vl_api_ipsec_itf_delete_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_itf_delete_t: */
    s = format(s, "vl_api_ipsec_itf_delete_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipsec_itf_delete_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_itf_delete_reply_t *a = va_arg (*args, vl_api_ipsec_itf_delete_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_itf_delete_reply_t: */
    s = format(s, "vl_api_ipsec_itf_delete_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_itf_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_itf_dump_t *a = va_arg (*args, vl_api_ipsec_itf_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_itf_dump_t: */
    s = format(s, "vl_api_ipsec_itf_dump_t:");
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    return s;
}

static inline u8 *vl_api_ipsec_itf_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_itf_details_t *a = va_arg (*args, vl_api_ipsec_itf_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_itf_details_t: */
    s = format(s, "vl_api_ipsec_itf_details_t:");
    s = format(s, "\n%Uitf: %U", format_white_space, indent, format_vl_api_ipsec_itf_t, &a->itf, indent);
    return s;
}

static inline u8 *vl_api_ipsec_sa_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_dump_t *a = va_arg (*args, vl_api_ipsec_sa_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_dump_t: */
    s = format(s, "vl_api_ipsec_sa_dump_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v2_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v2_dump_t *a = va_arg (*args, vl_api_ipsec_sa_v2_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v2_dump_t: */
    s = format(s, "vl_api_ipsec_sa_v2_dump_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v3_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v3_dump_t *a = va_arg (*args, vl_api_ipsec_sa_v3_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v3_dump_t: */
    s = format(s, "vl_api_ipsec_sa_v3_dump_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v4_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v4_dump_t *a = va_arg (*args, vl_api_ipsec_sa_v4_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v4_dump_t: */
    s = format(s, "vl_api_ipsec_sa_v4_dump_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v5_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v5_dump_t *a = va_arg (*args, vl_api_ipsec_sa_v5_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v5_dump_t: */
    s = format(s, "vl_api_ipsec_sa_v5_dump_t:");
    s = format(s, "\n%Usa_id: %u", format_white_space, indent, a->sa_id);
    return s;
}

static inline u8 *vl_api_ipsec_sa_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_details_t *a = va_arg (*args, vl_api_ipsec_sa_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_details_t: */
    s = format(s, "vl_api_ipsec_sa_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_t, &a->entry, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usalt: %u", format_white_space, indent, a->salt);
    s = format(s, "\n%Useq_outbound: %llu", format_white_space, indent, a->seq_outbound);
    s = format(s, "\n%Ulast_seq_inbound: %llu", format_white_space, indent, a->last_seq_inbound);
    s = format(s, "\n%Ureplay_window: %llu", format_white_space, indent, a->replay_window);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v2_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v2_details_t *a = va_arg (*args, vl_api_ipsec_sa_v2_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v2_details_t: */
    s = format(s, "vl_api_ipsec_sa_v2_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v2_t, &a->entry, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Usalt: %u", format_white_space, indent, a->salt);
    s = format(s, "\n%Useq_outbound: %llu", format_white_space, indent, a->seq_outbound);
    s = format(s, "\n%Ulast_seq_inbound: %llu", format_white_space, indent, a->last_seq_inbound);
    s = format(s, "\n%Ureplay_window: %llu", format_white_space, indent, a->replay_window);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v3_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v3_details_t *a = va_arg (*args, vl_api_ipsec_sa_v3_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v3_details_t: */
    s = format(s, "vl_api_ipsec_sa_v3_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v3_t, &a->entry, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Useq_outbound: %llu", format_white_space, indent, a->seq_outbound);
    s = format(s, "\n%Ulast_seq_inbound: %llu", format_white_space, indent, a->last_seq_inbound);
    s = format(s, "\n%Ureplay_window: %llu", format_white_space, indent, a->replay_window);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v4_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v4_details_t *a = va_arg (*args, vl_api_ipsec_sa_v4_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v4_details_t: */
    s = format(s, "vl_api_ipsec_sa_v4_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v3_t, &a->entry, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Useq_outbound: %llu", format_white_space, indent, a->seq_outbound);
    s = format(s, "\n%Ulast_seq_inbound: %llu", format_white_space, indent, a->last_seq_inbound);
    s = format(s, "\n%Ureplay_window: %llu", format_white_space, indent, a->replay_window);
    s = format(s, "\n%Uthread_index: %u", format_white_space, indent, a->thread_index);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_sa_v5_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_sa_v5_details_t *a = va_arg (*args, vl_api_ipsec_sa_v5_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_sa_v5_details_t: */
    s = format(s, "vl_api_ipsec_sa_v5_details_t:");
    s = format(s, "\n%Uentry: %U", format_white_space, indent, format_vl_api_ipsec_sad_entry_v4_t, &a->entry, indent);
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Useq_outbound: %llu", format_white_space, indent, a->seq_outbound);
    s = format(s, "\n%Ulast_seq_inbound: %llu", format_white_space, indent, a->last_seq_inbound);
    s = format(s, "\n%Ureplay_window: %llu", format_white_space, indent, a->replay_window);
    s = format(s, "\n%Uthread_index: %u", format_white_space, indent, a->thread_index);
    s = format(s, "\n%Ustat_index: %u", format_white_space, indent, a->stat_index);
    return s;
}

static inline u8 *vl_api_ipsec_backend_dump_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_backend_dump_t *a = va_arg (*args, vl_api_ipsec_backend_dump_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_backend_dump_t: */
    s = format(s, "vl_api_ipsec_backend_dump_t:");
    return s;
}

static inline u8 *vl_api_ipsec_backend_details_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_backend_details_t *a = va_arg (*args, vl_api_ipsec_backend_details_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_backend_details_t: */
    s = format(s, "vl_api_ipsec_backend_details_t:");
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ipsec_proto_t, &a->protocol, indent);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    s = format(s, "\n%Uactive: %u", format_white_space, indent, a->active);
    return s;
}

static inline u8 *vl_api_ipsec_select_backend_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_select_backend_t *a = va_arg (*args, vl_api_ipsec_select_backend_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_select_backend_t: */
    s = format(s, "vl_api_ipsec_select_backend_t:");
    s = format(s, "\n%Uprotocol: %U", format_white_space, indent, format_vl_api_ipsec_proto_t, &a->protocol, indent);
    s = format(s, "\n%Uindex: %u", format_white_space, indent, a->index);
    return s;
}

static inline u8 *vl_api_ipsec_select_backend_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_select_backend_reply_t *a = va_arg (*args, vl_api_ipsec_select_backend_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_select_backend_reply_t: */
    s = format(s, "vl_api_ipsec_select_backend_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}

static inline u8 *vl_api_ipsec_set_async_mode_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_set_async_mode_t *a = va_arg (*args, vl_api_ipsec_set_async_mode_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_set_async_mode_t: */
    s = format(s, "vl_api_ipsec_set_async_mode_t:");
    s = format(s, "\n%Uasync_enable: %u", format_white_space, indent, a->async_enable);
    return s;
}

static inline u8 *vl_api_ipsec_set_async_mode_reply_t_format (u8 *s,  va_list *args)
{
    __attribute__((unused)) vl_api_ipsec_set_async_mode_reply_t *a = va_arg (*args, vl_api_ipsec_set_async_mode_reply_t *);
    u32 indent __attribute__((unused)) = 2;
    int i __attribute__((unused));
    /* Message definition: vl_api_ipsec_set_async_mode_reply_t: */
    s = format(s, "vl_api_ipsec_set_async_mode_reply_t:");
    s = format(s, "\n%Uretval: %ld", format_white_space, indent, a->retval);
    return s;
}


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ipsec_endianfun
#define included_ipsec_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_ipsec_tunnel_protect_t_endian (vl_api_ipsec_tunnel_protect_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->nh, to_net);
    a->sa_out = clib_net_to_host_u32(a->sa_out);
    /* a->n_sa_in = a->n_sa_in (no-op) */
    u32 count = a->n_sa_in;
    ASSERT((u32)count <= (u32)VL_API_MAX_ARRAY_SIZE);
    for (i = 0; i < count; i++) {
        a->sa_in[i] = clib_net_to_host_u32(a->sa_in[i]);
    }
}

static inline void vl_api_ipsec_itf_t_endian (vl_api_ipsec_itf_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->user_instance = clib_net_to_host_u32(a->user_instance);
    vl_api_tunnel_mode_t_endian(&a->mode, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipsec_spd_add_del_t_endian (vl_api_ipsec_spd_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    a->spd_id = clib_net_to_host_u32(a->spd_id);
}

static inline void vl_api_ipsec_spd_add_del_reply_t_endian (vl_api_ipsec_spd_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_interface_add_del_spd_t_endian (vl_api_ipsec_interface_add_del_spd_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->spd_id = clib_net_to_host_u32(a->spd_id);
}

static inline void vl_api_ipsec_interface_add_del_spd_reply_t_endian (vl_api_ipsec_interface_add_del_spd_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_spd_entry_add_del_t_endian (vl_api_ipsec_spd_entry_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ipsec_spd_entry_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_spd_entry_add_del_v2_t_endian (vl_api_ipsec_spd_entry_add_del_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ipsec_spd_entry_v2_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_spd_entry_add_del_reply_t_endian (vl_api_ipsec_spd_entry_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_spd_entry_add_del_v2_reply_t_endian (vl_api_ipsec_spd_entry_add_del_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_spds_dump_t_endian (vl_api_ipsec_spds_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ipsec_spds_details_t_endian (vl_api_ipsec_spds_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->spd_id = clib_net_to_host_u32(a->spd_id);
    a->npolicies = clib_net_to_host_u32(a->npolicies);
}

static inline void vl_api_ipsec_spd_dump_t_endian (vl_api_ipsec_spd_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->spd_id = clib_net_to_host_u32(a->spd_id);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_spd_details_t_endian (vl_api_ipsec_spd_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_spd_entry_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_sad_entry_add_del_t_endian (vl_api_ipsec_sad_entry_add_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ipsec_sad_entry_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_sad_entry_add_del_v2_t_endian (vl_api_ipsec_sad_entry_add_del_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ipsec_sad_entry_v2_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_sad_entry_add_del_v3_t_endian (vl_api_ipsec_sad_entry_add_del_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    vl_api_ipsec_sad_entry_v3_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_sad_entry_add_t_endian (vl_api_ipsec_sad_entry_add_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_v3_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_sad_entry_add_v2_t_endian (vl_api_ipsec_sad_entry_add_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_v4_t_endian(&a->entry, to_net);
}

static inline void vl_api_ipsec_sad_entry_del_t_endian (vl_api_ipsec_sad_entry_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->id = clib_net_to_host_u32(a->id);
}

static inline void vl_api_ipsec_sad_entry_del_reply_t_endian (vl_api_ipsec_sad_entry_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_sad_bind_t_endian (vl_api_ipsec_sad_bind_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
    a->worker = clib_net_to_host_u32(a->worker);
}

static inline void vl_api_ipsec_sad_bind_reply_t_endian (vl_api_ipsec_sad_bind_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_sad_unbind_t_endian (vl_api_ipsec_sad_unbind_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_sad_unbind_reply_t_endian (vl_api_ipsec_sad_unbind_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_sad_entry_update_t_endian (vl_api_ipsec_sad_entry_update_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sad_id = clib_net_to_host_u32(a->sad_id);
    /* a->is_tun = a->is_tun (no-op) */
    vl_api_tunnel_t_endian(&a->tunnel, to_net);
    a->udp_src_port = clib_net_to_host_u16(a->udp_src_port);
    a->udp_dst_port = clib_net_to_host_u16(a->udp_dst_port);
}

static inline void vl_api_ipsec_sad_entry_update_reply_t_endian (vl_api_ipsec_sad_entry_update_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_sad_entry_add_del_reply_t_endian (vl_api_ipsec_sad_entry_add_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sad_entry_add_del_v2_reply_t_endian (vl_api_ipsec_sad_entry_add_del_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sad_entry_add_del_v3_reply_t_endian (vl_api_ipsec_sad_entry_add_del_v3_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sad_entry_add_reply_t_endian (vl_api_ipsec_sad_entry_add_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sad_entry_add_v2_reply_t_endian (vl_api_ipsec_sad_entry_add_v2_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_tunnel_protect_update_t_endian (vl_api_ipsec_tunnel_protect_update_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_tunnel_protect_t_endian(&a->tunnel, to_net);
}

static inline void vl_api_ipsec_tunnel_protect_update_reply_t_endian (vl_api_ipsec_tunnel_protect_update_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_tunnel_protect_del_t_endian (vl_api_ipsec_tunnel_protect_del_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->nh, to_net);
}

static inline void vl_api_ipsec_tunnel_protect_del_reply_t_endian (vl_api_ipsec_tunnel_protect_del_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_tunnel_protect_dump_t_endian (vl_api_ipsec_tunnel_protect_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipsec_tunnel_protect_details_t_endian (vl_api_ipsec_tunnel_protect_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_tunnel_protect_t_endian(&a->tun, to_net);
}

static inline void vl_api_ipsec_spd_interface_dump_t_endian (vl_api_ipsec_spd_interface_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->spd_index = clib_net_to_host_u32(a->spd_index);
    /* a->spd_index_valid = a->spd_index_valid (no-op) */
}

static inline void vl_api_ipsec_spd_interface_details_t_endian (vl_api_ipsec_spd_interface_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->spd_index = clib_net_to_host_u32(a->spd_index);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipsec_itf_create_t_endian (vl_api_ipsec_itf_create_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_itf_t_endian(&a->itf, to_net);
}

static inline void vl_api_ipsec_itf_create_reply_t_endian (vl_api_ipsec_itf_create_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipsec_itf_delete_t_endian (vl_api_ipsec_itf_delete_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipsec_itf_delete_reply_t_endian (vl_api_ipsec_itf_delete_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_itf_dump_t_endian (vl_api_ipsec_itf_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
}

static inline void vl_api_ipsec_itf_details_t_endian (vl_api_ipsec_itf_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_itf_t_endian(&a->itf, to_net);
}

static inline void vl_api_ipsec_sa_dump_t_endian (vl_api_ipsec_sa_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_sa_v2_dump_t_endian (vl_api_ipsec_sa_v2_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_sa_v3_dump_t_endian (vl_api_ipsec_sa_v3_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_sa_v4_dump_t_endian (vl_api_ipsec_sa_v4_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_sa_v5_dump_t_endian (vl_api_ipsec_sa_v5_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    a->sa_id = clib_net_to_host_u32(a->sa_id);
}

static inline void vl_api_ipsec_sa_details_t_endian (vl_api_ipsec_sa_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_t_endian(&a->entry, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->salt = clib_net_to_host_u32(a->salt);
    a->seq_outbound = clib_net_to_host_u64(a->seq_outbound);
    a->last_seq_inbound = clib_net_to_host_u64(a->last_seq_inbound);
    a->replay_window = clib_net_to_host_u64(a->replay_window);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sa_v2_details_t_endian (vl_api_ipsec_sa_v2_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_v2_t_endian(&a->entry, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->salt = clib_net_to_host_u32(a->salt);
    a->seq_outbound = clib_net_to_host_u64(a->seq_outbound);
    a->last_seq_inbound = clib_net_to_host_u64(a->last_seq_inbound);
    a->replay_window = clib_net_to_host_u64(a->replay_window);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sa_v3_details_t_endian (vl_api_ipsec_sa_v3_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_v3_t_endian(&a->entry, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->seq_outbound = clib_net_to_host_u64(a->seq_outbound);
    a->last_seq_inbound = clib_net_to_host_u64(a->last_seq_inbound);
    a->replay_window = clib_net_to_host_u64(a->replay_window);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sa_v4_details_t_endian (vl_api_ipsec_sa_v4_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_v3_t_endian(&a->entry, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->seq_outbound = clib_net_to_host_u64(a->seq_outbound);
    a->last_seq_inbound = clib_net_to_host_u64(a->last_seq_inbound);
    a->replay_window = clib_net_to_host_u64(a->replay_window);
    a->thread_index = clib_net_to_host_u32(a->thread_index);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_sa_v5_details_t_endian (vl_api_ipsec_sa_v5_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_sad_entry_v4_t_endian(&a->entry, to_net);
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    a->seq_outbound = clib_net_to_host_u64(a->seq_outbound);
    a->last_seq_inbound = clib_net_to_host_u64(a->last_seq_inbound);
    a->replay_window = clib_net_to_host_u64(a->replay_window);
    a->thread_index = clib_net_to_host_u32(a->thread_index);
    a->stat_index = clib_net_to_host_u32(a->stat_index);
}

static inline void vl_api_ipsec_backend_dump_t_endian (vl_api_ipsec_backend_dump_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
}

static inline void vl_api_ipsec_backend_details_t_endian (vl_api_ipsec_backend_details_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    /* a->name = a->name (no-op) */
    vl_api_ipsec_proto_t_endian(&a->protocol, to_net);
    /* a->index = a->index (no-op) */
    /* a->active = a->active (no-op) */
}

static inline void vl_api_ipsec_select_backend_t_endian (vl_api_ipsec_select_backend_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    vl_api_ipsec_proto_t_endian(&a->protocol, to_net);
    /* a->index = a->index (no-op) */
}

static inline void vl_api_ipsec_select_backend_reply_t_endian (vl_api_ipsec_select_backend_reply_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->retval = clib_net_to_host_i32(a->retval);
}

static inline void vl_api_ipsec_set_async_mode_t_endian (vl_api_ipsec_set_async_mode_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    /* a->client_index = a->client_index (no-op) */
    a->context = clib_net_to_host_u32(a->context);
    /* a->async_enable = a->async_enable (no-op) */
}

static inline void vl_api_ipsec_set_async_mode_reply_t_endian (vl_api_ipsec_set_async_mode_reply_t *a, bool to_net)
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
#ifndef included_ipsec_calcsizefun
#define included_ipsec_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_t_calc_size (vl_api_ipsec_tunnel_protect_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->nh) + vl_api_address_t_calc_size(&a->nh) + a->n_sa_in * sizeof(a->sa_in[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_t_calc_size (vl_api_ipsec_itf_t *a)
{
      return sizeof(*a) - sizeof(a->mode) + vl_api_tunnel_mode_t_calc_size(&a->mode) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_add_del_t_calc_size (vl_api_ipsec_spd_add_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_add_del_reply_t_calc_size (vl_api_ipsec_spd_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_interface_add_del_spd_t_calc_size (vl_api_ipsec_interface_add_del_spd_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_interface_add_del_spd_reply_t_calc_size (vl_api_ipsec_interface_add_del_spd_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_entry_add_del_t_calc_size (vl_api_ipsec_spd_entry_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_spd_entry_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_entry_add_del_v2_t_calc_size (vl_api_ipsec_spd_entry_add_del_v2_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_spd_entry_v2_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_entry_add_del_reply_t_calc_size (vl_api_ipsec_spd_entry_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_entry_add_del_v2_reply_t_calc_size (vl_api_ipsec_spd_entry_add_del_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spds_dump_t_calc_size (vl_api_ipsec_spds_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spds_details_t_calc_size (vl_api_ipsec_spds_details_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_dump_t_calc_size (vl_api_ipsec_spd_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_details_t_calc_size (vl_api_ipsec_spd_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_spd_entry_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_del_t_calc_size (vl_api_ipsec_sad_entry_add_del_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_del_v2_t_calc_size (vl_api_ipsec_sad_entry_add_del_v2_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v2_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_del_v3_t_calc_size (vl_api_ipsec_sad_entry_add_del_v3_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v3_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_t_calc_size (vl_api_ipsec_sad_entry_add_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v3_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_v2_t_calc_size (vl_api_ipsec_sad_entry_add_v2_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v4_t_calc_size(&a->entry);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_del_t_calc_size (vl_api_ipsec_sad_entry_del_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_del_reply_t_calc_size (vl_api_ipsec_sad_entry_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_bind_t_calc_size (vl_api_ipsec_sad_bind_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_bind_reply_t_calc_size (vl_api_ipsec_sad_bind_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_unbind_t_calc_size (vl_api_ipsec_sad_unbind_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_unbind_reply_t_calc_size (vl_api_ipsec_sad_unbind_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_update_t_calc_size (vl_api_ipsec_sad_entry_update_t *a)
{
      return sizeof(*a) - sizeof(a->tunnel) + vl_api_tunnel_t_calc_size(&a->tunnel);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_update_reply_t_calc_size (vl_api_ipsec_sad_entry_update_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_del_reply_t_calc_size (vl_api_ipsec_sad_entry_add_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_del_v2_reply_t_calc_size (vl_api_ipsec_sad_entry_add_del_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_del_v3_reply_t_calc_size (vl_api_ipsec_sad_entry_add_del_v3_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_reply_t_calc_size (vl_api_ipsec_sad_entry_add_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sad_entry_add_v2_reply_t_calc_size (vl_api_ipsec_sad_entry_add_v2_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_update_t_calc_size (vl_api_ipsec_tunnel_protect_update_t *a)
{
      return sizeof(*a) - sizeof(a->tunnel) + vl_api_ipsec_tunnel_protect_t_calc_size(&a->tunnel);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_update_reply_t_calc_size (vl_api_ipsec_tunnel_protect_update_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_del_t_calc_size (vl_api_ipsec_tunnel_protect_del_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->nh) + vl_api_address_t_calc_size(&a->nh);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_del_reply_t_calc_size (vl_api_ipsec_tunnel_protect_del_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_dump_t_calc_size (vl_api_ipsec_tunnel_protect_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_tunnel_protect_details_t_calc_size (vl_api_ipsec_tunnel_protect_details_t *a)
{
      return sizeof(*a) - sizeof(a->tun) + vl_api_ipsec_tunnel_protect_t_calc_size(&a->tun);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_interface_dump_t_calc_size (vl_api_ipsec_spd_interface_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_spd_interface_details_t_calc_size (vl_api_ipsec_spd_interface_details_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_create_t_calc_size (vl_api_ipsec_itf_create_t *a)
{
      return sizeof(*a) - sizeof(a->itf) + vl_api_ipsec_itf_t_calc_size(&a->itf);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_create_reply_t_calc_size (vl_api_ipsec_itf_create_reply_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_delete_t_calc_size (vl_api_ipsec_itf_delete_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_delete_reply_t_calc_size (vl_api_ipsec_itf_delete_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_dump_t_calc_size (vl_api_ipsec_itf_dump_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_itf_details_t_calc_size (vl_api_ipsec_itf_details_t *a)
{
      return sizeof(*a) - sizeof(a->itf) + vl_api_ipsec_itf_t_calc_size(&a->itf);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_dump_t_calc_size (vl_api_ipsec_sa_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v2_dump_t_calc_size (vl_api_ipsec_sa_v2_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v3_dump_t_calc_size (vl_api_ipsec_sa_v3_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v4_dump_t_calc_size (vl_api_ipsec_sa_v4_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v5_dump_t_calc_size (vl_api_ipsec_sa_v5_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_details_t_calc_size (vl_api_ipsec_sa_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_t_calc_size(&a->entry) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v2_details_t_calc_size (vl_api_ipsec_sa_v2_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v2_t_calc_size(&a->entry) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v3_details_t_calc_size (vl_api_ipsec_sa_v3_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v3_t_calc_size(&a->entry) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v4_details_t_calc_size (vl_api_ipsec_sa_v4_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v3_t_calc_size(&a->entry) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_sa_v5_details_t_calc_size (vl_api_ipsec_sa_v5_details_t *a)
{
      return sizeof(*a) - sizeof(a->entry) + vl_api_ipsec_sad_entry_v4_t_calc_size(&a->entry) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_backend_dump_t_calc_size (vl_api_ipsec_backend_dump_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_backend_details_t_calc_size (vl_api_ipsec_backend_details_t *a)
{
      return sizeof(*a) - sizeof(a->protocol) + vl_api_ipsec_proto_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_select_backend_t_calc_size (vl_api_ipsec_select_backend_t *a)
{
      return sizeof(*a) - sizeof(a->protocol) + vl_api_ipsec_proto_t_calc_size(&a->protocol);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_select_backend_reply_t_calc_size (vl_api_ipsec_select_backend_reply_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_set_async_mode_t_calc_size (vl_api_ipsec_set_async_mode_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ipsec_set_async_mode_reply_t_calc_size (vl_api_ipsec_set_async_mode_reply_t *a)
{
      return sizeof(*a);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ipsec.api, 5, 0, 2)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ipsec.api, 0xb648c199)

#endif

