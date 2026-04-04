/*
 * VLIB API definitions 2026-04-04 08:31:59
 * Input file: ikev2_types.api
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
#warning no content included from ikev2_types.api
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
#endif
/****** Message names ******/

#ifdef vl_msg_name
#endif
/****** Message name, crc list ******/

#ifdef vl_msg_name_crc_list
#define foreach_vl_msg_name_crc_ikev2_types 
#endif
/****** Typedefs ******/

#ifdef vl_typedefs
#include "ikev2_types.api_types.h"
#endif
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ikev2_types_printfun_types
#define included_ikev2_types_printfun_types

static inline u8 *format_vl_api_ikev2_id_t (u8 *s, va_list * args)
{
    vl_api_ikev2_id_t *a = va_arg (*args, vl_api_ikev2_id_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utype: %u", format_white_space, indent, a->type);
    s = format(s, "\n%Udata_len: %u", format_white_space, indent, a->data_len);
    s = format(s, "\n%Udata: %s", format_white_space, indent, a->data);
    return s;
}

static inline u8 *format_vl_api_ikev2_ts_t (u8 *s, va_list * args)
{
    vl_api_ikev2_ts_t *a = va_arg (*args, vl_api_ikev2_ts_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usa_index: %u", format_white_space, indent, a->sa_index);
    s = format(s, "\n%Uchild_sa_index: %u", format_white_space, indent, a->child_sa_index);
    s = format(s, "\n%Uis_local: %u", format_white_space, indent, a->is_local);
    s = format(s, "\n%Uprotocol_id: %u", format_white_space, indent, a->protocol_id);
    s = format(s, "\n%Ustart_port: %u", format_white_space, indent, a->start_port);
    s = format(s, "\n%Uend_port: %u", format_white_space, indent, a->end_port);
    s = format(s, "\n%Ustart_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->start_addr, indent);
    s = format(s, "\n%Uend_addr: %U", format_white_space, indent, format_vl_api_address_t, &a->end_addr, indent);
    return s;
}

static inline u8 *format_vl_api_ikev2_auth_t (u8 *s, va_list * args)
{
    vl_api_ikev2_auth_t *a = va_arg (*args, vl_api_ikev2_auth_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Umethod: %u", format_white_space, indent, a->method);
    s = format(s, "\n%Uhex: %u", format_white_space, indent, a->hex);
    s = format(s, "\n%Udata_len: %u", format_white_space, indent, a->data_len);
    s = format(s, "\n%Udata: %U", format_white_space, indent, format_hex_bytes, a->data, a->data_len);
    return s;
}

static inline u8 *format_vl_api_ikev2_responder_t (u8 *s, va_list * args)
{
    vl_api_ikev2_responder_t *a = va_arg (*args, vl_api_ikev2_responder_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usw_if_index: %U", format_white_space, indent, format_vl_api_interface_index_t, &a->sw_if_index, indent);
    s = format(s, "\n%Uaddr: %U", format_white_space, indent, format_vl_api_address_t, &a->addr, indent);
    return s;
}

static inline u8 *format_vl_api_ikev2_ike_transforms_t (u8 *s, va_list * args)
{
    vl_api_ikev2_ike_transforms_t *a = va_arg (*args, vl_api_ikev2_ike_transforms_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ucrypto_alg: %u", format_white_space, indent, a->crypto_alg);
    s = format(s, "\n%Ucrypto_key_size: %u", format_white_space, indent, a->crypto_key_size);
    s = format(s, "\n%Uinteg_alg: %u", format_white_space, indent, a->integ_alg);
    s = format(s, "\n%Udh_group: %u", format_white_space, indent, a->dh_group);
    return s;
}

static inline u8 *format_vl_api_ikev2_esp_transforms_t (u8 *s, va_list * args)
{
    vl_api_ikev2_esp_transforms_t *a = va_arg (*args, vl_api_ikev2_esp_transforms_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Ucrypto_alg: %u", format_white_space, indent, a->crypto_alg);
    s = format(s, "\n%Ucrypto_key_size: %u", format_white_space, indent, a->crypto_key_size);
    s = format(s, "\n%Uinteg_alg: %u", format_white_space, indent, a->integ_alg);
    return s;
}

static inline u8 *format_vl_api_ikev2_profile_t (u8 *s, va_list * args)
{
    vl_api_ikev2_profile_t *a = va_arg (*args, vl_api_ikev2_profile_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Uname: %s", format_white_space, indent, a->name);
    s = format(s, "\n%Uloc_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->loc_id, indent);
    s = format(s, "\n%Urem_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->rem_id, indent);
    s = format(s, "\n%Uloc_ts: %U", format_white_space, indent, format_vl_api_ikev2_ts_t, &a->loc_ts, indent);
    s = format(s, "\n%Urem_ts: %U", format_white_space, indent, format_vl_api_ikev2_ts_t, &a->rem_ts, indent);
    s = format(s, "\n%Uresponder: %U", format_white_space, indent, format_vl_api_ikev2_responder_t, &a->responder, indent);
    s = format(s, "\n%Uike_ts: %U", format_white_space, indent, format_vl_api_ikev2_ike_transforms_t, &a->ike_ts, indent);
    s = format(s, "\n%Uesp_ts: %U", format_white_space, indent, format_vl_api_ikev2_esp_transforms_t, &a->esp_ts, indent);
    s = format(s, "\n%Ulifetime: %llu", format_white_space, indent, a->lifetime);
    s = format(s, "\n%Ulifetime_maxdata: %llu", format_white_space, indent, a->lifetime_maxdata);
    s = format(s, "\n%Ulifetime_jitter: %u", format_white_space, indent, a->lifetime_jitter);
    s = format(s, "\n%Uhandover: %u", format_white_space, indent, a->handover);
    s = format(s, "\n%Uipsec_over_udp_port: %u", format_white_space, indent, a->ipsec_over_udp_port);
    s = format(s, "\n%Utun_itf: %u", format_white_space, indent, a->tun_itf);
    s = format(s, "\n%Uudp_encap: %u", format_white_space, indent, a->udp_encap);
    s = format(s, "\n%Unatt_disabled: %u", format_white_space, indent, a->natt_disabled);
    s = format(s, "\n%Uauth: %U", format_white_space, indent, format_vl_api_ikev2_auth_t, &a->auth, indent);
    return s;
}

static inline u8 *format_vl_api_ikev2_sa_transform_t (u8 *s, va_list * args)
{
    vl_api_ikev2_sa_transform_t *a = va_arg (*args, vl_api_ikev2_sa_transform_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Utransform_type: %u", format_white_space, indent, a->transform_type);
    s = format(s, "\n%Utransform_id: %u", format_white_space, indent, a->transform_id);
    s = format(s, "\n%Ukey_len: %u", format_white_space, indent, a->key_len);
    s = format(s, "\n%Ukey_trunc: %u", format_white_space, indent, a->key_trunc);
    s = format(s, "\n%Ublock_size: %u", format_white_space, indent, a->block_size);
    s = format(s, "\n%Udh_group: %u", format_white_space, indent, a->dh_group);
    return s;
}

static inline u8 *format_vl_api_ikev2_keys_t (u8 *s, va_list * args)
{
    vl_api_ikev2_keys_t *a = va_arg (*args, vl_api_ikev2_keys_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usk_d: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_d_len: %u", format_white_space, indent, a->sk_d_len);
    s = format(s, "\n%Usk_ai: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_ai_len: %u", format_white_space, indent, a->sk_ai_len);
    s = format(s, "\n%Usk_ar: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_ar_len: %u", format_white_space, indent, a->sk_ar_len);
    s = format(s, "\n%Usk_ei: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_ei_len: %u", format_white_space, indent, a->sk_ei_len);
    s = format(s, "\n%Usk_er: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_er_len: %u", format_white_space, indent, a->sk_er_len);
    s = format(s, "\n%Usk_pi: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_pi_len: %u", format_white_space, indent, a->sk_pi_len);
    s = format(s, "\n%Usk_pr: %U", format_white_space, indent, format_hex_bytes, a, 64);
    s = format(s, "\n%Usk_pr_len: %u", format_white_space, indent, a->sk_pr_len);
    return s;
}

static inline u8 *format_vl_api_ikev2_child_sa_t (u8 *s, va_list * args)
{
    vl_api_ikev2_child_sa_t *a = va_arg (*args, vl_api_ikev2_child_sa_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usa_index: %u", format_white_space, indent, a->sa_index);
    s = format(s, "\n%Uchild_sa_index: %u", format_white_space, indent, a->child_sa_index);
    s = format(s, "\n%Ui_spi: %u", format_white_space, indent, a->i_spi);
    s = format(s, "\n%Ur_spi: %u", format_white_space, indent, a->r_spi);
    s = format(s, "\n%Ukeys: %U", format_white_space, indent, format_vl_api_ikev2_keys_t, &a->keys, indent);
    s = format(s, "\n%Uencryption: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->encryption, indent);
    s = format(s, "\n%Uintegrity: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->integrity, indent);
    s = format(s, "\n%Uesn: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->esn, indent);
    return s;
}

static inline u8 *format_vl_api_ikev2_child_sa_v2_t (u8 *s, va_list * args)
{
    vl_api_ikev2_child_sa_v2_t *a = va_arg (*args, vl_api_ikev2_child_sa_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usa_index: %u", format_white_space, indent, a->sa_index);
    s = format(s, "\n%Uchild_sa_index: %u", format_white_space, indent, a->child_sa_index);
    s = format(s, "\n%Ui_spi: %u", format_white_space, indent, a->i_spi);
    s = format(s, "\n%Ur_spi: %u", format_white_space, indent, a->r_spi);
    s = format(s, "\n%Ukeys: %U", format_white_space, indent, format_vl_api_ikev2_keys_t, &a->keys, indent);
    s = format(s, "\n%Uencryption: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->encryption, indent);
    s = format(s, "\n%Uintegrity: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->integrity, indent);
    s = format(s, "\n%Uesn: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->esn, indent);
    s = format(s, "\n%Uuptime: %.2f", format_white_space, indent, a->uptime);
    return s;
}

static inline u8 *format_vl_api_ikev2_sa_stats_t (u8 *s, va_list * args)
{
    vl_api_ikev2_sa_stats_t *a = va_arg (*args, vl_api_ikev2_sa_stats_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Un_keepalives: %u", format_white_space, indent, a->n_keepalives);
    s = format(s, "\n%Un_rekey_req: %u", format_white_space, indent, a->n_rekey_req);
    s = format(s, "\n%Un_sa_init_req: %u", format_white_space, indent, a->n_sa_init_req);
    s = format(s, "\n%Un_sa_auth_req: %u", format_white_space, indent, a->n_sa_auth_req);
    s = format(s, "\n%Un_retransmit: %u", format_white_space, indent, a->n_retransmit);
    s = format(s, "\n%Un_init_sa_retransmit: %u", format_white_space, indent, a->n_init_sa_retransmit);
    return s;
}

static inline u8 *format_vl_api_ikev2_state_t (u8 *s, va_list * args)
{
    vl_api_ikev2_state_t *a = va_arg (*args, vl_api_ikev2_state_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    switch(*a) {
    case 0:
        return format(s, "UNKNOWN");
    case 1:
        return format(s, "SA_INIT");
    case 2:
        return format(s, "DELETED");
    case 3:
        return format(s, "AUTH_FAILED");
    case 4:
        return format(s, "AUTHENTICATED");
    case 5:
        return format(s, "NOTIFY_AND_DELETE");
    case 6:
        return format(s, "TS_UNACCEPTABLE");
    case 7:
        return format(s, "NO_PROPOSAL_CHOSEN");
    }
    return s;
}

static inline u8 *format_vl_api_ikev2_sa_t (u8 *s, va_list * args)
{
    vl_api_ikev2_sa_t *a = va_arg (*args, vl_api_ikev2_sa_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usa_index: %u", format_white_space, indent, a->sa_index);
    s = format(s, "\n%Uprofile_index: %u", format_white_space, indent, a->profile_index);
    s = format(s, "\n%Uispi: %llu", format_white_space, indent, a->ispi);
    s = format(s, "\n%Urspi: %llu", format_white_space, indent, a->rspi);
    s = format(s, "\n%Uiaddr: %U", format_white_space, indent, format_vl_api_address_t, &a->iaddr, indent);
    s = format(s, "\n%Uraddr: %U", format_white_space, indent, format_vl_api_address_t, &a->raddr, indent);
    s = format(s, "\n%Ukeys: %U", format_white_space, indent, format_vl_api_ikev2_keys_t, &a->keys, indent);
    s = format(s, "\n%Ui_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->i_id, indent);
    s = format(s, "\n%Ur_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->r_id, indent);
    s = format(s, "\n%Uencryption: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->encryption, indent);
    s = format(s, "\n%Uintegrity: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->integrity, indent);
    s = format(s, "\n%Uprf: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->prf, indent);
    s = format(s, "\n%Udh: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->dh, indent);
    s = format(s, "\n%Ustats: %U", format_white_space, indent, format_vl_api_ikev2_sa_stats_t, &a->stats, indent);
    return s;
}

static inline u8 *format_vl_api_ikev2_sa_v2_t (u8 *s, va_list * args)
{
    vl_api_ikev2_sa_v2_t *a = va_arg (*args, vl_api_ikev2_sa_v2_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usa_index: %u", format_white_space, indent, a->sa_index);
    s = format(s, "\n%Uprofile_name: %s", format_white_space, indent, a->profile_name);
    s = format(s, "\n%Ustate: %U", format_white_space, indent, format_vl_api_ikev2_state_t, &a->state, indent);
    s = format(s, "\n%Uispi: %llu", format_white_space, indent, a->ispi);
    s = format(s, "\n%Urspi: %llu", format_white_space, indent, a->rspi);
    s = format(s, "\n%Uiaddr: %U", format_white_space, indent, format_vl_api_address_t, &a->iaddr, indent);
    s = format(s, "\n%Uraddr: %U", format_white_space, indent, format_vl_api_address_t, &a->raddr, indent);
    s = format(s, "\n%Ukeys: %U", format_white_space, indent, format_vl_api_ikev2_keys_t, &a->keys, indent);
    s = format(s, "\n%Ui_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->i_id, indent);
    s = format(s, "\n%Ur_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->r_id, indent);
    s = format(s, "\n%Uencryption: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->encryption, indent);
    s = format(s, "\n%Uintegrity: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->integrity, indent);
    s = format(s, "\n%Uprf: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->prf, indent);
    s = format(s, "\n%Udh: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->dh, indent);
    s = format(s, "\n%Ustats: %U", format_white_space, indent, format_vl_api_ikev2_sa_stats_t, &a->stats, indent);
    return s;
}

static inline u8 *format_vl_api_ikev2_sa_v3_t (u8 *s, va_list * args)
{
    vl_api_ikev2_sa_v3_t *a = va_arg (*args, vl_api_ikev2_sa_v3_t *);
    u32 indent __attribute__((unused)) = va_arg (*args, u32);
    int i __attribute__((unused));
    indent += 2;
    s = format(s, "\n%Usa_index: %u", format_white_space, indent, a->sa_index);
    s = format(s, "\n%Uprofile_name: %s", format_white_space, indent, a->profile_name);
    s = format(s, "\n%Ustate: %U", format_white_space, indent, format_vl_api_ikev2_state_t, &a->state, indent);
    s = format(s, "\n%Uispi: %llu", format_white_space, indent, a->ispi);
    s = format(s, "\n%Urspi: %llu", format_white_space, indent, a->rspi);
    s = format(s, "\n%Uiaddr: %U", format_white_space, indent, format_vl_api_address_t, &a->iaddr, indent);
    s = format(s, "\n%Uraddr: %U", format_white_space, indent, format_vl_api_address_t, &a->raddr, indent);
    s = format(s, "\n%Ukeys: %U", format_white_space, indent, format_vl_api_ikev2_keys_t, &a->keys, indent);
    s = format(s, "\n%Ui_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->i_id, indent);
    s = format(s, "\n%Ur_id: %U", format_white_space, indent, format_vl_api_ikev2_id_t, &a->r_id, indent);
    s = format(s, "\n%Uencryption: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->encryption, indent);
    s = format(s, "\n%Uintegrity: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->integrity, indent);
    s = format(s, "\n%Uprf: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->prf, indent);
    s = format(s, "\n%Udh: %U", format_white_space, indent, format_vl_api_ikev2_sa_transform_t, &a->dh, indent);
    s = format(s, "\n%Ustats: %U", format_white_space, indent, format_vl_api_ikev2_sa_stats_t, &a->stats, indent);
    s = format(s, "\n%Uuptime: %.2f", format_white_space, indent, a->uptime);
    return s;
}


#endif
#endif /* vl_printfun_types */
/****** Print functions *****/
#ifdef vl_printfun
#ifndef included_ikev2_types_printfun
#define included_ikev2_types_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

#include "ikev2_types.api_tojson.h"
#include "ikev2_types.api_fromjson.h"


#endif
#endif /* vl_printfun */

/****** Endian swap functions *****/
#ifdef vl_endianfun
#ifndef included_ikev2_types_endianfun
#define included_ikev2_types_endianfun

#undef clib_net_to_host_uword
#undef clib_host_to_net_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#define clib_host_to_net_uword clib_host_to_net_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#define clib_host_to_net_uword clib_host_to_net_u32
#endif

static inline void vl_api_ikev2_id_t_endian (vl_api_ikev2_id_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->type = a->type (no-op) */
    /* a->data_len = a->data_len (no-op) */
    /* a->data = a->data (no-op) */
}

static inline void vl_api_ikev2_ts_t_endian (vl_api_ikev2_ts_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sa_index = clib_net_to_host_u32(a->sa_index);
    a->child_sa_index = clib_net_to_host_u32(a->child_sa_index);
    /* a->is_local = a->is_local (no-op) */
    /* a->protocol_id = a->protocol_id (no-op) */
    a->start_port = clib_net_to_host_u16(a->start_port);
    a->end_port = clib_net_to_host_u16(a->end_port);
    vl_api_address_t_endian(&a->start_addr, to_net);
    vl_api_address_t_endian(&a->end_addr, to_net);
}

static inline void vl_api_ikev2_auth_t_endian (vl_api_ikev2_auth_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->method = a->method (no-op) */
    /* a->hex = a->hex (no-op) */
    a->data_len = clib_net_to_host_u32(a->data_len);
    /* a->data = a->data (no-op) */
}

static inline void vl_api_ikev2_responder_t_endian (vl_api_ikev2_responder_t *a, bool to_net)
{
    int i __attribute__((unused));
    vl_api_interface_index_t_endian(&a->sw_if_index, to_net);
    vl_api_address_t_endian(&a->addr, to_net);
}

static inline void vl_api_ikev2_ike_transforms_t_endian (vl_api_ikev2_ike_transforms_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->crypto_alg = a->crypto_alg (no-op) */
    a->crypto_key_size = clib_net_to_host_u32(a->crypto_key_size);
    /* a->integ_alg = a->integ_alg (no-op) */
    /* a->dh_group = a->dh_group (no-op) */
}

static inline void vl_api_ikev2_esp_transforms_t_endian (vl_api_ikev2_esp_transforms_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->crypto_alg = a->crypto_alg (no-op) */
    a->crypto_key_size = clib_net_to_host_u32(a->crypto_key_size);
    /* a->integ_alg = a->integ_alg (no-op) */
}

static inline void vl_api_ikev2_profile_t_endian (vl_api_ikev2_profile_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->name = a->name (no-op) */
    vl_api_ikev2_id_t_endian(&a->loc_id, to_net);
    vl_api_ikev2_id_t_endian(&a->rem_id, to_net);
    vl_api_ikev2_ts_t_endian(&a->loc_ts, to_net);
    vl_api_ikev2_ts_t_endian(&a->rem_ts, to_net);
    vl_api_ikev2_responder_t_endian(&a->responder, to_net);
    vl_api_ikev2_ike_transforms_t_endian(&a->ike_ts, to_net);
    vl_api_ikev2_esp_transforms_t_endian(&a->esp_ts, to_net);
    a->lifetime = clib_net_to_host_u64(a->lifetime);
    a->lifetime_maxdata = clib_net_to_host_u64(a->lifetime_maxdata);
    a->lifetime_jitter = clib_net_to_host_u32(a->lifetime_jitter);
    a->handover = clib_net_to_host_u32(a->handover);
    a->ipsec_over_udp_port = clib_net_to_host_u16(a->ipsec_over_udp_port);
    a->tun_itf = clib_net_to_host_u32(a->tun_itf);
    /* a->udp_encap = a->udp_encap (no-op) */
    /* a->natt_disabled = a->natt_disabled (no-op) */
    vl_api_ikev2_auth_t_endian(&a->auth, to_net);
}

static inline void vl_api_ikev2_sa_transform_t_endian (vl_api_ikev2_sa_transform_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->transform_type = a->transform_type (no-op) */
    a->transform_id = clib_net_to_host_u16(a->transform_id);
    a->key_len = clib_net_to_host_u16(a->key_len);
    a->key_trunc = clib_net_to_host_u16(a->key_trunc);
    a->block_size = clib_net_to_host_u16(a->block_size);
    /* a->dh_group = a->dh_group (no-op) */
}

static inline void vl_api_ikev2_keys_t_endian (vl_api_ikev2_keys_t *a, bool to_net)
{
    int i __attribute__((unused));
    /* a->sk_d = a->sk_d (no-op) */
    /* a->sk_d_len = a->sk_d_len (no-op) */
    /* a->sk_ai = a->sk_ai (no-op) */
    /* a->sk_ai_len = a->sk_ai_len (no-op) */
    /* a->sk_ar = a->sk_ar (no-op) */
    /* a->sk_ar_len = a->sk_ar_len (no-op) */
    /* a->sk_ei = a->sk_ei (no-op) */
    /* a->sk_ei_len = a->sk_ei_len (no-op) */
    /* a->sk_er = a->sk_er (no-op) */
    /* a->sk_er_len = a->sk_er_len (no-op) */
    /* a->sk_pi = a->sk_pi (no-op) */
    /* a->sk_pi_len = a->sk_pi_len (no-op) */
    /* a->sk_pr = a->sk_pr (no-op) */
    /* a->sk_pr_len = a->sk_pr_len (no-op) */
}

static inline void vl_api_ikev2_child_sa_t_endian (vl_api_ikev2_child_sa_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sa_index = clib_net_to_host_u32(a->sa_index);
    a->child_sa_index = clib_net_to_host_u32(a->child_sa_index);
    a->i_spi = clib_net_to_host_u32(a->i_spi);
    a->r_spi = clib_net_to_host_u32(a->r_spi);
    vl_api_ikev2_keys_t_endian(&a->keys, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->encryption, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->integrity, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->esn, to_net);
}

static inline void vl_api_ikev2_child_sa_v2_t_endian (vl_api_ikev2_child_sa_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sa_index = clib_net_to_host_u32(a->sa_index);
    a->child_sa_index = clib_net_to_host_u32(a->child_sa_index);
    a->i_spi = clib_net_to_host_u32(a->i_spi);
    a->r_spi = clib_net_to_host_u32(a->r_spi);
    vl_api_ikev2_keys_t_endian(&a->keys, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->encryption, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->integrity, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->esn, to_net);
    a->uptime = clib_net_to_host_f64(a->uptime);
}

static inline void vl_api_ikev2_sa_stats_t_endian (vl_api_ikev2_sa_stats_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->n_keepalives = clib_net_to_host_u16(a->n_keepalives);
    a->n_rekey_req = clib_net_to_host_u16(a->n_rekey_req);
    a->n_sa_init_req = clib_net_to_host_u16(a->n_sa_init_req);
    a->n_sa_auth_req = clib_net_to_host_u16(a->n_sa_auth_req);
    a->n_retransmit = clib_net_to_host_u16(a->n_retransmit);
    a->n_init_sa_retransmit = clib_net_to_host_u16(a->n_init_sa_retransmit);
}

static inline void vl_api_ikev2_state_t_endian (vl_api_ikev2_state_t *a, bool to_net)
{
    int i __attribute__((unused));
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_ikev2_sa_t_endian (vl_api_ikev2_sa_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sa_index = clib_net_to_host_u32(a->sa_index);
    a->profile_index = clib_net_to_host_u32(a->profile_index);
    a->ispi = clib_net_to_host_u64(a->ispi);
    a->rspi = clib_net_to_host_u64(a->rspi);
    vl_api_address_t_endian(&a->iaddr, to_net);
    vl_api_address_t_endian(&a->raddr, to_net);
    vl_api_ikev2_keys_t_endian(&a->keys, to_net);
    vl_api_ikev2_id_t_endian(&a->i_id, to_net);
    vl_api_ikev2_id_t_endian(&a->r_id, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->encryption, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->integrity, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->prf, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->dh, to_net);
    vl_api_ikev2_sa_stats_t_endian(&a->stats, to_net);
}

static inline void vl_api_ikev2_sa_v2_t_endian (vl_api_ikev2_sa_v2_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sa_index = clib_net_to_host_u32(a->sa_index);
    /* a->profile_name = a->profile_name (no-op) */
    vl_api_ikev2_state_t_endian(&a->state, to_net);
    a->ispi = clib_net_to_host_u64(a->ispi);
    a->rspi = clib_net_to_host_u64(a->rspi);
    vl_api_address_t_endian(&a->iaddr, to_net);
    vl_api_address_t_endian(&a->raddr, to_net);
    vl_api_ikev2_keys_t_endian(&a->keys, to_net);
    vl_api_ikev2_id_t_endian(&a->i_id, to_net);
    vl_api_ikev2_id_t_endian(&a->r_id, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->encryption, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->integrity, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->prf, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->dh, to_net);
    vl_api_ikev2_sa_stats_t_endian(&a->stats, to_net);
}

static inline void vl_api_ikev2_sa_v3_t_endian (vl_api_ikev2_sa_v3_t *a, bool to_net)
{
    int i __attribute__((unused));
    a->sa_index = clib_net_to_host_u32(a->sa_index);
    /* a->profile_name = a->profile_name (no-op) */
    vl_api_ikev2_state_t_endian(&a->state, to_net);
    a->ispi = clib_net_to_host_u64(a->ispi);
    a->rspi = clib_net_to_host_u64(a->rspi);
    vl_api_address_t_endian(&a->iaddr, to_net);
    vl_api_address_t_endian(&a->raddr, to_net);
    vl_api_ikev2_keys_t_endian(&a->keys, to_net);
    vl_api_ikev2_id_t_endian(&a->i_id, to_net);
    vl_api_ikev2_id_t_endian(&a->r_id, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->encryption, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->integrity, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->prf, to_net);
    vl_api_ikev2_sa_transform_t_endian(&a->dh, to_net);
    vl_api_ikev2_sa_stats_t_endian(&a->stats, to_net);
    a->uptime = clib_net_to_host_f64(a->uptime);
}


#endif
#endif /* vl_endianfun */


/****** Calculate size functions *****/
#ifdef vl_calcsizefun
#ifndef included_ikev2_types_calcsizefun
#define included_ikev2_types_calcsizefun

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_id_t_calc_size (vl_api_ikev2_id_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_ts_t_calc_size (vl_api_ikev2_ts_t *a)
{
      return sizeof(*a) - sizeof(a->start_addr) + vl_api_address_t_calc_size(&a->start_addr) - sizeof(a->end_addr) + vl_api_address_t_calc_size(&a->end_addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_auth_t_calc_size (vl_api_ikev2_auth_t *a)
{
      return sizeof(*a) + clib_net_to_host_u32(a->data_len) * sizeof(a->data[0]);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_responder_t_calc_size (vl_api_ikev2_responder_t *a)
{
      return sizeof(*a) - sizeof(a->sw_if_index) + vl_api_interface_index_t_calc_size(&a->sw_if_index) - sizeof(a->addr) + vl_api_address_t_calc_size(&a->addr);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_ike_transforms_t_calc_size (vl_api_ikev2_ike_transforms_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_esp_transforms_t_calc_size (vl_api_ikev2_esp_transforms_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_profile_t_calc_size (vl_api_ikev2_profile_t *a)
{
      return sizeof(*a) - sizeof(a->loc_id) + vl_api_ikev2_id_t_calc_size(&a->loc_id) - sizeof(a->rem_id) + vl_api_ikev2_id_t_calc_size(&a->rem_id) - sizeof(a->loc_ts) + vl_api_ikev2_ts_t_calc_size(&a->loc_ts) - sizeof(a->rem_ts) + vl_api_ikev2_ts_t_calc_size(&a->rem_ts) - sizeof(a->responder) + vl_api_ikev2_responder_t_calc_size(&a->responder) - sizeof(a->ike_ts) + vl_api_ikev2_ike_transforms_t_calc_size(&a->ike_ts) - sizeof(a->esp_ts) + vl_api_ikev2_esp_transforms_t_calc_size(&a->esp_ts) - sizeof(a->auth) + vl_api_ikev2_auth_t_calc_size(&a->auth);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_sa_transform_t_calc_size (vl_api_ikev2_sa_transform_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_keys_t_calc_size (vl_api_ikev2_keys_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_child_sa_t_calc_size (vl_api_ikev2_child_sa_t *a)
{
      return sizeof(*a) - sizeof(a->keys) + vl_api_ikev2_keys_t_calc_size(&a->keys) - sizeof(a->encryption) + vl_api_ikev2_sa_transform_t_calc_size(&a->encryption) - sizeof(a->integrity) + vl_api_ikev2_sa_transform_t_calc_size(&a->integrity) - sizeof(a->esn) + vl_api_ikev2_sa_transform_t_calc_size(&a->esn);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_child_sa_v2_t_calc_size (vl_api_ikev2_child_sa_v2_t *a)
{
      return sizeof(*a) - sizeof(a->keys) + vl_api_ikev2_keys_t_calc_size(&a->keys) - sizeof(a->encryption) + vl_api_ikev2_sa_transform_t_calc_size(&a->encryption) - sizeof(a->integrity) + vl_api_ikev2_sa_transform_t_calc_size(&a->integrity) - sizeof(a->esn) + vl_api_ikev2_sa_transform_t_calc_size(&a->esn);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_sa_stats_t_calc_size (vl_api_ikev2_sa_stats_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_state_t_calc_size (vl_api_ikev2_state_t *a)
{
      return sizeof(*a);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_sa_t_calc_size (vl_api_ikev2_sa_t *a)
{
      return sizeof(*a) - sizeof(a->iaddr) + vl_api_address_t_calc_size(&a->iaddr) - sizeof(a->raddr) + vl_api_address_t_calc_size(&a->raddr) - sizeof(a->keys) + vl_api_ikev2_keys_t_calc_size(&a->keys) - sizeof(a->i_id) + vl_api_ikev2_id_t_calc_size(&a->i_id) - sizeof(a->r_id) + vl_api_ikev2_id_t_calc_size(&a->r_id) - sizeof(a->encryption) + vl_api_ikev2_sa_transform_t_calc_size(&a->encryption) - sizeof(a->integrity) + vl_api_ikev2_sa_transform_t_calc_size(&a->integrity) - sizeof(a->prf) + vl_api_ikev2_sa_transform_t_calc_size(&a->prf) - sizeof(a->dh) + vl_api_ikev2_sa_transform_t_calc_size(&a->dh) - sizeof(a->stats) + vl_api_ikev2_sa_stats_t_calc_size(&a->stats);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_sa_v2_t_calc_size (vl_api_ikev2_sa_v2_t *a)
{
      return sizeof(*a) - sizeof(a->state) + vl_api_ikev2_state_t_calc_size(&a->state) - sizeof(a->iaddr) + vl_api_address_t_calc_size(&a->iaddr) - sizeof(a->raddr) + vl_api_address_t_calc_size(&a->raddr) - sizeof(a->keys) + vl_api_ikev2_keys_t_calc_size(&a->keys) - sizeof(a->i_id) + vl_api_ikev2_id_t_calc_size(&a->i_id) - sizeof(a->r_id) + vl_api_ikev2_id_t_calc_size(&a->r_id) - sizeof(a->encryption) + vl_api_ikev2_sa_transform_t_calc_size(&a->encryption) - sizeof(a->integrity) + vl_api_ikev2_sa_transform_t_calc_size(&a->integrity) - sizeof(a->prf) + vl_api_ikev2_sa_transform_t_calc_size(&a->prf) - sizeof(a->dh) + vl_api_ikev2_sa_transform_t_calc_size(&a->dh) - sizeof(a->stats) + vl_api_ikev2_sa_stats_t_calc_size(&a->stats);
}

/* calculate message size of message in network byte order */
static inline uword vl_api_ikev2_sa_v3_t_calc_size (vl_api_ikev2_sa_v3_t *a)
{
      return sizeof(*a) - sizeof(a->state) + vl_api_ikev2_state_t_calc_size(&a->state) - sizeof(a->iaddr) + vl_api_address_t_calc_size(&a->iaddr) - sizeof(a->raddr) + vl_api_address_t_calc_size(&a->raddr) - sizeof(a->keys) + vl_api_ikev2_keys_t_calc_size(&a->keys) - sizeof(a->i_id) + vl_api_ikev2_id_t_calc_size(&a->i_id) - sizeof(a->r_id) + vl_api_ikev2_id_t_calc_size(&a->r_id) - sizeof(a->encryption) + vl_api_ikev2_sa_transform_t_calc_size(&a->encryption) - sizeof(a->integrity) + vl_api_ikev2_sa_transform_t_calc_size(&a->integrity) - sizeof(a->prf) + vl_api_ikev2_sa_transform_t_calc_size(&a->prf) - sizeof(a->dh) + vl_api_ikev2_sa_transform_t_calc_size(&a->dh) - sizeof(a->stats) + vl_api_ikev2_sa_stats_t_calc_size(&a->stats);
}


#endif
#endif /* vl_calcsizefun */

/****** Version tuple *****/

#ifdef vl_api_version_tuple

vl_api_version_tuple(ikev2_types.api, 1, 0, 0)

#endif /* vl_api_version_tuple */

/****** API CRC (whole file) *****/

#ifdef vl_api_version
vl_api_version(ikev2_types.api, 0x642f5a57)

#endif

