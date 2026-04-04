/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_ikev2_types_api_fromjson_h
#define included_ikev2_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ikev2_id_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_id_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->type);

    item = cJSON_GetObjectItem(o, "data_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->data_len);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    strncpy_s((char *)a->data, sizeof(a->data), cJSON_GetStringValue(item), sizeof(a->data) - 1);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_ts_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_ts_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "child_sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->child_sa_index);

    item = cJSON_GetObjectItem(o, "is_local");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_local);

    item = cJSON_GetObjectItem(o, "protocol_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol_id);

    item = cJSON_GetObjectItem(o, "start_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->start_port);

    item = cJSON_GetObjectItem(o, "end_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->end_port);

    item = cJSON_GetObjectItem(o, "start_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->start_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "end_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->end_addr) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_auth_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_auth_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "method");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->method);

    item = cJSON_GetObjectItem(o, "hex");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->hex);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    s = u8string_fromjson(o, "data");
    if (!s) goto error;
    a->data_len = vec_len(s);
    *mp = cJSON_realloc(*mp, *len + vec_len(s));
    clib_memcpy((void *)*mp + *len, s, vec_len(s));
    *len += vec_len(s);
    vec_free(s);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_responder_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_responder_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->addr) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_ike_transforms_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_ike_transforms_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "crypto_alg");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->crypto_alg);

    item = cJSON_GetObjectItem(o, "crypto_key_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->crypto_key_size);

    item = cJSON_GetObjectItem(o, "integ_alg");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->integ_alg);

    item = cJSON_GetObjectItem(o, "dh_group");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dh_group);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_esp_transforms_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_esp_transforms_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "crypto_alg");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->crypto_alg);

    item = cJSON_GetObjectItem(o, "crypto_key_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->crypto_key_size);

    item = cJSON_GetObjectItem(o, "integ_alg");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->integ_alg);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_profile_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_profile_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    item = cJSON_GetObjectItem(o, "loc_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->loc_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rem_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->rem_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "loc_ts");
    if (!item) goto error;
    if (vl_api_ikev2_ts_t_fromjson(mp, len, item, &a->loc_ts) < 0) goto error;

    item = cJSON_GetObjectItem(o, "rem_ts");
    if (!item) goto error;
    if (vl_api_ikev2_ts_t_fromjson(mp, len, item, &a->rem_ts) < 0) goto error;

    item = cJSON_GetObjectItem(o, "responder");
    if (!item) goto error;
    if (vl_api_ikev2_responder_t_fromjson(mp, len, item, &a->responder) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ike_ts");
    if (!item) goto error;
    if (vl_api_ikev2_ike_transforms_t_fromjson(mp, len, item, &a->ike_ts) < 0) goto error;

    item = cJSON_GetObjectItem(o, "esp_ts");
    if (!item) goto error;
    if (vl_api_ikev2_esp_transforms_t_fromjson(mp, len, item, &a->esp_ts) < 0) goto error;

    item = cJSON_GetObjectItem(o, "lifetime");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->lifetime);

    item = cJSON_GetObjectItem(o, "lifetime_maxdata");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->lifetime_maxdata);

    item = cJSON_GetObjectItem(o, "lifetime_jitter");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->lifetime_jitter);

    item = cJSON_GetObjectItem(o, "handover");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->handover);

    item = cJSON_GetObjectItem(o, "ipsec_over_udp_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ipsec_over_udp_port);

    item = cJSON_GetObjectItem(o, "tun_itf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tun_itf);

    item = cJSON_GetObjectItem(o, "udp_encap");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->udp_encap);

    item = cJSON_GetObjectItem(o, "natt_disabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->natt_disabled);

    item = cJSON_GetObjectItem(o, "auth");
    if (!item) goto error;
    if (vl_api_ikev2_auth_t_fromjson(mp, len, item, &a->auth) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_sa_transform_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_sa_transform_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "transform_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->transform_type);

    item = cJSON_GetObjectItem(o, "transform_id");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->transform_id);

    item = cJSON_GetObjectItem(o, "key_len");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->key_len);

    item = cJSON_GetObjectItem(o, "key_trunc");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->key_trunc);

    item = cJSON_GetObjectItem(o, "block_size");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->block_size);

    item = cJSON_GetObjectItem(o, "dh_group");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->dh_group);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_keys_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_keys_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sk_d");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_d", a->sk_d) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_d_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_d_len);

    item = cJSON_GetObjectItem(o, "sk_ai");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_ai", a->sk_ai) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_ai_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_ai_len);

    item = cJSON_GetObjectItem(o, "sk_ar");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_ar", a->sk_ar) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_ar_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_ar_len);

    item = cJSON_GetObjectItem(o, "sk_ei");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_ei", a->sk_ei) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_ei_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_ei_len);

    item = cJSON_GetObjectItem(o, "sk_er");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_er", a->sk_er) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_er_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_er_len);

    item = cJSON_GetObjectItem(o, "sk_pi");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_pi", a->sk_pi) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_pi_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_pi_len);

    item = cJSON_GetObjectItem(o, "sk_pr");
    if (!item) goto error;
    if (u8string_fromjson2(o, "sk_pr", a->sk_pr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sk_pr_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->sk_pr_len);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_child_sa_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_child_sa_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "child_sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->child_sa_index);

    item = cJSON_GetObjectItem(o, "i_spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->i_spi);

    item = cJSON_GetObjectItem(o, "r_spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->r_spi);

    item = cJSON_GetObjectItem(o, "keys");
    if (!item) goto error;
    if (vl_api_ikev2_keys_t_fromjson(mp, len, item, &a->keys) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encryption");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->encryption) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->integrity) < 0) goto error;

    item = cJSON_GetObjectItem(o, "esn");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->esn) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_child_sa_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_child_sa_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "child_sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->child_sa_index);

    item = cJSON_GetObjectItem(o, "i_spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->i_spi);

    item = cJSON_GetObjectItem(o, "r_spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->r_spi);

    item = cJSON_GetObjectItem(o, "keys");
    if (!item) goto error;
    if (vl_api_ikev2_keys_t_fromjson(mp, len, item, &a->keys) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encryption");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->encryption) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->integrity) < 0) goto error;

    item = cJSON_GetObjectItem(o, "esn");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->esn) < 0) goto error;

    item = cJSON_GetObjectItem(o, "uptime");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->uptime);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_sa_stats_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_sa_stats_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "n_keepalives");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->n_keepalives);

    item = cJSON_GetObjectItem(o, "n_rekey_req");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->n_rekey_req);

    item = cJSON_GetObjectItem(o, "n_sa_init_req");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->n_sa_init_req);

    item = cJSON_GetObjectItem(o, "n_sa_auth_req");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->n_sa_auth_req);

    item = cJSON_GetObjectItem(o, "n_retransmit");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->n_retransmit);

    item = cJSON_GetObjectItem(o, "n_init_sa_retransmit");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->n_init_sa_retransmit);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_state_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ikev2_state_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "UNKNOWN") == 0) {*a = 0; return 0;}
    if (strcmp(p, "SA_INIT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "DELETED") == 0) {*a = 2; return 0;}
    if (strcmp(p, "AUTH_FAILED") == 0) {*a = 3; return 0;}
    if (strcmp(p, "AUTHENTICATED") == 0) {*a = 4; return 0;}
    if (strcmp(p, "NOTIFY_AND_DELETE") == 0) {*a = 5; return 0;}
    if (strcmp(p, "TS_UNACCEPTABLE") == 0) {*a = 6; return 0;}
    if (strcmp(p, "NO_PROPOSAL_CHOSEN") == 0) {*a = 7; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ikev2_sa_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_sa_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "profile_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->profile_index);

    item = cJSON_GetObjectItem(o, "ispi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->ispi);

    item = cJSON_GetObjectItem(o, "rspi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->rspi);

    item = cJSON_GetObjectItem(o, "iaddr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->iaddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "raddr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->raddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "keys");
    if (!item) goto error;
    if (vl_api_ikev2_keys_t_fromjson(mp, len, item, &a->keys) < 0) goto error;

    item = cJSON_GetObjectItem(o, "i_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->i_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "r_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->r_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encryption");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->encryption) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->integrity) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prf");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->prf) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dh");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->dh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "stats");
    if (!item) goto error;
    if (vl_api_ikev2_sa_stats_t_fromjson(mp, len, item, &a->stats) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_sa_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_sa_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "profile_name");
    if (!item) goto error;
    strncpy_s((char *)a->profile_name, sizeof(a->profile_name), cJSON_GetStringValue(item), sizeof(a->profile_name) - 1);

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_ikev2_state_t_fromjson(mp, len, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ispi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->ispi);

    item = cJSON_GetObjectItem(o, "rspi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->rspi);

    item = cJSON_GetObjectItem(o, "iaddr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->iaddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "raddr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->raddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "keys");
    if (!item) goto error;
    if (vl_api_ikev2_keys_t_fromjson(mp, len, item, &a->keys) < 0) goto error;

    item = cJSON_GetObjectItem(o, "i_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->i_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "r_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->r_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encryption");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->encryption) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->integrity) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prf");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->prf) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dh");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->dh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "stats");
    if (!item) goto error;
    if (vl_api_ikev2_sa_stats_t_fromjson(mp, len, item, &a->stats) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ikev2_sa_v3_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ikev2_sa_v3_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sa_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_index);

    item = cJSON_GetObjectItem(o, "profile_name");
    if (!item) goto error;
    strncpy_s((char *)a->profile_name, sizeof(a->profile_name), cJSON_GetStringValue(item), sizeof(a->profile_name) - 1);

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_ikev2_state_t_fromjson(mp, len, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ispi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->ispi);

    item = cJSON_GetObjectItem(o, "rspi");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->rspi);

    item = cJSON_GetObjectItem(o, "iaddr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->iaddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "raddr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->raddr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "keys");
    if (!item) goto error;
    if (vl_api_ikev2_keys_t_fromjson(mp, len, item, &a->keys) < 0) goto error;

    item = cJSON_GetObjectItem(o, "i_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->i_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "r_id");
    if (!item) goto error;
    if (vl_api_ikev2_id_t_fromjson(mp, len, item, &a->r_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "encryption");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->encryption) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->integrity) < 0) goto error;

    item = cJSON_GetObjectItem(o, "prf");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->prf) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dh");
    if (!item) goto error;
    if (vl_api_ikev2_sa_transform_t_fromjson(mp, len, item, &a->dh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "stats");
    if (!item) goto error;
    if (vl_api_ikev2_sa_stats_t_fromjson(mp, len, item, &a->stats) < 0) goto error;

    item = cJSON_GetObjectItem(o, "uptime");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->uptime);

    return 0;

  error:
    return -1;
}
#endif
