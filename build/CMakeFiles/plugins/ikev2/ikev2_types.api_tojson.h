/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_ikev2_types_api_tojson_h
#define included_ikev2_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ikev2_id_t_tojson (vl_api_ikev2_id_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "type", a->type);
    cJSON_AddNumberToObject(o, "data_len", a->data_len);
    cJSON_AddStringToObject(o, "data", (char *)a->data);
    return o;
}
static inline cJSON *vl_api_ikev2_ts_t_tojson (vl_api_ikev2_ts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddNumberToObject(o, "child_sa_index", a->child_sa_index);
    cJSON_AddBoolToObject(o, "is_local", a->is_local);
    cJSON_AddNumberToObject(o, "protocol_id", a->protocol_id);
    cJSON_AddNumberToObject(o, "start_port", a->start_port);
    cJSON_AddNumberToObject(o, "end_port", a->end_port);
    cJSON_AddItemToObject(o, "start_addr", vl_api_address_t_tojson(&a->start_addr));
    cJSON_AddItemToObject(o, "end_addr", vl_api_address_t_tojson(&a->end_addr));
    return o;
}
static inline cJSON *vl_api_ikev2_auth_t_tojson (vl_api_ikev2_auth_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "method", a->method);
    cJSON_AddNumberToObject(o, "hex", a->hex);
    cJSON_AddNumberToObject(o, "data_len", a->data_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->data, a->data_len);
    cJSON_AddStringToObject(o, "data", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ikev2_responder_t_tojson (vl_api_ikev2_responder_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "addr", vl_api_address_t_tojson(&a->addr));
    return o;
}
static inline cJSON *vl_api_ikev2_ike_transforms_t_tojson (vl_api_ikev2_ike_transforms_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "crypto_alg", a->crypto_alg);
    cJSON_AddNumberToObject(o, "crypto_key_size", a->crypto_key_size);
    cJSON_AddNumberToObject(o, "integ_alg", a->integ_alg);
    cJSON_AddNumberToObject(o, "dh_group", a->dh_group);
    return o;
}
static inline cJSON *vl_api_ikev2_esp_transforms_t_tojson (vl_api_ikev2_esp_transforms_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "crypto_alg", a->crypto_alg);
    cJSON_AddNumberToObject(o, "crypto_key_size", a->crypto_key_size);
    cJSON_AddNumberToObject(o, "integ_alg", a->integ_alg);
    return o;
}
static inline cJSON *vl_api_ikev2_profile_t_tojson (vl_api_ikev2_profile_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "loc_id", vl_api_ikev2_id_t_tojson(&a->loc_id));
    cJSON_AddItemToObject(o, "rem_id", vl_api_ikev2_id_t_tojson(&a->rem_id));
    cJSON_AddItemToObject(o, "loc_ts", vl_api_ikev2_ts_t_tojson(&a->loc_ts));
    cJSON_AddItemToObject(o, "rem_ts", vl_api_ikev2_ts_t_tojson(&a->rem_ts));
    cJSON_AddItemToObject(o, "responder", vl_api_ikev2_responder_t_tojson(&a->responder));
    cJSON_AddItemToObject(o, "ike_ts", vl_api_ikev2_ike_transforms_t_tojson(&a->ike_ts));
    cJSON_AddItemToObject(o, "esp_ts", vl_api_ikev2_esp_transforms_t_tojson(&a->esp_ts));
    cJSON_AddNumberToObject(o, "lifetime", a->lifetime);
    cJSON_AddNumberToObject(o, "lifetime_maxdata", a->lifetime_maxdata);
    cJSON_AddNumberToObject(o, "lifetime_jitter", a->lifetime_jitter);
    cJSON_AddNumberToObject(o, "handover", a->handover);
    cJSON_AddNumberToObject(o, "ipsec_over_udp_port", a->ipsec_over_udp_port);
    cJSON_AddNumberToObject(o, "tun_itf", a->tun_itf);
    cJSON_AddBoolToObject(o, "udp_encap", a->udp_encap);
    cJSON_AddBoolToObject(o, "natt_disabled", a->natt_disabled);
    cJSON_AddItemToObject(o, "auth", vl_api_ikev2_auth_t_tojson(&a->auth));
    return o;
}
static inline cJSON *vl_api_ikev2_sa_transform_t_tojson (vl_api_ikev2_sa_transform_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "transform_type", a->transform_type);
    cJSON_AddNumberToObject(o, "transform_id", a->transform_id);
    cJSON_AddNumberToObject(o, "key_len", a->key_len);
    cJSON_AddNumberToObject(o, "key_trunc", a->key_trunc);
    cJSON_AddNumberToObject(o, "block_size", a->block_size);
    cJSON_AddNumberToObject(o, "dh_group", a->dh_group);
    return o;
}
static inline cJSON *vl_api_ikev2_keys_t_tojson (vl_api_ikev2_keys_t *a) {
    cJSON *o = cJSON_CreateObject();
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_d, 64);
    cJSON_AddStringToObject(o, "sk_d", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_d_len", a->sk_d_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_ai, 64);
    cJSON_AddStringToObject(o, "sk_ai", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_ai_len", a->sk_ai_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_ar, 64);
    cJSON_AddStringToObject(o, "sk_ar", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_ar_len", a->sk_ar_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_ei, 64);
    cJSON_AddStringToObject(o, "sk_ei", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_ei_len", a->sk_ei_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_er, 64);
    cJSON_AddStringToObject(o, "sk_er", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_er_len", a->sk_er_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_pi, 64);
    cJSON_AddStringToObject(o, "sk_pi", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_pi_len", a->sk_pi_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->sk_pr, 64);
    cJSON_AddStringToObject(o, "sk_pr", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "sk_pr_len", a->sk_pr_len);
    return o;
}
static inline cJSON *vl_api_ikev2_child_sa_t_tojson (vl_api_ikev2_child_sa_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddNumberToObject(o, "child_sa_index", a->child_sa_index);
    cJSON_AddNumberToObject(o, "i_spi", a->i_spi);
    cJSON_AddNumberToObject(o, "r_spi", a->r_spi);
    cJSON_AddItemToObject(o, "keys", vl_api_ikev2_keys_t_tojson(&a->keys));
    cJSON_AddItemToObject(o, "encryption", vl_api_ikev2_sa_transform_t_tojson(&a->encryption));
    cJSON_AddItemToObject(o, "integrity", vl_api_ikev2_sa_transform_t_tojson(&a->integrity));
    cJSON_AddItemToObject(o, "esn", vl_api_ikev2_sa_transform_t_tojson(&a->esn));
    return o;
}
static inline cJSON *vl_api_ikev2_child_sa_v2_t_tojson (vl_api_ikev2_child_sa_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddNumberToObject(o, "child_sa_index", a->child_sa_index);
    cJSON_AddNumberToObject(o, "i_spi", a->i_spi);
    cJSON_AddNumberToObject(o, "r_spi", a->r_spi);
    cJSON_AddItemToObject(o, "keys", vl_api_ikev2_keys_t_tojson(&a->keys));
    cJSON_AddItemToObject(o, "encryption", vl_api_ikev2_sa_transform_t_tojson(&a->encryption));
    cJSON_AddItemToObject(o, "integrity", vl_api_ikev2_sa_transform_t_tojson(&a->integrity));
    cJSON_AddItemToObject(o, "esn", vl_api_ikev2_sa_transform_t_tojson(&a->esn));
    cJSON_AddNumberToObject(o, "uptime", a->uptime);
    return o;
}
static inline cJSON *vl_api_ikev2_sa_stats_t_tojson (vl_api_ikev2_sa_stats_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "n_keepalives", a->n_keepalives);
    cJSON_AddNumberToObject(o, "n_rekey_req", a->n_rekey_req);
    cJSON_AddNumberToObject(o, "n_sa_init_req", a->n_sa_init_req);
    cJSON_AddNumberToObject(o, "n_sa_auth_req", a->n_sa_auth_req);
    cJSON_AddNumberToObject(o, "n_retransmit", a->n_retransmit);
    cJSON_AddNumberToObject(o, "n_init_sa_retransmit", a->n_init_sa_retransmit);
    return o;
}
static inline cJSON *vl_api_ikev2_state_t_tojson (vl_api_ikev2_state_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("UNKNOWN");
    case 1:
        return cJSON_CreateString("SA_INIT");
    case 2:
        return cJSON_CreateString("DELETED");
    case 3:
        return cJSON_CreateString("AUTH_FAILED");
    case 4:
        return cJSON_CreateString("AUTHENTICATED");
    case 5:
        return cJSON_CreateString("NOTIFY_AND_DELETE");
    case 6:
        return cJSON_CreateString("TS_UNACCEPTABLE");
    case 7:
        return cJSON_CreateString("NO_PROPOSAL_CHOSEN");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ikev2_sa_t_tojson (vl_api_ikev2_sa_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddNumberToObject(o, "profile_index", a->profile_index);
    cJSON_AddNumberToObject(o, "ispi", a->ispi);
    cJSON_AddNumberToObject(o, "rspi", a->rspi);
    cJSON_AddItemToObject(o, "iaddr", vl_api_address_t_tojson(&a->iaddr));
    cJSON_AddItemToObject(o, "raddr", vl_api_address_t_tojson(&a->raddr));
    cJSON_AddItemToObject(o, "keys", vl_api_ikev2_keys_t_tojson(&a->keys));
    cJSON_AddItemToObject(o, "i_id", vl_api_ikev2_id_t_tojson(&a->i_id));
    cJSON_AddItemToObject(o, "r_id", vl_api_ikev2_id_t_tojson(&a->r_id));
    cJSON_AddItemToObject(o, "encryption", vl_api_ikev2_sa_transform_t_tojson(&a->encryption));
    cJSON_AddItemToObject(o, "integrity", vl_api_ikev2_sa_transform_t_tojson(&a->integrity));
    cJSON_AddItemToObject(o, "prf", vl_api_ikev2_sa_transform_t_tojson(&a->prf));
    cJSON_AddItemToObject(o, "dh", vl_api_ikev2_sa_transform_t_tojson(&a->dh));
    cJSON_AddItemToObject(o, "stats", vl_api_ikev2_sa_stats_t_tojson(&a->stats));
    return o;
}
static inline cJSON *vl_api_ikev2_sa_v2_t_tojson (vl_api_ikev2_sa_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddStringToObject(o, "profile_name", (char *)a->profile_name);
    cJSON_AddItemToObject(o, "state", vl_api_ikev2_state_t_tojson(a->state));
    cJSON_AddNumberToObject(o, "ispi", a->ispi);
    cJSON_AddNumberToObject(o, "rspi", a->rspi);
    cJSON_AddItemToObject(o, "iaddr", vl_api_address_t_tojson(&a->iaddr));
    cJSON_AddItemToObject(o, "raddr", vl_api_address_t_tojson(&a->raddr));
    cJSON_AddItemToObject(o, "keys", vl_api_ikev2_keys_t_tojson(&a->keys));
    cJSON_AddItemToObject(o, "i_id", vl_api_ikev2_id_t_tojson(&a->i_id));
    cJSON_AddItemToObject(o, "r_id", vl_api_ikev2_id_t_tojson(&a->r_id));
    cJSON_AddItemToObject(o, "encryption", vl_api_ikev2_sa_transform_t_tojson(&a->encryption));
    cJSON_AddItemToObject(o, "integrity", vl_api_ikev2_sa_transform_t_tojson(&a->integrity));
    cJSON_AddItemToObject(o, "prf", vl_api_ikev2_sa_transform_t_tojson(&a->prf));
    cJSON_AddItemToObject(o, "dh", vl_api_ikev2_sa_transform_t_tojson(&a->dh));
    cJSON_AddItemToObject(o, "stats", vl_api_ikev2_sa_stats_t_tojson(&a->stats));
    return o;
}
static inline cJSON *vl_api_ikev2_sa_v3_t_tojson (vl_api_ikev2_sa_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sa_index", a->sa_index);
    cJSON_AddStringToObject(o, "profile_name", (char *)a->profile_name);
    cJSON_AddItemToObject(o, "state", vl_api_ikev2_state_t_tojson(a->state));
    cJSON_AddNumberToObject(o, "ispi", a->ispi);
    cJSON_AddNumberToObject(o, "rspi", a->rspi);
    cJSON_AddItemToObject(o, "iaddr", vl_api_address_t_tojson(&a->iaddr));
    cJSON_AddItemToObject(o, "raddr", vl_api_address_t_tojson(&a->raddr));
    cJSON_AddItemToObject(o, "keys", vl_api_ikev2_keys_t_tojson(&a->keys));
    cJSON_AddItemToObject(o, "i_id", vl_api_ikev2_id_t_tojson(&a->i_id));
    cJSON_AddItemToObject(o, "r_id", vl_api_ikev2_id_t_tojson(&a->r_id));
    cJSON_AddItemToObject(o, "encryption", vl_api_ikev2_sa_transform_t_tojson(&a->encryption));
    cJSON_AddItemToObject(o, "integrity", vl_api_ikev2_sa_transform_t_tojson(&a->integrity));
    cJSON_AddItemToObject(o, "prf", vl_api_ikev2_sa_transform_t_tojson(&a->prf));
    cJSON_AddItemToObject(o, "dh", vl_api_ikev2_sa_transform_t_tojson(&a->dh));
    cJSON_AddItemToObject(o, "stats", vl_api_ikev2_sa_stats_t_tojson(&a->stats));
    cJSON_AddNumberToObject(o, "uptime", a->uptime);
    return o;
}
#endif
