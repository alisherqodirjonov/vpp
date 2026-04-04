/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/tunnel/tunnel_types.api_fromjson.h>
#ifndef included_ipsec_types_api_fromjson_h
#define included_ipsec_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_ipsec_crypto_alg_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ipsec_crypto_alg_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_CBC_128") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_CBC_192") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_CBC_256") == 0) {*a = 3; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_CTR_128") == 0) {*a = 4; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_CTR_192") == 0) {*a = 5; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_CTR_256") == 0) {*a = 6; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_GCM_128") == 0) {*a = 7; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_GCM_192") == 0) {*a = 8; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_GCM_256") == 0) {*a = 9; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_DES_CBC") == 0) {*a = 10; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_3DES_CBC") == 0) {*a = 11; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_CHACHA20_POLY1305") == 0) {*a = 12; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_128") == 0) {*a = 13; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_192") == 0) {*a = 14; return 0;}
    if (strcmp(p, "IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_256") == 0) {*a = 15; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ipsec_integ_alg_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ipsec_integ_alg_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IPSEC_API_INTEG_ALG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IPSEC_API_INTEG_ALG_MD5_96") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IPSEC_API_INTEG_ALG_SHA1_96") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IPSEC_API_INTEG_ALG_SHA_256_96") == 0) {*a = 3; return 0;}
    if (strcmp(p, "IPSEC_API_INTEG_ALG_SHA_256_128") == 0) {*a = 4; return 0;}
    if (strcmp(p, "IPSEC_API_INTEG_ALG_SHA_384_192") == 0) {*a = 5; return 0;}
    if (strcmp(p, "IPSEC_API_INTEG_ALG_SHA_512_256") == 0) {*a = 6; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ipsec_sad_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ipsec_sad_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IPSEC_API_SAD_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_USE_ESN") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_IS_TUNNEL") == 0) {*a = 4; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_IS_TUNNEL_V6") == 0) {*a = 8; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_UDP_ENCAP") == 0) {*a = 16; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_IS_INBOUND") == 0) {*a = 64; return 0;}
    if (strcmp(p, "IPSEC_API_SAD_FLAG_ASYNC") == 0) {*a = 128; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ipsec_proto_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ipsec_proto_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IPSEC_API_PROTO_ESP") == 0) {*a = 50; return 0;}
    if (strcmp(p, "IPSEC_API_PROTO_AH") == 0) {*a = 51; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_key_t_fromjson (void **mp, int *len, cJSON *o, vl_api_key_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "length");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->length);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    if (u8string_fromjson2(o, "data", a->data) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_spd_action_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ipsec_spd_action_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IPSEC_API_SPD_ACTION_BYPASS") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IPSEC_API_SPD_ACTION_DISCARD") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IPSEC_API_SPD_ACTION_RESOLVE") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IPSEC_API_SPD_ACTION_PROTECT") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ipsec_spd_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_spd_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "spd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_id);

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "is_outbound");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_outbound);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    item = cJSON_GetObjectItem(o, "policy");
    if (!item) goto error;
    if (vl_api_ipsec_spd_action_t_fromjson(mp, len, item, &a->policy) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "remote_address_start");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->remote_address_start) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote_address_stop");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->remote_address_stop) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_address_start");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->local_address_start) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_address_stop");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->local_address_stop) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote_port_start");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port_start);

    item = cJSON_GetObjectItem(o, "remote_port_stop");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port_stop);

    item = cJSON_GetObjectItem(o, "local_port_start");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port_start);

    item = cJSON_GetObjectItem(o, "local_port_stop");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port_stop);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_spd_entry_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_spd_entry_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "spd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spd_id);

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "is_outbound");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_outbound);

    item = cJSON_GetObjectItem(o, "sa_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sa_id);

    item = cJSON_GetObjectItem(o, "policy");
    if (!item) goto error;
    if (vl_api_ipsec_spd_action_t_fromjson(mp, len, item, &a->policy) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "remote_address_start");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->remote_address_start) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote_address_stop");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->remote_address_stop) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_address_start");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->local_address_start) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_address_stop");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->local_address_stop) < 0) goto error;

    item = cJSON_GetObjectItem(o, "remote_port_start");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port_start);

    item = cJSON_GetObjectItem(o, "remote_port_stop");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->remote_port_stop);

    item = cJSON_GetObjectItem(o, "local_port_start");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port_start);

    item = cJSON_GetObjectItem(o, "local_port_stop");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port_stop);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_sad_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_sad_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sad_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sad_id);

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ipsec_proto_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_crypto_alg_t_fromjson(mp, len, item, &a->crypto_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->crypto_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_integ_alg_t_fromjson(mp, len, item, &a->integrity_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->integrity_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_ipsec_sad_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel_src");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->tunnel_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel_dst");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->tunnel_dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_table_id);

    item = cJSON_GetObjectItem(o, "salt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->salt);

    item = cJSON_GetObjectItem(o, "udp_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_src_port);

    item = cJSON_GetObjectItem(o, "udp_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_dst_port);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_sad_entry_v2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_sad_entry_v2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sad_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sad_id);

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ipsec_proto_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_crypto_alg_t_fromjson(mp, len, item, &a->crypto_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->crypto_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_integ_alg_t_fromjson(mp, len, item, &a->integrity_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->integrity_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_ipsec_sad_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel_src");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->tunnel_src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel_dst");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->tunnel_dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel_flags");
    if (!item) goto error;
    if (vl_api_tunnel_encap_decap_flags_t_fromjson(mp, len, item, &a->tunnel_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    if (vl_api_ip_dscp_t_fromjson(mp, len, item, &a->dscp) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_table_id);

    item = cJSON_GetObjectItem(o, "salt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->salt);

    item = cJSON_GetObjectItem(o, "udp_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_src_port);

    item = cJSON_GetObjectItem(o, "udp_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_dst_port);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_sad_entry_v3_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_sad_entry_v3_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sad_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sad_id);

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ipsec_proto_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_crypto_alg_t_fromjson(mp, len, item, &a->crypto_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->crypto_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_integ_alg_t_fromjson(mp, len, item, &a->integrity_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->integrity_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_ipsec_sad_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_tunnel_t_fromjson(mp, len, item, &a->tunnel) < 0) goto error;

    item = cJSON_GetObjectItem(o, "salt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->salt);

    item = cJSON_GetObjectItem(o, "udp_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_src_port);

    item = cJSON_GetObjectItem(o, "udp_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_dst_port);

    return 0;

  error:
    return -1;
}
static inline int vl_api_ipsec_sad_entry_v4_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ipsec_sad_entry_v4_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sad_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sad_id);

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ipsec_proto_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_crypto_alg_t_fromjson(mp, len, item, &a->crypto_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "crypto_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->crypto_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_algorithm");
    if (!item) goto error;
    if (vl_api_ipsec_integ_alg_t_fromjson(mp, len, item, &a->integrity_algorithm) < 0) goto error;

    item = cJSON_GetObjectItem(o, "integrity_key");
    if (!item) goto error;
    if (vl_api_key_t_fromjson(mp, len, item, &a->integrity_key) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_ipsec_sad_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tunnel");
    if (!item) goto error;
    if (vl_api_tunnel_t_fromjson(mp, len, item, &a->tunnel) < 0) goto error;

    item = cJSON_GetObjectItem(o, "salt");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->salt);

    item = cJSON_GetObjectItem(o, "udp_src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_src_port);

    item = cJSON_GetObjectItem(o, "udp_dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->udp_dst_port);

    item = cJSON_GetObjectItem(o, "anti_replay_window_size");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->anti_replay_window_size);

    return 0;

  error:
    return -1;
}
#endif
