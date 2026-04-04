/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/tunnel/tunnel_types.api_tojson.h>
#ifndef included_ipsec_types_api_tojson_h
#define included_ipsec_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ipsec_crypto_alg_t_tojson (vl_api_ipsec_crypto_alg_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_NONE");
    case 1:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_CBC_128");
    case 2:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_CBC_192");
    case 3:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_CBC_256");
    case 4:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_CTR_128");
    case 5:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_CTR_192");
    case 6:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_CTR_256");
    case 7:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_GCM_128");
    case 8:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_GCM_192");
    case 9:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_GCM_256");
    case 10:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_DES_CBC");
    case 11:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_3DES_CBC");
    case 12:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_CHACHA20_POLY1305");
    case 13:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_128");
    case 14:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_192");
    case 15:
        return cJSON_CreateString("IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_256");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ipsec_integ_alg_t_tojson (vl_api_ipsec_integ_alg_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_NONE");
    case 1:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_MD5_96");
    case 2:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_SHA1_96");
    case 3:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_SHA_256_96");
    case 4:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_SHA_256_128");
    case 5:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_SHA_384_192");
    case 6:
        return cJSON_CreateString("IPSEC_API_INTEG_ALG_SHA_512_256");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ipsec_sad_flags_t_tojson (vl_api_ipsec_sad_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_NONE");
    case 1:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_USE_ESN");
    case 2:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY");
    case 4:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_IS_TUNNEL");
    case 8:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_IS_TUNNEL_V6");
    case 16:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_UDP_ENCAP");
    case 64:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_IS_INBOUND");
    case 128:
        return cJSON_CreateString("IPSEC_API_SAD_FLAG_ASYNC");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ipsec_proto_t_tojson (vl_api_ipsec_proto_t a) {
    switch(a) {
    case 50:
        return cJSON_CreateString("IPSEC_API_PROTO_ESP");
    case 51:
        return cJSON_CreateString("IPSEC_API_PROTO_AH");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_key_t_tojson (vl_api_key_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "length", a->length);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->data, 128);
    cJSON_AddStringToObject(o, "data", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ipsec_spd_action_t_tojson (vl_api_ipsec_spd_action_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("IPSEC_API_SPD_ACTION_BYPASS");
    case 1:
        return cJSON_CreateString("IPSEC_API_SPD_ACTION_DISCARD");
    case 2:
        return cJSON_CreateString("IPSEC_API_SPD_ACTION_RESOLVE");
    case 3:
        return cJSON_CreateString("IPSEC_API_SPD_ACTION_PROTECT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_ipsec_spd_entry_t_tojson (vl_api_ipsec_spd_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "spd_id", a->spd_id);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddBoolToObject(o, "is_outbound", a->is_outbound);
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    cJSON_AddItemToObject(o, "policy", vl_api_ipsec_spd_action_t_tojson(a->policy));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "remote_address_start", vl_api_address_t_tojson(&a->remote_address_start));
    cJSON_AddItemToObject(o, "remote_address_stop", vl_api_address_t_tojson(&a->remote_address_stop));
    cJSON_AddItemToObject(o, "local_address_start", vl_api_address_t_tojson(&a->local_address_start));
    cJSON_AddItemToObject(o, "local_address_stop", vl_api_address_t_tojson(&a->local_address_stop));
    cJSON_AddNumberToObject(o, "remote_port_start", a->remote_port_start);
    cJSON_AddNumberToObject(o, "remote_port_stop", a->remote_port_stop);
    cJSON_AddNumberToObject(o, "local_port_start", a->local_port_start);
    cJSON_AddNumberToObject(o, "local_port_stop", a->local_port_stop);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_entry_v2_t_tojson (vl_api_ipsec_spd_entry_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "spd_id", a->spd_id);
    cJSON_AddNumberToObject(o, "priority", a->priority);
    cJSON_AddBoolToObject(o, "is_outbound", a->is_outbound);
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    cJSON_AddItemToObject(o, "policy", vl_api_ipsec_spd_action_t_tojson(a->policy));
    cJSON_AddNumberToObject(o, "protocol", a->protocol);
    cJSON_AddItemToObject(o, "remote_address_start", vl_api_address_t_tojson(&a->remote_address_start));
    cJSON_AddItemToObject(o, "remote_address_stop", vl_api_address_t_tojson(&a->remote_address_stop));
    cJSON_AddItemToObject(o, "local_address_start", vl_api_address_t_tojson(&a->local_address_start));
    cJSON_AddItemToObject(o, "local_address_stop", vl_api_address_t_tojson(&a->local_address_stop));
    cJSON_AddNumberToObject(o, "remote_port_start", a->remote_port_start);
    cJSON_AddNumberToObject(o, "remote_port_stop", a->remote_port_stop);
    cJSON_AddNumberToObject(o, "local_port_start", a->local_port_start);
    cJSON_AddNumberToObject(o, "local_port_stop", a->local_port_stop);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_t_tojson (vl_api_ipsec_sad_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sad_id", a->sad_id);
    cJSON_AddNumberToObject(o, "spi", a->spi);
    cJSON_AddItemToObject(o, "protocol", vl_api_ipsec_proto_t_tojson(a->protocol));
    cJSON_AddItemToObject(o, "crypto_algorithm", vl_api_ipsec_crypto_alg_t_tojson(a->crypto_algorithm));
    cJSON_AddItemToObject(o, "crypto_key", vl_api_key_t_tojson(&a->crypto_key));
    cJSON_AddItemToObject(o, "integrity_algorithm", vl_api_ipsec_integ_alg_t_tojson(a->integrity_algorithm));
    cJSON_AddItemToObject(o, "integrity_key", vl_api_key_t_tojson(&a->integrity_key));
    cJSON_AddItemToObject(o, "flags", vl_api_ipsec_sad_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "tunnel_src", vl_api_address_t_tojson(&a->tunnel_src));
    cJSON_AddItemToObject(o, "tunnel_dst", vl_api_address_t_tojson(&a->tunnel_dst));
    cJSON_AddNumberToObject(o, "tx_table_id", a->tx_table_id);
    cJSON_AddNumberToObject(o, "salt", a->salt);
    cJSON_AddNumberToObject(o, "udp_src_port", a->udp_src_port);
    cJSON_AddNumberToObject(o, "udp_dst_port", a->udp_dst_port);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_v2_t_tojson (vl_api_ipsec_sad_entry_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sad_id", a->sad_id);
    cJSON_AddNumberToObject(o, "spi", a->spi);
    cJSON_AddItemToObject(o, "protocol", vl_api_ipsec_proto_t_tojson(a->protocol));
    cJSON_AddItemToObject(o, "crypto_algorithm", vl_api_ipsec_crypto_alg_t_tojson(a->crypto_algorithm));
    cJSON_AddItemToObject(o, "crypto_key", vl_api_key_t_tojson(&a->crypto_key));
    cJSON_AddItemToObject(o, "integrity_algorithm", vl_api_ipsec_integ_alg_t_tojson(a->integrity_algorithm));
    cJSON_AddItemToObject(o, "integrity_key", vl_api_key_t_tojson(&a->integrity_key));
    cJSON_AddItemToObject(o, "flags", vl_api_ipsec_sad_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "tunnel_src", vl_api_address_t_tojson(&a->tunnel_src));
    cJSON_AddItemToObject(o, "tunnel_dst", vl_api_address_t_tojson(&a->tunnel_dst));
    cJSON_AddItemToObject(o, "tunnel_flags", vl_api_tunnel_encap_decap_flags_t_tojson(a->tunnel_flags));
    cJSON_AddItemToObject(o, "dscp", vl_api_ip_dscp_t_tojson(a->dscp));
    cJSON_AddNumberToObject(o, "tx_table_id", a->tx_table_id);
    cJSON_AddNumberToObject(o, "salt", a->salt);
    cJSON_AddNumberToObject(o, "udp_src_port", a->udp_src_port);
    cJSON_AddNumberToObject(o, "udp_dst_port", a->udp_dst_port);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_v3_t_tojson (vl_api_ipsec_sad_entry_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sad_id", a->sad_id);
    cJSON_AddNumberToObject(o, "spi", a->spi);
    cJSON_AddItemToObject(o, "protocol", vl_api_ipsec_proto_t_tojson(a->protocol));
    cJSON_AddItemToObject(o, "crypto_algorithm", vl_api_ipsec_crypto_alg_t_tojson(a->crypto_algorithm));
    cJSON_AddItemToObject(o, "crypto_key", vl_api_key_t_tojson(&a->crypto_key));
    cJSON_AddItemToObject(o, "integrity_algorithm", vl_api_ipsec_integ_alg_t_tojson(a->integrity_algorithm));
    cJSON_AddItemToObject(o, "integrity_key", vl_api_key_t_tojson(&a->integrity_key));
    cJSON_AddItemToObject(o, "flags", vl_api_ipsec_sad_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "tunnel", vl_api_tunnel_t_tojson(&a->tunnel));
    cJSON_AddNumberToObject(o, "salt", a->salt);
    cJSON_AddNumberToObject(o, "udp_src_port", a->udp_src_port);
    cJSON_AddNumberToObject(o, "udp_dst_port", a->udp_dst_port);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_v4_t_tojson (vl_api_ipsec_sad_entry_v4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sad_id", a->sad_id);
    cJSON_AddNumberToObject(o, "spi", a->spi);
    cJSON_AddItemToObject(o, "protocol", vl_api_ipsec_proto_t_tojson(a->protocol));
    cJSON_AddItemToObject(o, "crypto_algorithm", vl_api_ipsec_crypto_alg_t_tojson(a->crypto_algorithm));
    cJSON_AddItemToObject(o, "crypto_key", vl_api_key_t_tojson(&a->crypto_key));
    cJSON_AddItemToObject(o, "integrity_algorithm", vl_api_ipsec_integ_alg_t_tojson(a->integrity_algorithm));
    cJSON_AddItemToObject(o, "integrity_key", vl_api_key_t_tojson(&a->integrity_key));
    cJSON_AddItemToObject(o, "flags", vl_api_ipsec_sad_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "tunnel", vl_api_tunnel_t_tojson(&a->tunnel));
    cJSON_AddNumberToObject(o, "salt", a->salt);
    cJSON_AddNumberToObject(o, "udp_src_port", a->udp_src_port);
    cJSON_AddNumberToObject(o, "udp_dst_port", a->udp_dst_port);
    cJSON_AddNumberToObject(o, "anti_replay_window_size", a->anti_replay_window_size);
    return o;
}
#endif
