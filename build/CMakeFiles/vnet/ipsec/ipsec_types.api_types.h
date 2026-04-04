#ifndef included_ipsec_types_api_types_h
#define included_ipsec_types_api_types_h
#define VL_API_IPSEC_TYPES_API_VERSION_MAJOR 3
#define VL_API_IPSEC_TYPES_API_VERSION_MINOR 0
#define VL_API_IPSEC_TYPES_API_VERSION_PATCH 1
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/tunnel/tunnel_types.api_types.h>
typedef enum {
    IPSEC_API_CRYPTO_ALG_NONE = 0,
    IPSEC_API_CRYPTO_ALG_AES_CBC_128 = 1,
    IPSEC_API_CRYPTO_ALG_AES_CBC_192 = 2,
    IPSEC_API_CRYPTO_ALG_AES_CBC_256 = 3,
    IPSEC_API_CRYPTO_ALG_AES_CTR_128 = 4,
    IPSEC_API_CRYPTO_ALG_AES_CTR_192 = 5,
    IPSEC_API_CRYPTO_ALG_AES_CTR_256 = 6,
    IPSEC_API_CRYPTO_ALG_AES_GCM_128 = 7,
    IPSEC_API_CRYPTO_ALG_AES_GCM_192 = 8,
    IPSEC_API_CRYPTO_ALG_AES_GCM_256 = 9,
    IPSEC_API_CRYPTO_ALG_DES_CBC = 10,
    IPSEC_API_CRYPTO_ALG_3DES_CBC = 11,
    IPSEC_API_CRYPTO_ALG_CHACHA20_POLY1305 = 12,
    IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_128 = 13,
    IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_192 = 14,
    IPSEC_API_CRYPTO_ALG_AES_NULL_GMAC_256 = 15,
} vl_api_ipsec_crypto_alg_t;
typedef enum {
    IPSEC_API_INTEG_ALG_NONE = 0,
    IPSEC_API_INTEG_ALG_MD5_96 = 1,
    IPSEC_API_INTEG_ALG_SHA1_96 = 2,
    IPSEC_API_INTEG_ALG_SHA_256_96 = 3,
    IPSEC_API_INTEG_ALG_SHA_256_128 = 4,
    IPSEC_API_INTEG_ALG_SHA_384_192 = 5,
    IPSEC_API_INTEG_ALG_SHA_512_256 = 6,
} vl_api_ipsec_integ_alg_t;
typedef enum {
    IPSEC_API_SAD_FLAG_NONE = 0,
    IPSEC_API_SAD_FLAG_USE_ESN = 1,
    IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY = 2,
    IPSEC_API_SAD_FLAG_IS_TUNNEL = 4,
    IPSEC_API_SAD_FLAG_IS_TUNNEL_V6 = 8,
    IPSEC_API_SAD_FLAG_UDP_ENCAP = 16,
    IPSEC_API_SAD_FLAG_IS_INBOUND = 64,
    IPSEC_API_SAD_FLAG_ASYNC = 128,
} vl_api_ipsec_sad_flags_t;
typedef enum {
    IPSEC_API_PROTO_ESP = 50,
    IPSEC_API_PROTO_AH = 51,
} vl_api_ipsec_proto_t;
typedef struct __attribute__ ((packed)) _vl_api_key {
    u8 length;
    u8 data[128];
} vl_api_key_t;
#define VL_API_KEY_IS_CONSTANT_SIZE (1)

typedef enum {
    IPSEC_API_SPD_ACTION_BYPASS = 0,
    IPSEC_API_SPD_ACTION_DISCARD = 1,
    IPSEC_API_SPD_ACTION_RESOLVE = 2,
    IPSEC_API_SPD_ACTION_PROTECT = 3,
} vl_api_ipsec_spd_action_t;
typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_entry {
    u32 spd_id;
    i32 priority;
    bool is_outbound;
    u32 sa_id;
    vl_api_ipsec_spd_action_t policy;
    u8 protocol;
    vl_api_address_t remote_address_start;
    vl_api_address_t remote_address_stop;
    vl_api_address_t local_address_start;
    vl_api_address_t local_address_stop;
    u16 remote_port_start;
    u16 remote_port_stop;
    u16 local_port_start;
    u16 local_port_stop;
} vl_api_ipsec_spd_entry_t;
#define VL_API_IPSEC_SPD_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_spd_entry_v2 {
    u32 spd_id;
    i32 priority;
    bool is_outbound;
    u32 sa_id;
    vl_api_ipsec_spd_action_t policy;
    u8 protocol;
    vl_api_address_t remote_address_start;
    vl_api_address_t remote_address_stop;
    vl_api_address_t local_address_start;
    vl_api_address_t local_address_stop;
    u16 remote_port_start;
    u16 remote_port_stop;
    u16 local_port_start;
    u16 local_port_stop;
} vl_api_ipsec_spd_entry_v2_t;
#define VL_API_IPSEC_SPD_ENTRY_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry {
    u32 sad_id;
    u32 spi;
    vl_api_ipsec_proto_t protocol;
    vl_api_ipsec_crypto_alg_t crypto_algorithm;
    vl_api_key_t crypto_key;
    vl_api_ipsec_integ_alg_t integrity_algorithm;
    vl_api_key_t integrity_key;
    vl_api_ipsec_sad_flags_t flags;
    vl_api_address_t tunnel_src;
    vl_api_address_t tunnel_dst;
    u32 tx_table_id;
    u32 salt;
    u16 udp_src_port;
    u16 udp_dst_port;
} vl_api_ipsec_sad_entry_t;
#define VL_API_IPSEC_SAD_ENTRY_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_v2 {
    u32 sad_id;
    u32 spi;
    vl_api_ipsec_proto_t protocol;
    vl_api_ipsec_crypto_alg_t crypto_algorithm;
    vl_api_key_t crypto_key;
    vl_api_ipsec_integ_alg_t integrity_algorithm;
    vl_api_key_t integrity_key;
    vl_api_ipsec_sad_flags_t flags;
    vl_api_address_t tunnel_src;
    vl_api_address_t tunnel_dst;
    vl_api_tunnel_encap_decap_flags_t tunnel_flags;
    vl_api_ip_dscp_t dscp;
    u32 tx_table_id;
    u32 salt;
    u16 udp_src_port;
    u16 udp_dst_port;
} vl_api_ipsec_sad_entry_v2_t;
#define VL_API_IPSEC_SAD_ENTRY_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_v3 {
    u32 sad_id;
    u32 spi;
    vl_api_ipsec_proto_t protocol;
    vl_api_ipsec_crypto_alg_t crypto_algorithm;
    vl_api_key_t crypto_key;
    vl_api_ipsec_integ_alg_t integrity_algorithm;
    vl_api_key_t integrity_key;
    vl_api_ipsec_sad_flags_t flags;
    vl_api_tunnel_t tunnel;
    u32 salt;
    u16 udp_src_port;
    u16 udp_dst_port;
} vl_api_ipsec_sad_entry_v3_t;
#define VL_API_IPSEC_SAD_ENTRY_V3_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ipsec_sad_entry_v4 {
    u32 sad_id;
    u32 spi;
    vl_api_ipsec_proto_t protocol;
    vl_api_ipsec_crypto_alg_t crypto_algorithm;
    vl_api_key_t crypto_key;
    vl_api_ipsec_integ_alg_t integrity_algorithm;
    vl_api_key_t integrity_key;
    vl_api_ipsec_sad_flags_t flags;
    vl_api_tunnel_t tunnel;
    u32 salt;
    u16 udp_src_port;
    u16 udp_dst_port;
    u32 anti_replay_window_size;
} vl_api_ipsec_sad_entry_v4_t;
#define VL_API_IPSEC_SAD_ENTRY_V4_IS_CONSTANT_SIZE (1)


#endif
