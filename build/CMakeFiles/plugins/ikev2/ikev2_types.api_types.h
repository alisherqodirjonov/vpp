#ifndef included_ikev2_types_api_types_h
#define included_ikev2_types_api_types_h
#define VL_API_IKEV2_TYPES_API_VERSION_MAJOR 1
#define VL_API_IKEV2_TYPES_API_VERSION_MINOR 0
#define VL_API_IKEV2_TYPES_API_VERSION_PATCH 0
/* Imported API files */
#include <vnet/ip/ip_types.api_types.h>
#include <vnet/interface_types.api_types.h>
typedef struct __attribute__ ((packed)) _vl_api_ikev2_id {
    u8 type;
    u8 data_len;
    u8 data[64];
} vl_api_ikev2_id_t;
#define VL_API_IKEV2_ID_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_ts {
    u32 sa_index;
    u32 child_sa_index;
    bool is_local;
    u8 protocol_id;
    u16 start_port;
    u16 end_port;
    vl_api_address_t start_addr;
    vl_api_address_t end_addr;
} vl_api_ikev2_ts_t;
#define VL_API_IKEV2_TS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_auth {
    u8 method;
    u8 hex;
    u32 data_len;
    u8 data[0];
} vl_api_ikev2_auth_t;
#define VL_API_IKEV2_AUTH_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_responder {
    vl_api_interface_index_t sw_if_index;
    vl_api_address_t addr;
} vl_api_ikev2_responder_t;
#define VL_API_IKEV2_RESPONDER_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_ike_transforms {
    u8 crypto_alg;
    u32 crypto_key_size;
    u8 integ_alg;
    u8 dh_group;
} vl_api_ikev2_ike_transforms_t;
#define VL_API_IKEV2_IKE_TRANSFORMS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_esp_transforms {
    u8 crypto_alg;
    u32 crypto_key_size;
    u8 integ_alg;
} vl_api_ikev2_esp_transforms_t;
#define VL_API_IKEV2_ESP_TRANSFORMS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_profile {
    u8 name[64];
    vl_api_ikev2_id_t loc_id;
    vl_api_ikev2_id_t rem_id;
    vl_api_ikev2_ts_t loc_ts;
    vl_api_ikev2_ts_t rem_ts;
    vl_api_ikev2_responder_t responder;
    vl_api_ikev2_ike_transforms_t ike_ts;
    vl_api_ikev2_esp_transforms_t esp_ts;
    u64 lifetime;
    u64 lifetime_maxdata;
    u32 lifetime_jitter;
    u32 handover;
    u16 ipsec_over_udp_port;
    u32 tun_itf;
    bool udp_encap;
    bool natt_disabled;
    vl_api_ikev2_auth_t auth;
} vl_api_ikev2_profile_t;
#define VL_API_IKEV2_PROFILE_IS_CONSTANT_SIZE (0)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_sa_transform {
    u8 transform_type;
    u16 transform_id;
    u16 key_len;
    u16 key_trunc;
    u16 block_size;
    u8 dh_group;
} vl_api_ikev2_sa_transform_t;
#define VL_API_IKEV2_SA_TRANSFORM_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_keys {
    u8 sk_d[64];
    u8 sk_d_len;
    u8 sk_ai[64];
    u8 sk_ai_len;
    u8 sk_ar[64];
    u8 sk_ar_len;
    u8 sk_ei[64];
    u8 sk_ei_len;
    u8 sk_er[64];
    u8 sk_er_len;
    u8 sk_pi[64];
    u8 sk_pi_len;
    u8 sk_pr[64];
    u8 sk_pr_len;
} vl_api_ikev2_keys_t;
#define VL_API_IKEV2_KEYS_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_child_sa {
    u32 sa_index;
    u32 child_sa_index;
    u32 i_spi;
    u32 r_spi;
    vl_api_ikev2_keys_t keys;
    vl_api_ikev2_sa_transform_t encryption;
    vl_api_ikev2_sa_transform_t integrity;
    vl_api_ikev2_sa_transform_t esn;
} vl_api_ikev2_child_sa_t;
#define VL_API_IKEV2_CHILD_SA_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_child_sa_v2 {
    u32 sa_index;
    u32 child_sa_index;
    u32 i_spi;
    u32 r_spi;
    vl_api_ikev2_keys_t keys;
    vl_api_ikev2_sa_transform_t encryption;
    vl_api_ikev2_sa_transform_t integrity;
    vl_api_ikev2_sa_transform_t esn;
    f64 uptime;
} vl_api_ikev2_child_sa_v2_t;
#define VL_API_IKEV2_CHILD_SA_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_sa_stats {
    u16 n_keepalives;
    u16 n_rekey_req;
    u16 n_sa_init_req;
    u16 n_sa_auth_req;
    u16 n_retransmit;
    u16 n_init_sa_retransmit;
} vl_api_ikev2_sa_stats_t;
#define VL_API_IKEV2_SA_STATS_IS_CONSTANT_SIZE (1)

typedef enum {
    UNKNOWN = 0,
    SA_INIT = 1,
    DELETED = 2,
    AUTH_FAILED = 3,
    AUTHENTICATED = 4,
    NOTIFY_AND_DELETE = 5,
    TS_UNACCEPTABLE = 6,
    NO_PROPOSAL_CHOSEN = 7,
} vl_api_ikev2_state_t;
typedef struct __attribute__ ((packed)) _vl_api_ikev2_sa {
    u32 sa_index;
    u32 profile_index;
    u64 ispi;
    u64 rspi;
    vl_api_address_t iaddr;
    vl_api_address_t raddr;
    vl_api_ikev2_keys_t keys;
    vl_api_ikev2_id_t i_id;
    vl_api_ikev2_id_t r_id;
    vl_api_ikev2_sa_transform_t encryption;
    vl_api_ikev2_sa_transform_t integrity;
    vl_api_ikev2_sa_transform_t prf;
    vl_api_ikev2_sa_transform_t dh;
    vl_api_ikev2_sa_stats_t stats;
} vl_api_ikev2_sa_t;
#define VL_API_IKEV2_SA_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_sa_v2 {
    u32 sa_index;
    u8 profile_name[64];
    vl_api_ikev2_state_t state;
    u64 ispi;
    u64 rspi;
    vl_api_address_t iaddr;
    vl_api_address_t raddr;
    vl_api_ikev2_keys_t keys;
    vl_api_ikev2_id_t i_id;
    vl_api_ikev2_id_t r_id;
    vl_api_ikev2_sa_transform_t encryption;
    vl_api_ikev2_sa_transform_t integrity;
    vl_api_ikev2_sa_transform_t prf;
    vl_api_ikev2_sa_transform_t dh;
    vl_api_ikev2_sa_stats_t stats;
} vl_api_ikev2_sa_v2_t;
#define VL_API_IKEV2_SA_V2_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_ikev2_sa_v3 {
    u32 sa_index;
    u8 profile_name[64];
    vl_api_ikev2_state_t state;
    u64 ispi;
    u64 rspi;
    vl_api_address_t iaddr;
    vl_api_address_t raddr;
    vl_api_ikev2_keys_t keys;
    vl_api_ikev2_id_t i_id;
    vl_api_ikev2_id_t r_id;
    vl_api_ikev2_sa_transform_t encryption;
    vl_api_ikev2_sa_transform_t integrity;
    vl_api_ikev2_sa_transform_t prf;
    vl_api_ikev2_sa_transform_t dh;
    vl_api_ikev2_sa_stats_t stats;
    f64 uptime;
} vl_api_ikev2_sa_v3_t;
#define VL_API_IKEV2_SA_V3_IS_CONSTANT_SIZE (1)


#endif
