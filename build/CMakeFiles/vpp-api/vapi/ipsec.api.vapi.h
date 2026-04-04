#ifndef __included_ipsec_api_json
#define __included_ipsec_api_json

#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <vapi/vapi_internal.h>
#include <vapi/vapi.h>
#include <vapi/vapi_dbg.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifndef __vl_api_string_swap_fns_defined__
#define __vl_api_string_swap_fns_defined__

#include <vlibapi/api_types.h>

static inline void vl_api_string_t_hton(vl_api_string_t *msg)
{
  msg->length = htobe32(msg->length);
}

static inline void vl_api_string_t_ntoh(vl_api_string_t *msg)
{
  msg->length = be32toh(msg->length);
}

#endif //__vl_api_string_swap_fns_defined__
#include <vapi/vlib.api.vapi.h>

extern vapi_msg_id_t vapi_msg_id_ipsec_spd_add_del;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_interface_add_del_spd;
extern vapi_msg_id_t vapi_msg_id_ipsec_interface_add_del_spd_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_spds_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_spds_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v2;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v3;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_v2;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_del;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_del_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_bind;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_bind_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_unbind;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_unbind_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_update;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_update_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v3_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_v2_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_update;
extern vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_update_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_del;
extern vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_del_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_interface_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_spd_interface_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_itf_create;
extern vapi_msg_id_t vapi_msg_id_ipsec_itf_create_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_itf_delete;
extern vapi_msg_id_t vapi_msg_id_ipsec_itf_delete_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_itf_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_itf_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v2_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v3_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v4_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v5_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v2_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v3_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v4_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_sa_v5_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_backend_dump;
extern vapi_msg_id_t vapi_msg_id_ipsec_backend_details;
extern vapi_msg_id_t vapi_msg_id_ipsec_select_backend;
extern vapi_msg_id_t vapi_msg_id_ipsec_select_backend_reply;
extern vapi_msg_id_t vapi_msg_id_ipsec_set_async_mode;
extern vapi_msg_id_t vapi_msg_id_ipsec_set_async_mode_reply;

#define DEFINE_VAPI_MSG_IDS_IPSEC_API_JSON\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_add_del;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_interface_add_del_spd;\
  vapi_msg_id_t vapi_msg_id_ipsec_interface_add_del_spd_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_entry_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_spds_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_spds_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v2;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v3;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_v2;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_del;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_del_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_bind;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_bind_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_unbind;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_unbind_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_update;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_update_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_del_v3_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_sad_entry_add_v2_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_update;\
  vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_update_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_del;\
  vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_del_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_tunnel_protect_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_interface_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_spd_interface_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_itf_create;\
  vapi_msg_id_t vapi_msg_id_ipsec_itf_create_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_itf_delete;\
  vapi_msg_id_t vapi_msg_id_ipsec_itf_delete_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_itf_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_itf_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v2_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v3_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v4_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v5_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v2_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v3_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v4_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_sa_v5_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_backend_dump;\
  vapi_msg_id_t vapi_msg_id_ipsec_backend_details;\
  vapi_msg_id_t vapi_msg_id_ipsec_select_backend;\
  vapi_msg_id_t vapi_msg_id_ipsec_select_backend_reply;\
  vapi_msg_id_t vapi_msg_id_ipsec_set_async_mode;\
  vapi_msg_id_t vapi_msg_id_ipsec_set_async_mode_reply;


#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_tunnel_encap_decap_flags
#define defined_vapi_enum_tunnel_encap_decap_flags
typedef enum {
  TUNNEL_API_ENCAP_DECAP_FLAG_NONE = 0,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF = 1,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF = 2,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP = 4,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN = 8,
  TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN = 16,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH = 32,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT = 64,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL = 128,
} __attribute__((packed)) vapi_enum_tunnel_encap_decap_flags;

#endif

#ifndef defined_vapi_enum_tunnel_mode
#define defined_vapi_enum_tunnel_mode
typedef enum {
  TUNNEL_API_MODE_P2P = 0,
  TUNNEL_API_MODE_MP = 1,
} __attribute__((packed)) vapi_enum_tunnel_mode;

#endif

#ifndef defined_vapi_enum_ipsec_crypto_alg
#define defined_vapi_enum_ipsec_crypto_alg
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
}  vapi_enum_ipsec_crypto_alg;

#endif

#ifndef defined_vapi_enum_ipsec_integ_alg
#define defined_vapi_enum_ipsec_integ_alg
typedef enum {
  IPSEC_API_INTEG_ALG_NONE = 0,
  IPSEC_API_INTEG_ALG_MD5_96 = 1,
  IPSEC_API_INTEG_ALG_SHA1_96 = 2,
  IPSEC_API_INTEG_ALG_SHA_256_96 = 3,
  IPSEC_API_INTEG_ALG_SHA_256_128 = 4,
  IPSEC_API_INTEG_ALG_SHA_384_192 = 5,
  IPSEC_API_INTEG_ALG_SHA_512_256 = 6,
}  vapi_enum_ipsec_integ_alg;

#endif

#ifndef defined_vapi_enum_ipsec_sad_flags
#define defined_vapi_enum_ipsec_sad_flags
typedef enum {
  IPSEC_API_SAD_FLAG_NONE = 0,
  IPSEC_API_SAD_FLAG_USE_ESN = 1,
  IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY = 2,
  IPSEC_API_SAD_FLAG_IS_TUNNEL = 4,
  IPSEC_API_SAD_FLAG_IS_TUNNEL_V6 = 8,
  IPSEC_API_SAD_FLAG_UDP_ENCAP = 16,
  IPSEC_API_SAD_FLAG_IS_INBOUND = 64,
  IPSEC_API_SAD_FLAG_ASYNC = 128,
}  vapi_enum_ipsec_sad_flags;

#endif

#ifndef defined_vapi_enum_ipsec_proto
#define defined_vapi_enum_ipsec_proto
typedef enum {
  IPSEC_API_PROTO_ESP = 50,
  IPSEC_API_PROTO_AH = 51,
}  vapi_enum_ipsec_proto;

#endif

#ifndef defined_vapi_enum_ipsec_spd_action
#define defined_vapi_enum_ipsec_spd_action
typedef enum {
  IPSEC_API_SPD_ACTION_BYPASS = 0,
  IPSEC_API_SPD_ACTION_DISCARD = 1,
  IPSEC_API_SPD_ACTION_RESOLVE = 2,
  IPSEC_API_SPD_ACTION_PROTECT = 3,
}  vapi_enum_ipsec_spd_action;

#endif

#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_if_status_flags
#define defined_vapi_enum_if_status_flags
typedef enum {
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
}  vapi_enum_if_status_flags;

#endif

#ifndef defined_vapi_enum_mtu_proto
#define defined_vapi_enum_mtu_proto
typedef enum {
  MTU_PROTO_API_L3 = 0,
  MTU_PROTO_API_IP4 = 1,
  MTU_PROTO_API_IP6 = 2,
  MTU_PROTO_API_MPLS = 3,
}  vapi_enum_mtu_proto;

#endif

#ifndef defined_vapi_enum_link_duplex
#define defined_vapi_enum_link_duplex
typedef enum {
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
}  vapi_enum_link_duplex;

#endif

#ifndef defined_vapi_enum_sub_if_flags
#define defined_vapi_enum_sub_if_flags
typedef enum {
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,
  SUB_IF_API_FLAG_DOT1AH = 256,
}  vapi_enum_sub_if_flags;

#endif

#ifndef defined_vapi_enum_rx_mode
#define defined_vapi_enum_rx_mode
typedef enum {
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING = 1,
  RX_MODE_API_INTERRUPT = 2,
  RX_MODE_API_ADAPTIVE = 3,
  RX_MODE_API_DEFAULT = 4,
}  vapi_enum_rx_mode;

#endif

#ifndef defined_vapi_enum_if_type
#define defined_vapi_enum_if_type
typedef enum {
  IF_API_TYPE_HARDWARE = 0,
  IF_API_TYPE_SUB = 1,
  IF_API_TYPE_P2P = 2,
  IF_API_TYPE_PIPE = 3,
}  vapi_enum_if_type;

#endif

#ifndef defined_vapi_enum_direction
#define defined_vapi_enum_direction
typedef enum {
  RX = 0,
  TX = 1,
} __attribute__((packed)) vapi_enum_direction;

#endif

#ifndef defined_vapi_enum_address_family
#define defined_vapi_enum_address_family
typedef enum {
  ADDRESS_IP4 = 0,
  ADDRESS_IP6 = 1,
} __attribute__((packed)) vapi_enum_address_family;

#endif

#ifndef defined_vapi_enum_ip_feature_location
#define defined_vapi_enum_ip_feature_location
typedef enum {
  IP_API_FEATURE_INPUT = 0,
  IP_API_FEATURE_OUTPUT = 1,
  IP_API_FEATURE_LOCAL = 2,
  IP_API_FEATURE_PUNT = 3,
  IP_API_FEATURE_DROP = 4,
} __attribute__((packed)) vapi_enum_ip_feature_location;

#endif

#ifndef defined_vapi_enum_ip_ecn
#define defined_vapi_enum_ip_ecn
typedef enum {
  IP_API_ECN_NONE = 0,
  IP_API_ECN_ECT0 = 1,
  IP_API_ECN_ECT1 = 2,
  IP_API_ECN_CE = 3,
} __attribute__((packed)) vapi_enum_ip_ecn;

#endif

#ifndef defined_vapi_enum_ip_dscp
#define defined_vapi_enum_ip_dscp
typedef enum {
  IP_API_DSCP_CS0 = 0,
  IP_API_DSCP_CS1 = 8,
  IP_API_DSCP_AF11 = 10,
  IP_API_DSCP_AF12 = 12,
  IP_API_DSCP_AF13 = 14,
  IP_API_DSCP_CS2 = 16,
  IP_API_DSCP_AF21 = 18,
  IP_API_DSCP_AF22 = 20,
  IP_API_DSCP_AF23 = 22,
  IP_API_DSCP_CS3 = 24,
  IP_API_DSCP_AF31 = 26,
  IP_API_DSCP_AF32 = 28,
  IP_API_DSCP_AF33 = 30,
  IP_API_DSCP_CS4 = 32,
  IP_API_DSCP_AF41 = 34,
  IP_API_DSCP_AF42 = 36,
  IP_API_DSCP_AF43 = 38,
  IP_API_DSCP_CS5 = 40,
  IP_API_DSCP_EF = 46,
  IP_API_DSCP_CS6 = 48,
  IP_API_DSCP_CS7 = 50,
} __attribute__((packed)) vapi_enum_ip_dscp;

#endif

#ifndef defined_vapi_enum_ip_proto
#define defined_vapi_enum_ip_proto
typedef enum {
  IP_API_PROTO_HOPOPT = 0,
  IP_API_PROTO_ICMP = 1,
  IP_API_PROTO_IGMP = 2,
  IP_API_PROTO_TCP = 6,
  IP_API_PROTO_UDP = 17,
  IP_API_PROTO_GRE = 47,
  IP_API_PROTO_ESP = 50,
  IP_API_PROTO_AH = 51,
  IP_API_PROTO_ICMP6 = 58,
  IP_API_PROTO_EIGRP = 88,
  IP_API_PROTO_OSPF = 89,
  IP_API_PROTO_SCTP = 132,
  IP_API_PROTO_RESERVED = 255,
} __attribute__((packed)) vapi_enum_ip_proto;

#endif

#ifndef defined_vapi_enum_tunnel_encap_decap_flags
#define defined_vapi_enum_tunnel_encap_decap_flags
typedef enum {
  TUNNEL_API_ENCAP_DECAP_FLAG_NONE = 0,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF = 1,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF = 2,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP = 4,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN = 8,
  TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN = 16,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH = 32,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT = 64,
  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL = 128,
} __attribute__((packed)) vapi_enum_tunnel_encap_decap_flags;

#endif

#ifndef defined_vapi_enum_tunnel_mode
#define defined_vapi_enum_tunnel_mode
typedef enum {
  TUNNEL_API_MODE_P2P = 0,
  TUNNEL_API_MODE_MP = 1,
} __attribute__((packed)) vapi_enum_tunnel_mode;

#endif

#ifndef defined_vapi_enum_tunnel_flags
#define defined_vapi_enum_tunnel_flags
typedef enum {
  TUNNEL_API_FLAG_TRACK_MTU = 1,
} __attribute__((packed)) vapi_enum_tunnel_flags;

#endif

#ifndef defined_vapi_enum_tunnel_flags
#define defined_vapi_enum_tunnel_flags
typedef enum {
  TUNNEL_API_FLAG_TRACK_MTU = 1,
} __attribute__((packed)) vapi_enum_tunnel_flags;

#endif

#ifndef defined_vapi_type_ip4_address
#define defined_vapi_type_ip4_address
typedef u8 vapi_type_ip4_address[4];

#endif

#ifndef defined_vapi_type_ip6_address
#define defined_vapi_type_ip6_address
typedef u8 vapi_type_ip6_address[16];

#endif

#ifndef defined_vapi_union_address_union
#define defined_vapi_union_address_union
typedef union {
  vapi_type_ip4_address ip4;
  vapi_type_ip6_address ip6;
} vapi_union_address_union;

#endif

#ifndef defined_vapi_type_prefix_matcher
#define defined_vapi_type_prefix_matcher
typedef struct __attribute__((__packed__)) {
  u8 le;
  u8 ge;
} vapi_type_prefix_matcher;

static inline void vapi_type_prefix_matcher_hton(vapi_type_prefix_matcher *msg)
{

}

static inline void vapi_type_prefix_matcher_ntoh(vapi_type_prefix_matcher *msg)
{

}
#endif

#ifndef defined_vapi_type_key
#define defined_vapi_type_key
typedef struct __attribute__((__packed__)) {
  u8 length;
  u8 data[128];
} vapi_type_key;

static inline void vapi_type_key_hton(vapi_type_key *msg)
{

}

static inline void vapi_type_key_ntoh(vapi_type_key *msg)
{

}
#endif

#ifndef defined_vapi_type_address
#define defined_vapi_type_address
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  vapi_union_address_union un;
} vapi_type_address;

static inline void vapi_type_address_hton(vapi_type_address *msg)
{

}

static inline void vapi_type_address_ntoh(vapi_type_address *msg)
{

}
#endif

#ifndef defined_vapi_type_prefix
#define defined_vapi_type_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_address address;
  u8 len;
} vapi_type_prefix;

static inline void vapi_type_prefix_hton(vapi_type_prefix *msg)
{

}

static inline void vapi_type_prefix_ntoh(vapi_type_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_address_and_mask
#define defined_vapi_type_ip4_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address addr;
  vapi_type_ip4_address mask;
} vapi_type_ip4_address_and_mask;

static inline void vapi_type_ip4_address_and_mask_hton(vapi_type_ip4_address_and_mask *msg)
{

}

static inline void vapi_type_ip4_address_and_mask_ntoh(vapi_type_ip4_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_ip6_address_and_mask
#define defined_vapi_type_ip6_address_and_mask
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address addr;
  vapi_type_ip6_address mask;
} vapi_type_ip6_address_and_mask;

static inline void vapi_type_ip6_address_and_mask_hton(vapi_type_ip6_address_and_mask *msg)
{

}

static inline void vapi_type_ip6_address_and_mask_ntoh(vapi_type_ip6_address_and_mask *msg)
{

}
#endif

#ifndef defined_vapi_type_mprefix
#define defined_vapi_type_mprefix
typedef struct __attribute__((__packed__)) {
  vapi_enum_address_family af;
  u16 grp_address_length;
  vapi_union_address_union grp_address;
  vapi_union_address_union src_address;
} vapi_type_mprefix;

static inline void vapi_type_mprefix_hton(vapi_type_mprefix *msg)
{
  msg->grp_address_length = htobe16(msg->grp_address_length);
}

static inline void vapi_type_mprefix_ntoh(vapi_type_mprefix *msg)
{
  msg->grp_address_length = be16toh(msg->grp_address_length);
}
#endif

#ifndef defined_vapi_type_ip6_prefix
#define defined_vapi_type_ip6_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip6_address address;
  u8 len;
} vapi_type_ip6_prefix;

static inline void vapi_type_ip6_prefix_hton(vapi_type_ip6_prefix *msg)
{

}

static inline void vapi_type_ip6_prefix_ntoh(vapi_type_ip6_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_ip4_prefix
#define defined_vapi_type_ip4_prefix
typedef struct __attribute__((__packed__)) {
  vapi_type_ip4_address address;
  u8 len;
} vapi_type_ip4_prefix;

static inline void vapi_type_ip4_prefix_hton(vapi_type_ip4_prefix *msg)
{

}

static inline void vapi_type_ip4_prefix_ntoh(vapi_type_ip4_prefix *msg)
{

}
#endif

#ifndef defined_vapi_type_interface_index
#define defined_vapi_type_interface_index
typedef u32 vapi_type_interface_index;

#endif

#ifndef defined_vapi_type_tunnel
#define defined_vapi_type_tunnel
typedef struct __attribute__((__packed__)) {
  u32 instance;
  vapi_type_address src;
  vapi_type_address dst;
  vapi_type_interface_index sw_if_index;
  u32 table_id;
  vapi_enum_tunnel_encap_decap_flags encap_decap_flags;
  vapi_enum_tunnel_mode mode;
  vapi_enum_tunnel_flags flags;
  vapi_enum_ip_dscp dscp;
  u8 hop_limit;
} vapi_type_tunnel;

static inline void vapi_type_tunnel_hton(vapi_type_tunnel *msg)
{
  msg->instance = htobe32(msg->instance);
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->table_id = htobe32(msg->table_id);
}

static inline void vapi_type_tunnel_ntoh(vapi_type_tunnel *msg)
{
  msg->instance = be32toh(msg->instance);
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->table_id = be32toh(msg->table_id);
}
#endif

#ifndef defined_vapi_type_ipsec_spd_entry
#define defined_vapi_type_ipsec_spd_entry
typedef struct __attribute__((__packed__)) {
  u32 spd_id;
  i32 priority;
  bool is_outbound;
  u32 sa_id;
  vapi_enum_ipsec_spd_action policy;
  u8 protocol;
  vapi_type_address remote_address_start;
  vapi_type_address remote_address_stop;
  vapi_type_address local_address_start;
  vapi_type_address local_address_stop;
  u16 remote_port_start;
  u16 remote_port_stop;
  u16 local_port_start;
  u16 local_port_stop;
} vapi_type_ipsec_spd_entry;

static inline void vapi_type_ipsec_spd_entry_hton(vapi_type_ipsec_spd_entry *msg)
{
  msg->spd_id = htobe32(msg->spd_id);
  msg->priority = htobe32(msg->priority);
  msg->sa_id = htobe32(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)htobe32(msg->policy);
  msg->remote_port_start = htobe16(msg->remote_port_start);
  msg->remote_port_stop = htobe16(msg->remote_port_stop);
  msg->local_port_start = htobe16(msg->local_port_start);
  msg->local_port_stop = htobe16(msg->local_port_stop);
}

static inline void vapi_type_ipsec_spd_entry_ntoh(vapi_type_ipsec_spd_entry *msg)
{
  msg->spd_id = be32toh(msg->spd_id);
  msg->priority = be32toh(msg->priority);
  msg->sa_id = be32toh(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)be32toh(msg->policy);
  msg->remote_port_start = be16toh(msg->remote_port_start);
  msg->remote_port_stop = be16toh(msg->remote_port_stop);
  msg->local_port_start = be16toh(msg->local_port_start);
  msg->local_port_stop = be16toh(msg->local_port_stop);
}
#endif

#ifndef defined_vapi_type_ipsec_spd_entry_v2
#define defined_vapi_type_ipsec_spd_entry_v2
typedef struct __attribute__((__packed__)) {
  u32 spd_id;
  i32 priority;
  bool is_outbound;
  u32 sa_id;
  vapi_enum_ipsec_spd_action policy;
  u8 protocol;
  vapi_type_address remote_address_start;
  vapi_type_address remote_address_stop;
  vapi_type_address local_address_start;
  vapi_type_address local_address_stop;
  u16 remote_port_start;
  u16 remote_port_stop;
  u16 local_port_start;
  u16 local_port_stop;
} vapi_type_ipsec_spd_entry_v2;

static inline void vapi_type_ipsec_spd_entry_v2_hton(vapi_type_ipsec_spd_entry_v2 *msg)
{
  msg->spd_id = htobe32(msg->spd_id);
  msg->priority = htobe32(msg->priority);
  msg->sa_id = htobe32(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)htobe32(msg->policy);
  msg->remote_port_start = htobe16(msg->remote_port_start);
  msg->remote_port_stop = htobe16(msg->remote_port_stop);
  msg->local_port_start = htobe16(msg->local_port_start);
  msg->local_port_stop = htobe16(msg->local_port_stop);
}

static inline void vapi_type_ipsec_spd_entry_v2_ntoh(vapi_type_ipsec_spd_entry_v2 *msg)
{
  msg->spd_id = be32toh(msg->spd_id);
  msg->priority = be32toh(msg->priority);
  msg->sa_id = be32toh(msg->sa_id);
  msg->policy = (vapi_enum_ipsec_spd_action)be32toh(msg->policy);
  msg->remote_port_start = be16toh(msg->remote_port_start);
  msg->remote_port_stop = be16toh(msg->remote_port_stop);
  msg->local_port_start = be16toh(msg->local_port_start);
  msg->local_port_stop = be16toh(msg->local_port_stop);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry
#define defined_vapi_type_ipsec_sad_entry
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_address tunnel_src;
  vapi_type_address tunnel_dst;
  u32 tx_table_id;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
} vapi_type_ipsec_sad_entry;

static inline void vapi_type_ipsec_sad_entry_hton(vapi_type_ipsec_sad_entry *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  msg->tx_table_id = htobe32(msg->tx_table_id);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
}

static inline void vapi_type_ipsec_sad_entry_ntoh(vapi_type_ipsec_sad_entry *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  msg->tx_table_id = be32toh(msg->tx_table_id);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry_v2
#define defined_vapi_type_ipsec_sad_entry_v2
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_address tunnel_src;
  vapi_type_address tunnel_dst;
  vapi_enum_tunnel_encap_decap_flags tunnel_flags;
  vapi_enum_ip_dscp dscp;
  u32 tx_table_id;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
} vapi_type_ipsec_sad_entry_v2;

static inline void vapi_type_ipsec_sad_entry_v2_hton(vapi_type_ipsec_sad_entry_v2 *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  msg->tx_table_id = htobe32(msg->tx_table_id);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
}

static inline void vapi_type_ipsec_sad_entry_v2_ntoh(vapi_type_ipsec_sad_entry_v2 *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  msg->tx_table_id = be32toh(msg->tx_table_id);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry_v3
#define defined_vapi_type_ipsec_sad_entry_v3
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_tunnel tunnel;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
} vapi_type_ipsec_sad_entry_v3;

static inline void vapi_type_ipsec_sad_entry_v3_hton(vapi_type_ipsec_sad_entry_v3 *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  vapi_type_tunnel_hton(&msg->tunnel);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
}

static inline void vapi_type_ipsec_sad_entry_v3_ntoh(vapi_type_ipsec_sad_entry_v3 *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  vapi_type_tunnel_ntoh(&msg->tunnel);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
}
#endif

#ifndef defined_vapi_type_ipsec_sad_entry_v4
#define defined_vapi_type_ipsec_sad_entry_v4
typedef struct __attribute__((__packed__)) {
  u32 sad_id;
  u32 spi;
  vapi_enum_ipsec_proto protocol;
  vapi_enum_ipsec_crypto_alg crypto_algorithm;
  vapi_type_key crypto_key;
  vapi_enum_ipsec_integ_alg integrity_algorithm;
  vapi_type_key integrity_key;
  vapi_enum_ipsec_sad_flags flags;
  vapi_type_tunnel tunnel;
  u32 salt;
  u16 udp_src_port;
  u16 udp_dst_port;
  u32 anti_replay_window_size;
} vapi_type_ipsec_sad_entry_v4;

static inline void vapi_type_ipsec_sad_entry_v4_hton(vapi_type_ipsec_sad_entry_v4 *msg)
{
  msg->sad_id = htobe32(msg->sad_id);
  msg->spi = htobe32(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)htobe32(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)htobe32(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)htobe32(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)htobe32(msg->flags);
  vapi_type_tunnel_hton(&msg->tunnel);
  msg->salt = htobe32(msg->salt);
  msg->udp_src_port = htobe16(msg->udp_src_port);
  msg->udp_dst_port = htobe16(msg->udp_dst_port);
  msg->anti_replay_window_size = htobe32(msg->anti_replay_window_size);
}

static inline void vapi_type_ipsec_sad_entry_v4_ntoh(vapi_type_ipsec_sad_entry_v4 *msg)
{
  msg->sad_id = be32toh(msg->sad_id);
  msg->spi = be32toh(msg->spi);
  msg->protocol = (vapi_enum_ipsec_proto)be32toh(msg->protocol);
  msg->crypto_algorithm = (vapi_enum_ipsec_crypto_alg)be32toh(msg->crypto_algorithm);
  msg->integrity_algorithm = (vapi_enum_ipsec_integ_alg)be32toh(msg->integrity_algorithm);
  msg->flags = (vapi_enum_ipsec_sad_flags)be32toh(msg->flags);
  vapi_type_tunnel_ntoh(&msg->tunnel);
  msg->salt = be32toh(msg->salt);
  msg->udp_src_port = be16toh(msg->udp_src_port);
  msg->udp_dst_port = be16toh(msg->udp_dst_port);
  msg->anti_replay_window_size = be32toh(msg->anti_replay_window_size);
}
#endif

#ifndef defined_vapi_type_ipsec_tunnel_protect
#define defined_vapi_type_ipsec_tunnel_protect
typedef struct __attribute__((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address nh;
  u32 sa_out;
  u8 n_sa_in;
  u32 sa_in[0];
} vapi_type_ipsec_tunnel_protect;

static inline void vapi_type_ipsec_tunnel_protect_hton(vapi_type_ipsec_tunnel_protect *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->sa_out = htobe32(msg->sa_out);
  do { unsigned i; for (i = 0; i < msg->n_sa_in; ++i) { msg->sa_in[i] = htobe32(msg->sa_in[i]); } } while(0);
}

static inline void vapi_type_ipsec_tunnel_protect_ntoh(vapi_type_ipsec_tunnel_protect *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->sa_out = be32toh(msg->sa_out);
  do { unsigned i; for (i = 0; i < msg->n_sa_in; ++i) { msg->sa_in[i] = be32toh(msg->sa_in[i]); } } while(0);
}
#endif

#ifndef defined_vapi_type_ipsec_itf
#define defined_vapi_type_ipsec_itf
typedef struct __attribute__((__packed__)) {
  u32 user_instance;
  vapi_enum_tunnel_mode mode;
  vapi_type_interface_index sw_if_index;
} vapi_type_ipsec_itf;

static inline void vapi_type_ipsec_itf_hton(vapi_type_ipsec_itf *msg)
{
  msg->user_instance = htobe32(msg->user_instance);
  msg->sw_if_index = htobe32(msg->sw_if_index);
}

static inline void vapi_type_ipsec_itf_ntoh(vapi_type_ipsec_itf *msg)
{
  msg->user_instance = be32toh(msg->user_instance);
  msg->sw_if_index = be32toh(msg->sw_if_index);
}
#endif

#ifndef defined_vapi_type_address_with_prefix
#define defined_vapi_type_address_with_prefix
typedef vapi_type_prefix vapi_type_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip4_address_with_prefix
#define defined_vapi_type_ip4_address_with_prefix
typedef vapi_type_ip4_prefix vapi_type_ip4_address_with_prefix;

#endif

#ifndef defined_vapi_type_ip6_address_with_prefix
#define defined_vapi_type_ip6_address_with_prefix
typedef vapi_type_ip6_prefix vapi_type_ip6_address_with_prefix;

#endif

#ifndef defined_vapi_msg_ipsec_spd_add_del_reply
#define defined_vapi_msg_ipsec_spd_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_spd_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_spd_add_del_reply payload;
} vapi_msg_ipsec_spd_add_del_reply;

static inline void vapi_msg_ipsec_spd_add_del_reply_payload_hton(vapi_payload_ipsec_spd_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_spd_add_del_reply_payload_ntoh(vapi_payload_ipsec_spd_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_spd_add_del_reply_hton(vapi_msg_ipsec_spd_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_spd_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_add_del_reply_ntoh(vapi_msg_ipsec_spd_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_add_del_reply_msg_size(vapi_msg_ipsec_spd_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_add_del_reply_msg_size(vapi_msg_ipsec_spd_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_add_del_reply));
      return -1;
    }
  if (vapi_calc_ipsec_spd_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_add_del_reply()
{
  static const char name[] = "ipsec_spd_add_del_reply";
  static const char name_with_crc[] = "ipsec_spd_add_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_spd_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_add_del_reply = vapi_register_msg(&__vapi_metadata_ipsec_spd_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_add_del_reply", vapi_msg_id_ipsec_spd_add_del_reply);
}

static inline void vapi_set_vapi_msg_ipsec_spd_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_spd_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_spd_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_spd_add_del
#define defined_vapi_msg_ipsec_spd_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  u32 spd_id; 
} vapi_payload_ipsec_spd_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_spd_add_del payload;
} vapi_msg_ipsec_spd_add_del;

static inline void vapi_msg_ipsec_spd_add_del_payload_hton(vapi_payload_ipsec_spd_add_del *payload)
{
  payload->spd_id = htobe32(payload->spd_id);
}

static inline void vapi_msg_ipsec_spd_add_del_payload_ntoh(vapi_payload_ipsec_spd_add_del *payload)
{
  payload->spd_id = be32toh(payload->spd_id);
}

static inline void vapi_msg_ipsec_spd_add_del_hton(vapi_msg_ipsec_spd_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_spd_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_add_del_ntoh(vapi_msg_ipsec_spd_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_add_del_msg_size(vapi_msg_ipsec_spd_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_add_del_msg_size(vapi_msg_ipsec_spd_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_add_del));
      return -1;
    }
  if (vapi_calc_ipsec_spd_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_spd_add_del* vapi_alloc_ipsec_spd_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_spd_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_spd_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_spd_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_spd_add_del);

  return msg;
}

static inline vapi_error_e vapi_ipsec_spd_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_spd_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_spd_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_spd_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_spd_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_spd_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_add_del()
{
  static const char name[] = "ipsec_spd_add_del";
  static const char name_with_crc[] = "ipsec_spd_add_del_20e89a95";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_spd_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_add_del = vapi_register_msg(&__vapi_metadata_ipsec_spd_add_del);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_add_del", vapi_msg_id_ipsec_spd_add_del);
}
#endif

#ifndef defined_vapi_msg_ipsec_interface_add_del_spd_reply
#define defined_vapi_msg_ipsec_interface_add_del_spd_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_interface_add_del_spd_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_interface_add_del_spd_reply payload;
} vapi_msg_ipsec_interface_add_del_spd_reply;

static inline void vapi_msg_ipsec_interface_add_del_spd_reply_payload_hton(vapi_payload_ipsec_interface_add_del_spd_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_interface_add_del_spd_reply_payload_ntoh(vapi_payload_ipsec_interface_add_del_spd_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_interface_add_del_spd_reply_hton(vapi_msg_ipsec_interface_add_del_spd_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_interface_add_del_spd_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_interface_add_del_spd_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_interface_add_del_spd_reply_ntoh(vapi_msg_ipsec_interface_add_del_spd_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_interface_add_del_spd_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_interface_add_del_spd_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_interface_add_del_spd_reply_msg_size(vapi_msg_ipsec_interface_add_del_spd_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_interface_add_del_spd_reply_msg_size(vapi_msg_ipsec_interface_add_del_spd_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_interface_add_del_spd_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_interface_add_del_spd_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_interface_add_del_spd_reply));
      return -1;
    }
  if (vapi_calc_ipsec_interface_add_del_spd_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_interface_add_del_spd_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_interface_add_del_spd_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_interface_add_del_spd_reply()
{
  static const char name[] = "ipsec_interface_add_del_spd_reply";
  static const char name_with_crc[] = "ipsec_interface_add_del_spd_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_interface_add_del_spd_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_interface_add_del_spd_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_interface_add_del_spd_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_interface_add_del_spd_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_interface_add_del_spd_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_interface_add_del_spd_reply = vapi_register_msg(&__vapi_metadata_ipsec_interface_add_del_spd_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_interface_add_del_spd_reply", vapi_msg_id_ipsec_interface_add_del_spd_reply);
}

static inline void vapi_set_vapi_msg_ipsec_interface_add_del_spd_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_interface_add_del_spd_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_interface_add_del_spd_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_interface_add_del_spd
#define defined_vapi_msg_ipsec_interface_add_del_spd
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_interface_index sw_if_index;
  u32 spd_id; 
} vapi_payload_ipsec_interface_add_del_spd;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_interface_add_del_spd payload;
} vapi_msg_ipsec_interface_add_del_spd;

static inline void vapi_msg_ipsec_interface_add_del_spd_payload_hton(vapi_payload_ipsec_interface_add_del_spd *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->spd_id = htobe32(payload->spd_id);
}

static inline void vapi_msg_ipsec_interface_add_del_spd_payload_ntoh(vapi_payload_ipsec_interface_add_del_spd *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->spd_id = be32toh(payload->spd_id);
}

static inline void vapi_msg_ipsec_interface_add_del_spd_hton(vapi_msg_ipsec_interface_add_del_spd *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_interface_add_del_spd'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_interface_add_del_spd_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_interface_add_del_spd_ntoh(vapi_msg_ipsec_interface_add_del_spd *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_interface_add_del_spd'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_interface_add_del_spd_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_interface_add_del_spd_msg_size(vapi_msg_ipsec_interface_add_del_spd *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_interface_add_del_spd_msg_size(vapi_msg_ipsec_interface_add_del_spd *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_interface_add_del_spd) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_interface_add_del_spd' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_interface_add_del_spd));
      return -1;
    }
  if (vapi_calc_ipsec_interface_add_del_spd_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_interface_add_del_spd' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_interface_add_del_spd_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_interface_add_del_spd* vapi_alloc_ipsec_interface_add_del_spd(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_interface_add_del_spd *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_interface_add_del_spd);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_interface_add_del_spd*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_interface_add_del_spd);

  return msg;
}

static inline vapi_error_e vapi_ipsec_interface_add_del_spd(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_interface_add_del_spd *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_interface_add_del_spd_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_interface_add_del_spd_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_interface_add_del_spd_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_interface_add_del_spd_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_interface_add_del_spd()
{
  static const char name[] = "ipsec_interface_add_del_spd";
  static const char name_with_crc[] = "ipsec_interface_add_del_spd_80f80cbb";
  static vapi_message_desc_t __vapi_metadata_ipsec_interface_add_del_spd = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_interface_add_del_spd, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_interface_add_del_spd_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_interface_add_del_spd_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_interface_add_del_spd_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_interface_add_del_spd = vapi_register_msg(&__vapi_metadata_ipsec_interface_add_del_spd);
  VAPI_DBG("Assigned msg id %d to ipsec_interface_add_del_spd", vapi_msg_id_ipsec_interface_add_del_spd);
}
#endif

#ifndef defined_vapi_msg_ipsec_spd_entry_add_del_reply
#define defined_vapi_msg_ipsec_spd_entry_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_spd_entry_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_spd_entry_add_del_reply payload;
} vapi_msg_ipsec_spd_entry_add_del_reply;

static inline void vapi_msg_ipsec_spd_entry_add_del_reply_payload_hton(vapi_payload_ipsec_spd_entry_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_reply_payload_ntoh(vapi_payload_ipsec_spd_entry_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_reply_hton(vapi_msg_ipsec_spd_entry_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_reply_ntoh(vapi_msg_ipsec_spd_entry_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_entry_add_del_reply_msg_size(vapi_msg_ipsec_spd_entry_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_entry_add_del_reply_msg_size(vapi_msg_ipsec_spd_entry_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_entry_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_entry_add_del_reply));
      return -1;
    }
  if (vapi_calc_ipsec_spd_entry_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_entry_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_entry_add_del_reply()
{
  static const char name[] = "ipsec_spd_entry_add_del_reply";
  static const char name_with_crc[] = "ipsec_spd_entry_add_del_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_entry_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_spd_entry_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_entry_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_entry_add_del_reply = vapi_register_msg(&__vapi_metadata_ipsec_spd_entry_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_entry_add_del_reply", vapi_msg_id_ipsec_spd_entry_add_del_reply);
}

static inline void vapi_set_vapi_msg_ipsec_spd_entry_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_spd_entry_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_spd_entry_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_spd_entry_add_del
#define defined_vapi_msg_ipsec_spd_entry_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ipsec_spd_entry entry; 
} vapi_payload_ipsec_spd_entry_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_spd_entry_add_del payload;
} vapi_msg_ipsec_spd_entry_add_del;

static inline void vapi_msg_ipsec_spd_entry_add_del_payload_hton(vapi_payload_ipsec_spd_entry_add_del *payload)
{
  vapi_type_ipsec_spd_entry_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_payload_ntoh(vapi_payload_ipsec_spd_entry_add_del *payload)
{
  vapi_type_ipsec_spd_entry_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_hton(vapi_msg_ipsec_spd_entry_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_ntoh(vapi_msg_ipsec_spd_entry_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_entry_add_del_msg_size(vapi_msg_ipsec_spd_entry_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_entry_add_del_msg_size(vapi_msg_ipsec_spd_entry_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_entry_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_entry_add_del));
      return -1;
    }
  if (vapi_calc_ipsec_spd_entry_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_entry_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_spd_entry_add_del* vapi_alloc_ipsec_spd_entry_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_spd_entry_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_spd_entry_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_spd_entry_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_spd_entry_add_del);

  return msg;
}

static inline vapi_error_e vapi_ipsec_spd_entry_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_spd_entry_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_spd_entry_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_spd_entry_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_spd_entry_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_spd_entry_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_entry_add_del()
{
  static const char name[] = "ipsec_spd_entry_add_del";
  static const char name_with_crc[] = "ipsec_spd_entry_add_del_338b7411";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_entry_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_spd_entry_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_entry_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_entry_add_del = vapi_register_msg(&__vapi_metadata_ipsec_spd_entry_add_del);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_entry_add_del", vapi_msg_id_ipsec_spd_entry_add_del);
}
#endif

#ifndef defined_vapi_msg_ipsec_spd_entry_add_del_v2_reply
#define defined_vapi_msg_ipsec_spd_entry_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_spd_entry_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_spd_entry_add_del_v2_reply payload;
} vapi_msg_ipsec_spd_entry_add_del_v2_reply;

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_reply_payload_hton(vapi_payload_ipsec_spd_entry_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_reply_payload_ntoh(vapi_payload_ipsec_spd_entry_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_reply_hton(vapi_msg_ipsec_spd_entry_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_reply_ntoh(vapi_msg_ipsec_spd_entry_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_entry_add_del_v2_reply_msg_size(vapi_msg_ipsec_spd_entry_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_entry_add_del_v2_reply_msg_size(vapi_msg_ipsec_spd_entry_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_entry_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_entry_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_ipsec_spd_entry_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_entry_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_entry_add_del_v2_reply()
{
  static const char name[] = "ipsec_spd_entry_add_del_v2_reply";
  static const char name_with_crc[] = "ipsec_spd_entry_add_del_v2_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_entry_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_spd_entry_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_entry_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_entry_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_ipsec_spd_entry_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_entry_add_del_v2_reply", vapi_msg_id_ipsec_spd_entry_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_ipsec_spd_entry_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_spd_entry_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_spd_entry_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_spd_entry_add_del_v2
#define defined_vapi_msg_ipsec_spd_entry_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ipsec_spd_entry_v2 entry; 
} vapi_payload_ipsec_spd_entry_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_spd_entry_add_del_v2 payload;
} vapi_msg_ipsec_spd_entry_add_del_v2;

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_payload_hton(vapi_payload_ipsec_spd_entry_add_del_v2 *payload)
{
  vapi_type_ipsec_spd_entry_v2_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_payload_ntoh(vapi_payload_ipsec_spd_entry_add_del_v2 *payload)
{
  vapi_type_ipsec_spd_entry_v2_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_hton(vapi_msg_ipsec_spd_entry_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_entry_add_del_v2_ntoh(vapi_msg_ipsec_spd_entry_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_entry_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_entry_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_entry_add_del_v2_msg_size(vapi_msg_ipsec_spd_entry_add_del_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_entry_add_del_v2_msg_size(vapi_msg_ipsec_spd_entry_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_entry_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_entry_add_del_v2));
      return -1;
    }
  if (vapi_calc_ipsec_spd_entry_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_entry_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_entry_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_spd_entry_add_del_v2* vapi_alloc_ipsec_spd_entry_add_del_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_spd_entry_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_spd_entry_add_del_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_spd_entry_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_spd_entry_add_del_v2);

  return msg;
}

static inline vapi_error_e vapi_ipsec_spd_entry_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_spd_entry_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_spd_entry_add_del_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_spd_entry_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_spd_entry_add_del_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_spd_entry_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_entry_add_del_v2()
{
  static const char name[] = "ipsec_spd_entry_add_del_v2";
  static const char name_with_crc[] = "ipsec_spd_entry_add_del_v2_7bfe69fc";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_entry_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_spd_entry_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_entry_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_entry_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_entry_add_del_v2 = vapi_register_msg(&__vapi_metadata_ipsec_spd_entry_add_del_v2);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_entry_add_del_v2", vapi_msg_id_ipsec_spd_entry_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_ipsec_spds_details
#define defined_vapi_msg_ipsec_spds_details
typedef struct __attribute__ ((__packed__)) {
  u32 spd_id;
  u32 npolicies; 
} vapi_payload_ipsec_spds_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_spds_details payload;
} vapi_msg_ipsec_spds_details;

static inline void vapi_msg_ipsec_spds_details_payload_hton(vapi_payload_ipsec_spds_details *payload)
{
  payload->spd_id = htobe32(payload->spd_id);
  payload->npolicies = htobe32(payload->npolicies);
}

static inline void vapi_msg_ipsec_spds_details_payload_ntoh(vapi_payload_ipsec_spds_details *payload)
{
  payload->spd_id = be32toh(payload->spd_id);
  payload->npolicies = be32toh(payload->npolicies);
}

static inline void vapi_msg_ipsec_spds_details_hton(vapi_msg_ipsec_spds_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spds_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_spds_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spds_details_ntoh(vapi_msg_ipsec_spds_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spds_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_spds_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spds_details_msg_size(vapi_msg_ipsec_spds_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spds_details_msg_size(vapi_msg_ipsec_spds_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spds_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spds_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spds_details));
      return -1;
    }
  if (vapi_calc_ipsec_spds_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spds_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spds_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_spds_details()
{
  static const char name[] = "ipsec_spds_details";
  static const char name_with_crc[] = "ipsec_spds_details_a04bb254";
  static vapi_message_desc_t __vapi_metadata_ipsec_spds_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_spds_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spds_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spds_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spds_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spds_details = vapi_register_msg(&__vapi_metadata_ipsec_spds_details);
  VAPI_DBG("Assigned msg id %d to ipsec_spds_details", vapi_msg_id_ipsec_spds_details);
}

static inline void vapi_set_vapi_msg_ipsec_spds_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_spds_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_spds_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_spds_dump
#define defined_vapi_msg_ipsec_spds_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ipsec_spds_dump;

static inline void vapi_msg_ipsec_spds_dump_hton(vapi_msg_ipsec_spds_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spds_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ipsec_spds_dump_ntoh(vapi_msg_ipsec_spds_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spds_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ipsec_spds_dump_msg_size(vapi_msg_ipsec_spds_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spds_dump_msg_size(vapi_msg_ipsec_spds_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spds_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spds_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spds_dump));
      return -1;
    }
  if (vapi_calc_ipsec_spds_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spds_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spds_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_spds_dump* vapi_alloc_ipsec_spds_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_spds_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_spds_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_spds_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_spds_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_spds_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_spds_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_spds_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_spds_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_spds_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_spds_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_spds_dump()
{
  static const char name[] = "ipsec_spds_dump";
  static const char name_with_crc[] = "ipsec_spds_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ipsec_spds_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ipsec_spds_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spds_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spds_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spds_dump = vapi_register_msg(&__vapi_metadata_ipsec_spds_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_spds_dump", vapi_msg_id_ipsec_spds_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_spd_details
#define defined_vapi_msg_ipsec_spd_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_spd_entry entry; 
} vapi_payload_ipsec_spd_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_spd_details payload;
} vapi_msg_ipsec_spd_details;

static inline void vapi_msg_ipsec_spd_details_payload_hton(vapi_payload_ipsec_spd_details *payload)
{
  vapi_type_ipsec_spd_entry_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_spd_details_payload_ntoh(vapi_payload_ipsec_spd_details *payload)
{
  vapi_type_ipsec_spd_entry_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_spd_details_hton(vapi_msg_ipsec_spd_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_spd_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_details_ntoh(vapi_msg_ipsec_spd_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_details_msg_size(vapi_msg_ipsec_spd_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_details_msg_size(vapi_msg_ipsec_spd_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_details));
      return -1;
    }
  if (vapi_calc_ipsec_spd_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_details()
{
  static const char name[] = "ipsec_spd_details";
  static const char name_with_crc[] = "ipsec_spd_details_5813d7a2";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_spd_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_details = vapi_register_msg(&__vapi_metadata_ipsec_spd_details);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_details", vapi_msg_id_ipsec_spd_details);
}

static inline void vapi_set_vapi_msg_ipsec_spd_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_spd_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_spd_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_spd_dump
#define defined_vapi_msg_ipsec_spd_dump
typedef struct __attribute__ ((__packed__)) {
  u32 spd_id;
  u32 sa_id; 
} vapi_payload_ipsec_spd_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_spd_dump payload;
} vapi_msg_ipsec_spd_dump;

static inline void vapi_msg_ipsec_spd_dump_payload_hton(vapi_payload_ipsec_spd_dump *payload)
{
  payload->spd_id = htobe32(payload->spd_id);
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_spd_dump_payload_ntoh(vapi_payload_ipsec_spd_dump *payload)
{
  payload->spd_id = be32toh(payload->spd_id);
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_spd_dump_hton(vapi_msg_ipsec_spd_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_spd_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_dump_ntoh(vapi_msg_ipsec_spd_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_dump_msg_size(vapi_msg_ipsec_spd_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_dump_msg_size(vapi_msg_ipsec_spd_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_dump));
      return -1;
    }
  if (vapi_calc_ipsec_spd_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_spd_dump* vapi_alloc_ipsec_spd_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_spd_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_spd_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_spd_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_spd_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_spd_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_spd_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_spd_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_spd_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_spd_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_spd_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_dump()
{
  static const char name[] = "ipsec_spd_dump";
  static const char name_with_crc[] = "ipsec_spd_dump_afefbf7d";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_spd_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_dump = vapi_register_msg(&__vapi_metadata_ipsec_spd_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_dump", vapi_msg_id_ipsec_spd_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_del_reply
#define defined_vapi_msg_ipsec_sad_entry_add_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_sad_entry_add_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_add_del_reply payload;
} vapi_msg_ipsec_sad_entry_add_del_reply;

static inline void vapi_msg_ipsec_sad_entry_add_del_reply_payload_hton(vapi_payload_ipsec_sad_entry_add_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_add_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_reply_hton(vapi_msg_ipsec_sad_entry_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_reply_ntoh(vapi_msg_ipsec_sad_entry_add_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_del_reply_msg_size(vapi_msg_ipsec_sad_entry_add_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_del_reply_msg_size(vapi_msg_ipsec_sad_entry_add_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_del_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_del_reply()
{
  static const char name[] = "ipsec_sad_entry_add_del_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_add_del_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_del_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_del_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_del_reply", vapi_msg_id_ipsec_sad_entry_add_del_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_add_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_add_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_add_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_del
#define defined_vapi_msg_ipsec_sad_entry_add_del
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ipsec_sad_entry entry; 
} vapi_payload_ipsec_sad_entry_add_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_add_del payload;
} vapi_msg_ipsec_sad_entry_add_del;

static inline void vapi_msg_ipsec_sad_entry_add_del_payload_hton(vapi_payload_ipsec_sad_entry_add_del *payload)
{
  vapi_type_ipsec_sad_entry_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_payload_ntoh(vapi_payload_ipsec_sad_entry_add_del *payload)
{
  vapi_type_ipsec_sad_entry_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_hton(vapi_msg_ipsec_sad_entry_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_ntoh(vapi_msg_ipsec_sad_entry_add_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_del_msg_size(vapi_msg_ipsec_sad_entry_add_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_del_msg_size(vapi_msg_ipsec_sad_entry_add_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_del));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_add_del* vapi_alloc_ipsec_sad_entry_add_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_add_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_add_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_add_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_add_del);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_add_del(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_add_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_add_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_add_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_add_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_add_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_del()
{
  static const char name[] = "ipsec_sad_entry_add_del";
  static const char name_with_crc[] = "ipsec_sad_entry_add_del_ab64b5c6";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_del = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_del);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_del", vapi_msg_id_ipsec_sad_entry_add_del);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_del_v2_reply
#define defined_vapi_msg_ipsec_sad_entry_add_del_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_sad_entry_add_del_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_add_del_v2_reply payload;
} vapi_msg_ipsec_sad_entry_add_del_v2_reply;

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_reply_payload_hton(vapi_payload_ipsec_sad_entry_add_del_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_add_del_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_reply_hton(vapi_msg_ipsec_sad_entry_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_reply_ntoh(vapi_msg_ipsec_sad_entry_add_del_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_del_v2_reply_msg_size(vapi_msg_ipsec_sad_entry_add_del_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_del_v2_reply_msg_size(vapi_msg_ipsec_sad_entry_add_del_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_del_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_del_v2_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_del_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_del_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_del_v2_reply()
{
  static const char name[] = "ipsec_sad_entry_add_del_v2_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_add_del_v2_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_del_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_del_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_del_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_del_v2_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_del_v2_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_del_v2_reply", vapi_msg_id_ipsec_sad_entry_add_del_v2_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_add_del_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_add_del_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_add_del_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_del_v2
#define defined_vapi_msg_ipsec_sad_entry_add_del_v2
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ipsec_sad_entry_v2 entry; 
} vapi_payload_ipsec_sad_entry_add_del_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_add_del_v2 payload;
} vapi_msg_ipsec_sad_entry_add_del_v2;

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_payload_hton(vapi_payload_ipsec_sad_entry_add_del_v2 *payload)
{
  vapi_type_ipsec_sad_entry_v2_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_payload_ntoh(vapi_payload_ipsec_sad_entry_add_del_v2 *payload)
{
  vapi_type_ipsec_sad_entry_v2_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_hton(vapi_msg_ipsec_sad_entry_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v2_ntoh(vapi_msg_ipsec_sad_entry_add_del_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_del_v2_msg_size(vapi_msg_ipsec_sad_entry_add_del_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_del_v2_msg_size(vapi_msg_ipsec_sad_entry_add_del_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_del_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_del_v2));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_del_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_del_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_add_del_v2* vapi_alloc_ipsec_sad_entry_add_del_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_add_del_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_add_del_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_add_del_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_add_del_v2);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_add_del_v2(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_add_del_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_add_del_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_add_del_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_add_del_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_add_del_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_del_v2()
{
  static const char name[] = "ipsec_sad_entry_add_del_v2";
  static const char name_with_crc[] = "ipsec_sad_entry_add_del_v2_aca78b27";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_del_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_del_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_del_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v2_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_del_v2 = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_del_v2);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_del_v2", vapi_msg_id_ipsec_sad_entry_add_del_v2);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_del_v3_reply
#define defined_vapi_msg_ipsec_sad_entry_add_del_v3_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_sad_entry_add_del_v3_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_add_del_v3_reply payload;
} vapi_msg_ipsec_sad_entry_add_del_v3_reply;

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_reply_payload_hton(vapi_payload_ipsec_sad_entry_add_del_v3_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_add_del_v3_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_reply_hton(vapi_msg_ipsec_sad_entry_add_del_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v3_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v3_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_reply_ntoh(vapi_msg_ipsec_sad_entry_add_del_v3_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v3_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v3_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_del_v3_reply_msg_size(vapi_msg_ipsec_sad_entry_add_del_v3_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_del_v3_reply_msg_size(vapi_msg_ipsec_sad_entry_add_del_v3_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_del_v3_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_del_v3_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_del_v3_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v3_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_del_v3_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_del_v3_reply()
{
  static const char name[] = "ipsec_sad_entry_add_del_v3_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_add_del_v3_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_del_v3_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_del_v3_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_del_v3_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v3_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v3_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_del_v3_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_del_v3_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_del_v3_reply", vapi_msg_id_ipsec_sad_entry_add_del_v3_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_add_del_v3_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_add_del_v3_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_add_del_v3_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_del_v3
#define defined_vapi_msg_ipsec_sad_entry_add_del_v3
typedef struct __attribute__ ((__packed__)) {
  bool is_add;
  vapi_type_ipsec_sad_entry_v3 entry; 
} vapi_payload_ipsec_sad_entry_add_del_v3;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_add_del_v3 payload;
} vapi_msg_ipsec_sad_entry_add_del_v3;

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_payload_hton(vapi_payload_ipsec_sad_entry_add_del_v3 *payload)
{
  vapi_type_ipsec_sad_entry_v3_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_payload_ntoh(vapi_payload_ipsec_sad_entry_add_del_v3 *payload)
{
  vapi_type_ipsec_sad_entry_v3_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_hton(vapi_msg_ipsec_sad_entry_add_del_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v3'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v3_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_del_v3_ntoh(vapi_msg_ipsec_sad_entry_add_del_v3 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_del_v3'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_del_v3_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_del_v3_msg_size(vapi_msg_ipsec_sad_entry_add_del_v3 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_del_v3_msg_size(vapi_msg_ipsec_sad_entry_add_del_v3 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_del_v3) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_del_v3));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_del_v3_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_del_v3' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_del_v3_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_add_del_v3* vapi_alloc_ipsec_sad_entry_add_del_v3(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_add_del_v3 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_add_del_v3);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_add_del_v3*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_add_del_v3);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_add_del_v3(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_add_del_v3 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_add_del_v3_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_add_del_v3_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_add_del_v3_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_add_del_v3_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_del_v3()
{
  static const char name[] = "ipsec_sad_entry_add_del_v3";
  static const char name_with_crc[] = "ipsec_sad_entry_add_del_v3_c77ebd92";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_del_v3 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_del_v3, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_del_v3_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v3_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_del_v3_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_del_v3 = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_del_v3);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_del_v3", vapi_msg_id_ipsec_sad_entry_add_del_v3);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_reply
#define defined_vapi_msg_ipsec_sad_entry_add_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_sad_entry_add_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_add_reply payload;
} vapi_msg_ipsec_sad_entry_add_reply;

static inline void vapi_msg_ipsec_sad_entry_add_reply_payload_hton(vapi_payload_ipsec_sad_entry_add_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_add_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_reply_hton(vapi_msg_ipsec_sad_entry_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_reply_ntoh(vapi_msg_ipsec_sad_entry_add_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_reply_msg_size(vapi_msg_ipsec_sad_entry_add_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_reply_msg_size(vapi_msg_ipsec_sad_entry_add_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_reply()
{
  static const char name[] = "ipsec_sad_entry_add_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_add_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_reply", vapi_msg_id_ipsec_sad_entry_add_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_add_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_add_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_add_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add
#define defined_vapi_msg_ipsec_sad_entry_add
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry_v3 entry; 
} vapi_payload_ipsec_sad_entry_add;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_add payload;
} vapi_msg_ipsec_sad_entry_add;

static inline void vapi_msg_ipsec_sad_entry_add_payload_hton(vapi_payload_ipsec_sad_entry_add *payload)
{
  vapi_type_ipsec_sad_entry_v3_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_payload_ntoh(vapi_payload_ipsec_sad_entry_add *payload)
{
  vapi_type_ipsec_sad_entry_v3_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_hton(vapi_msg_ipsec_sad_entry_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_ntoh(vapi_msg_ipsec_sad_entry_add *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_msg_size(vapi_msg_ipsec_sad_entry_add *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_msg_size(vapi_msg_ipsec_sad_entry_add *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_add* vapi_alloc_ipsec_sad_entry_add(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_add *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_add);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_add*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_add);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_add(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_add *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_add_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_add_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_add_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_add_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add()
{
  static const char name[] = "ipsec_sad_entry_add";
  static const char name_with_crc[] = "ipsec_sad_entry_add_50229353";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add", vapi_msg_id_ipsec_sad_entry_add);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_v2_reply
#define defined_vapi_msg_ipsec_sad_entry_add_v2_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  u32 stat_index; 
} vapi_payload_ipsec_sad_entry_add_v2_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_add_v2_reply payload;
} vapi_msg_ipsec_sad_entry_add_v2_reply;

static inline void vapi_msg_ipsec_sad_entry_add_v2_reply_payload_hton(vapi_payload_ipsec_sad_entry_add_v2_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_v2_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_add_v2_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sad_entry_add_v2_reply_hton(vapi_msg_ipsec_sad_entry_add_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_v2_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_v2_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_v2_reply_ntoh(vapi_msg_ipsec_sad_entry_add_v2_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_v2_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_v2_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_v2_reply_msg_size(vapi_msg_ipsec_sad_entry_add_v2_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_v2_reply_msg_size(vapi_msg_ipsec_sad_entry_add_v2_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_v2_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_v2_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_v2_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_v2_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_v2_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_v2_reply()
{
  static const char name[] = "ipsec_sad_entry_add_v2_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_add_v2_reply_9ffac24b";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_v2_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_v2_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_v2_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_v2_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_v2_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_v2_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_v2_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_v2_reply", vapi_msg_id_ipsec_sad_entry_add_v2_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_add_v2_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_add_v2_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_add_v2_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_add_v2
#define defined_vapi_msg_ipsec_sad_entry_add_v2
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry_v4 entry; 
} vapi_payload_ipsec_sad_entry_add_v2;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_add_v2 payload;
} vapi_msg_ipsec_sad_entry_add_v2;

static inline void vapi_msg_ipsec_sad_entry_add_v2_payload_hton(vapi_payload_ipsec_sad_entry_add_v2 *payload)
{
  vapi_type_ipsec_sad_entry_v4_hton(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_v2_payload_ntoh(vapi_payload_ipsec_sad_entry_add_v2 *payload)
{
  vapi_type_ipsec_sad_entry_v4_ntoh(&payload->entry);
}

static inline void vapi_msg_ipsec_sad_entry_add_v2_hton(vapi_msg_ipsec_sad_entry_add_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_v2'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_add_v2_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_add_v2_ntoh(vapi_msg_ipsec_sad_entry_add_v2 *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_add_v2'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_add_v2_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_add_v2_msg_size(vapi_msg_ipsec_sad_entry_add_v2 *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_add_v2_msg_size(vapi_msg_ipsec_sad_entry_add_v2 *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_add_v2) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_add_v2));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_add_v2_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_add_v2' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_add_v2_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_add_v2* vapi_alloc_ipsec_sad_entry_add_v2(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_add_v2 *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_add_v2);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_add_v2*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_add_v2);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_add_v2(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_add_v2 *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_add_v2_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_add_v2_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_add_v2_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_add_v2_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_add_v2()
{
  static const char name[] = "ipsec_sad_entry_add_v2";
  static const char name_with_crc[] = "ipsec_sad_entry_add_v2_9611297a";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_add_v2 = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_add_v2, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_add_v2_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_v2_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_add_v2_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_add_v2 = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_add_v2);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_add_v2", vapi_msg_id_ipsec_sad_entry_add_v2);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_del_reply
#define defined_vapi_msg_ipsec_sad_entry_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_sad_entry_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_del_reply payload;
} vapi_msg_ipsec_sad_entry_del_reply;

static inline void vapi_msg_ipsec_sad_entry_del_reply_payload_hton(vapi_payload_ipsec_sad_entry_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_sad_entry_del_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_sad_entry_del_reply_hton(vapi_msg_ipsec_sad_entry_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_del_reply_ntoh(vapi_msg_ipsec_sad_entry_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_del_reply_msg_size(vapi_msg_ipsec_sad_entry_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_del_reply_msg_size(vapi_msg_ipsec_sad_entry_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_del_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_del_reply()
{
  static const char name[] = "ipsec_sad_entry_del_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_del_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_del_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_del_reply", vapi_msg_id_ipsec_sad_entry_del_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_del
#define defined_vapi_msg_ipsec_sad_entry_del
typedef struct __attribute__ ((__packed__)) {
  u32 id; 
} vapi_payload_ipsec_sad_entry_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_del payload;
} vapi_msg_ipsec_sad_entry_del;

static inline void vapi_msg_ipsec_sad_entry_del_payload_hton(vapi_payload_ipsec_sad_entry_del *payload)
{
  payload->id = htobe32(payload->id);
}

static inline void vapi_msg_ipsec_sad_entry_del_payload_ntoh(vapi_payload_ipsec_sad_entry_del *payload)
{
  payload->id = be32toh(payload->id);
}

static inline void vapi_msg_ipsec_sad_entry_del_hton(vapi_msg_ipsec_sad_entry_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_del_ntoh(vapi_msg_ipsec_sad_entry_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_del_msg_size(vapi_msg_ipsec_sad_entry_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_del_msg_size(vapi_msg_ipsec_sad_entry_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_del));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_del* vapi_alloc_ipsec_sad_entry_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_del);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_del(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_del()
{
  static const char name[] = "ipsec_sad_entry_del";
  static const char name_with_crc[] = "ipsec_sad_entry_del_3a91bde5";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_del_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_del = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_del);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_del", vapi_msg_id_ipsec_sad_entry_del);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_bind_reply
#define defined_vapi_msg_ipsec_sad_bind_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_sad_bind_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_bind_reply payload;
} vapi_msg_ipsec_sad_bind_reply;

static inline void vapi_msg_ipsec_sad_bind_reply_payload_hton(vapi_payload_ipsec_sad_bind_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_sad_bind_reply_payload_ntoh(vapi_payload_ipsec_sad_bind_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_sad_bind_reply_hton(vapi_msg_ipsec_sad_bind_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_bind_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_bind_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_bind_reply_ntoh(vapi_msg_ipsec_sad_bind_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_bind_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_bind_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_bind_reply_msg_size(vapi_msg_ipsec_sad_bind_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_bind_reply_msg_size(vapi_msg_ipsec_sad_bind_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_bind_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_bind_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_bind_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_bind_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_bind_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_bind_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_bind_reply()
{
  static const char name[] = "ipsec_sad_bind_reply";
  static const char name_with_crc[] = "ipsec_sad_bind_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_bind_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_bind_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_bind_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_bind_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_bind_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_bind_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_bind_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_bind_reply", vapi_msg_id_ipsec_sad_bind_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_bind_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_bind_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_bind_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_bind
#define defined_vapi_msg_ipsec_sad_bind
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id;
  u32 worker; 
} vapi_payload_ipsec_sad_bind;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_bind payload;
} vapi_msg_ipsec_sad_bind;

static inline void vapi_msg_ipsec_sad_bind_payload_hton(vapi_payload_ipsec_sad_bind *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
  payload->worker = htobe32(payload->worker);
}

static inline void vapi_msg_ipsec_sad_bind_payload_ntoh(vapi_payload_ipsec_sad_bind *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
  payload->worker = be32toh(payload->worker);
}

static inline void vapi_msg_ipsec_sad_bind_hton(vapi_msg_ipsec_sad_bind *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_bind'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_bind_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_bind_ntoh(vapi_msg_ipsec_sad_bind *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_bind'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_bind_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_bind_msg_size(vapi_msg_ipsec_sad_bind *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_bind_msg_size(vapi_msg_ipsec_sad_bind *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_bind) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_bind' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_bind));
      return -1;
    }
  if (vapi_calc_ipsec_sad_bind_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_bind' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_bind_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_bind* vapi_alloc_ipsec_sad_bind(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_bind *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_bind);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_bind*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_bind);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_bind(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_bind *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_bind_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_bind_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_bind_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_bind_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_bind()
{
  static const char name[] = "ipsec_sad_bind";
  static const char name_with_crc[] = "ipsec_sad_bind_0649c0d9";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_bind = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_bind, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_bind_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_bind_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_bind_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_bind = vapi_register_msg(&__vapi_metadata_ipsec_sad_bind);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_bind", vapi_msg_id_ipsec_sad_bind);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_unbind_reply
#define defined_vapi_msg_ipsec_sad_unbind_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_sad_unbind_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_unbind_reply payload;
} vapi_msg_ipsec_sad_unbind_reply;

static inline void vapi_msg_ipsec_sad_unbind_reply_payload_hton(vapi_payload_ipsec_sad_unbind_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_sad_unbind_reply_payload_ntoh(vapi_payload_ipsec_sad_unbind_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_sad_unbind_reply_hton(vapi_msg_ipsec_sad_unbind_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_unbind_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_unbind_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_unbind_reply_ntoh(vapi_msg_ipsec_sad_unbind_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_unbind_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_unbind_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_unbind_reply_msg_size(vapi_msg_ipsec_sad_unbind_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_unbind_reply_msg_size(vapi_msg_ipsec_sad_unbind_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_unbind_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_unbind_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_unbind_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_unbind_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_unbind_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_unbind_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_unbind_reply()
{
  static const char name[] = "ipsec_sad_unbind_reply";
  static const char name_with_crc[] = "ipsec_sad_unbind_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_unbind_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_unbind_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_unbind_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_unbind_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_unbind_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_unbind_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_unbind_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_unbind_reply", vapi_msg_id_ipsec_sad_unbind_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_unbind_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_unbind_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_unbind_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_unbind
#define defined_vapi_msg_ipsec_sad_unbind
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id; 
} vapi_payload_ipsec_sad_unbind;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_unbind payload;
} vapi_msg_ipsec_sad_unbind;

static inline void vapi_msg_ipsec_sad_unbind_payload_hton(vapi_payload_ipsec_sad_unbind *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_sad_unbind_payload_ntoh(vapi_payload_ipsec_sad_unbind *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_sad_unbind_hton(vapi_msg_ipsec_sad_unbind *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_unbind'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_unbind_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_unbind_ntoh(vapi_msg_ipsec_sad_unbind *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_unbind'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_unbind_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_unbind_msg_size(vapi_msg_ipsec_sad_unbind *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_unbind_msg_size(vapi_msg_ipsec_sad_unbind *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_unbind) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_unbind' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_unbind));
      return -1;
    }
  if (vapi_calc_ipsec_sad_unbind_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_unbind' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_unbind_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_unbind* vapi_alloc_ipsec_sad_unbind(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_unbind *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_unbind);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_unbind*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_unbind);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_unbind(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_unbind *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_unbind_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_unbind_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_unbind_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_unbind_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_unbind()
{
  static const char name[] = "ipsec_sad_unbind";
  static const char name_with_crc[] = "ipsec_sad_unbind_2076c2f4";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_unbind = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_unbind, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_unbind_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_unbind_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_unbind_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_unbind = vapi_register_msg(&__vapi_metadata_ipsec_sad_unbind);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_unbind", vapi_msg_id_ipsec_sad_unbind);
}
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_update_reply
#define defined_vapi_msg_ipsec_sad_entry_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_sad_entry_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sad_entry_update_reply payload;
} vapi_msg_ipsec_sad_entry_update_reply;

static inline void vapi_msg_ipsec_sad_entry_update_reply_payload_hton(vapi_payload_ipsec_sad_entry_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_sad_entry_update_reply_payload_ntoh(vapi_payload_ipsec_sad_entry_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_sad_entry_update_reply_hton(vapi_msg_ipsec_sad_entry_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_update_reply_ntoh(vapi_msg_ipsec_sad_entry_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_update_reply_msg_size(vapi_msg_ipsec_sad_entry_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_update_reply_msg_size(vapi_msg_ipsec_sad_entry_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_update_reply));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_update_reply()
{
  static const char name[] = "ipsec_sad_entry_update_reply";
  static const char name_with_crc[] = "ipsec_sad_entry_update_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_update_reply = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_update_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_update_reply", vapi_msg_id_ipsec_sad_entry_update_reply);
}

static inline void vapi_set_vapi_msg_ipsec_sad_entry_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sad_entry_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sad_entry_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sad_entry_update
#define defined_vapi_msg_ipsec_sad_entry_update
typedef struct __attribute__ ((__packed__)) {
  u32 sad_id;
  bool is_tun;
  vapi_type_tunnel tunnel;
  u16 udp_src_port;
  u16 udp_dst_port; 
} vapi_payload_ipsec_sad_entry_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sad_entry_update payload;
} vapi_msg_ipsec_sad_entry_update;

static inline void vapi_msg_ipsec_sad_entry_update_payload_hton(vapi_payload_ipsec_sad_entry_update *payload)
{
  payload->sad_id = htobe32(payload->sad_id);
  vapi_type_tunnel_hton(&payload->tunnel);
  payload->udp_src_port = htobe16(payload->udp_src_port);
  payload->udp_dst_port = htobe16(payload->udp_dst_port);
}

static inline void vapi_msg_ipsec_sad_entry_update_payload_ntoh(vapi_payload_ipsec_sad_entry_update *payload)
{
  payload->sad_id = be32toh(payload->sad_id);
  vapi_type_tunnel_ntoh(&payload->tunnel);
  payload->udp_src_port = be16toh(payload->udp_src_port);
  payload->udp_dst_port = be16toh(payload->udp_dst_port);
}

static inline void vapi_msg_ipsec_sad_entry_update_hton(vapi_msg_ipsec_sad_entry_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sad_entry_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sad_entry_update_ntoh(vapi_msg_ipsec_sad_entry_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sad_entry_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sad_entry_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sad_entry_update_msg_size(vapi_msg_ipsec_sad_entry_update *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sad_entry_update_msg_size(vapi_msg_ipsec_sad_entry_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sad_entry_update) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sad_entry_update));
      return -1;
    }
  if (vapi_calc_ipsec_sad_entry_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sad_entry_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sad_entry_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sad_entry_update* vapi_alloc_ipsec_sad_entry_update(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sad_entry_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sad_entry_update);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sad_entry_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sad_entry_update);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sad_entry_update(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sad_entry_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sad_entry_update_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sad_entry_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sad_entry_update_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sad_entry_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sad_entry_update()
{
  static const char name[] = "ipsec_sad_entry_update";
  static const char name_with_crc[] = "ipsec_sad_entry_update_1412af86";
  static vapi_message_desc_t __vapi_metadata_ipsec_sad_entry_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sad_entry_update, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sad_entry_update_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_update_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sad_entry_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sad_entry_update = vapi_register_msg(&__vapi_metadata_ipsec_sad_entry_update);
  VAPI_DBG("Assigned msg id %d to ipsec_sad_entry_update", vapi_msg_id_ipsec_sad_entry_update);
}
#endif

#ifndef defined_vapi_msg_ipsec_tunnel_protect_update_reply
#define defined_vapi_msg_ipsec_tunnel_protect_update_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_tunnel_protect_update_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_tunnel_protect_update_reply payload;
} vapi_msg_ipsec_tunnel_protect_update_reply;

static inline void vapi_msg_ipsec_tunnel_protect_update_reply_payload_hton(vapi_payload_ipsec_tunnel_protect_update_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_tunnel_protect_update_reply_payload_ntoh(vapi_payload_ipsec_tunnel_protect_update_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_tunnel_protect_update_reply_hton(vapi_msg_ipsec_tunnel_protect_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_update_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_tunnel_protect_update_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_tunnel_protect_update_reply_ntoh(vapi_msg_ipsec_tunnel_protect_update_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_update_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_tunnel_protect_update_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_tunnel_protect_update_reply_msg_size(vapi_msg_ipsec_tunnel_protect_update_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_tunnel_protect_update_reply_msg_size(vapi_msg_ipsec_tunnel_protect_update_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_tunnel_protect_update_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_tunnel_protect_update_reply));
      return -1;
    }
  if (vapi_calc_ipsec_tunnel_protect_update_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_update_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_tunnel_protect_update_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_tunnel_protect_update_reply()
{
  static const char name[] = "ipsec_tunnel_protect_update_reply";
  static const char name_with_crc[] = "ipsec_tunnel_protect_update_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_tunnel_protect_update_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_tunnel_protect_update_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_tunnel_protect_update_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_update_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_update_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_tunnel_protect_update_reply = vapi_register_msg(&__vapi_metadata_ipsec_tunnel_protect_update_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_tunnel_protect_update_reply", vapi_msg_id_ipsec_tunnel_protect_update_reply);
}

static inline void vapi_set_vapi_msg_ipsec_tunnel_protect_update_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_tunnel_protect_update_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_tunnel_protect_update_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_tunnel_protect_update
#define defined_vapi_msg_ipsec_tunnel_protect_update
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_tunnel_protect tunnel; 
} vapi_payload_ipsec_tunnel_protect_update;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_tunnel_protect_update payload;
} vapi_msg_ipsec_tunnel_protect_update;

static inline void vapi_msg_ipsec_tunnel_protect_update_payload_hton(vapi_payload_ipsec_tunnel_protect_update *payload)
{
  vapi_type_ipsec_tunnel_protect_hton(&payload->tunnel);
}

static inline void vapi_msg_ipsec_tunnel_protect_update_payload_ntoh(vapi_payload_ipsec_tunnel_protect_update *payload)
{
  vapi_type_ipsec_tunnel_protect_ntoh(&payload->tunnel);
}

static inline void vapi_msg_ipsec_tunnel_protect_update_hton(vapi_msg_ipsec_tunnel_protect_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_update'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_tunnel_protect_update_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_tunnel_protect_update_ntoh(vapi_msg_ipsec_tunnel_protect_update *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_update'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_tunnel_protect_update_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_tunnel_protect_update_msg_size(vapi_msg_ipsec_tunnel_protect_update *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.tunnel.sa_in[0]) * msg->payload.tunnel.n_sa_in;
}

static inline int vapi_verify_ipsec_tunnel_protect_update_msg_size(vapi_msg_ipsec_tunnel_protect_update *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_tunnel_protect_update) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_tunnel_protect_update));
      return -1;
    }
  if (vapi_calc_ipsec_tunnel_protect_update_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_update' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_tunnel_protect_update_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_tunnel_protect_update* vapi_alloc_ipsec_tunnel_protect_update(struct vapi_ctx_s *ctx, size_t tunnel_sa_in_array_size)
{
  vapi_msg_ipsec_tunnel_protect_update *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_tunnel_protect_update) + sizeof(msg->payload.tunnel.sa_in[0]) * tunnel_sa_in_array_size;
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_tunnel_protect_update*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_tunnel_protect_update);
  msg->payload.tunnel.n_sa_in = tunnel_sa_in_array_size;

  return msg;
}

static inline vapi_error_e vapi_ipsec_tunnel_protect_update(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_tunnel_protect_update *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_tunnel_protect_update_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_tunnel_protect_update_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_tunnel_protect_update_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_tunnel_protect_update_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_tunnel_protect_update()
{
  static const char name[] = "ipsec_tunnel_protect_update";
  static const char name_with_crc[] = "ipsec_tunnel_protect_update_30d5f133";
  static vapi_message_desc_t __vapi_metadata_ipsec_tunnel_protect_update = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_tunnel_protect_update, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_tunnel_protect_update_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_update_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_update_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_tunnel_protect_update = vapi_register_msg(&__vapi_metadata_ipsec_tunnel_protect_update);
  VAPI_DBG("Assigned msg id %d to ipsec_tunnel_protect_update", vapi_msg_id_ipsec_tunnel_protect_update);
}
#endif

#ifndef defined_vapi_msg_ipsec_tunnel_protect_del_reply
#define defined_vapi_msg_ipsec_tunnel_protect_del_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_tunnel_protect_del_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_tunnel_protect_del_reply payload;
} vapi_msg_ipsec_tunnel_protect_del_reply;

static inline void vapi_msg_ipsec_tunnel_protect_del_reply_payload_hton(vapi_payload_ipsec_tunnel_protect_del_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_tunnel_protect_del_reply_payload_ntoh(vapi_payload_ipsec_tunnel_protect_del_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_tunnel_protect_del_reply_hton(vapi_msg_ipsec_tunnel_protect_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_del_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_tunnel_protect_del_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_tunnel_protect_del_reply_ntoh(vapi_msg_ipsec_tunnel_protect_del_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_del_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_tunnel_protect_del_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_tunnel_protect_del_reply_msg_size(vapi_msg_ipsec_tunnel_protect_del_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_tunnel_protect_del_reply_msg_size(vapi_msg_ipsec_tunnel_protect_del_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_tunnel_protect_del_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_tunnel_protect_del_reply));
      return -1;
    }
  if (vapi_calc_ipsec_tunnel_protect_del_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_del_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_tunnel_protect_del_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_tunnel_protect_del_reply()
{
  static const char name[] = "ipsec_tunnel_protect_del_reply";
  static const char name_with_crc[] = "ipsec_tunnel_protect_del_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_tunnel_protect_del_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_tunnel_protect_del_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_tunnel_protect_del_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_del_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_del_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_tunnel_protect_del_reply = vapi_register_msg(&__vapi_metadata_ipsec_tunnel_protect_del_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_tunnel_protect_del_reply", vapi_msg_id_ipsec_tunnel_protect_del_reply);
}

static inline void vapi_set_vapi_msg_ipsec_tunnel_protect_del_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_tunnel_protect_del_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_tunnel_protect_del_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_tunnel_protect_del
#define defined_vapi_msg_ipsec_tunnel_protect_del
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index;
  vapi_type_address nh; 
} vapi_payload_ipsec_tunnel_protect_del;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_tunnel_protect_del payload;
} vapi_msg_ipsec_tunnel_protect_del;

static inline void vapi_msg_ipsec_tunnel_protect_del_payload_hton(vapi_payload_ipsec_tunnel_protect_del *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_tunnel_protect_del_payload_ntoh(vapi_payload_ipsec_tunnel_protect_del *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_tunnel_protect_del_hton(vapi_msg_ipsec_tunnel_protect_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_del'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_tunnel_protect_del_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_tunnel_protect_del_ntoh(vapi_msg_ipsec_tunnel_protect_del *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_del'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_tunnel_protect_del_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_tunnel_protect_del_msg_size(vapi_msg_ipsec_tunnel_protect_del *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_tunnel_protect_del_msg_size(vapi_msg_ipsec_tunnel_protect_del *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_tunnel_protect_del) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_tunnel_protect_del));
      return -1;
    }
  if (vapi_calc_ipsec_tunnel_protect_del_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_del' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_tunnel_protect_del_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_tunnel_protect_del* vapi_alloc_ipsec_tunnel_protect_del(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_tunnel_protect_del *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_tunnel_protect_del);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_tunnel_protect_del*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_tunnel_protect_del);

  return msg;
}

static inline vapi_error_e vapi_ipsec_tunnel_protect_del(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_tunnel_protect_del *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_tunnel_protect_del_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_tunnel_protect_del_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_tunnel_protect_del_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_tunnel_protect_del_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_tunnel_protect_del()
{
  static const char name[] = "ipsec_tunnel_protect_del";
  static const char name_with_crc[] = "ipsec_tunnel_protect_del_cd239930";
  static vapi_message_desc_t __vapi_metadata_ipsec_tunnel_protect_del = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_tunnel_protect_del, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_tunnel_protect_del_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_del_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_del_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_tunnel_protect_del = vapi_register_msg(&__vapi_metadata_ipsec_tunnel_protect_del);
  VAPI_DBG("Assigned msg id %d to ipsec_tunnel_protect_del", vapi_msg_id_ipsec_tunnel_protect_del);
}
#endif

#ifndef defined_vapi_msg_ipsec_tunnel_protect_details
#define defined_vapi_msg_ipsec_tunnel_protect_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_tunnel_protect tun; 
} vapi_payload_ipsec_tunnel_protect_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_tunnel_protect_details payload;
} vapi_msg_ipsec_tunnel_protect_details;

static inline void vapi_msg_ipsec_tunnel_protect_details_payload_hton(vapi_payload_ipsec_tunnel_protect_details *payload)
{
  vapi_type_ipsec_tunnel_protect_hton(&payload->tun);
}

static inline void vapi_msg_ipsec_tunnel_protect_details_payload_ntoh(vapi_payload_ipsec_tunnel_protect_details *payload)
{
  vapi_type_ipsec_tunnel_protect_ntoh(&payload->tun);
}

static inline void vapi_msg_ipsec_tunnel_protect_details_hton(vapi_msg_ipsec_tunnel_protect_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_tunnel_protect_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_tunnel_protect_details_ntoh(vapi_msg_ipsec_tunnel_protect_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_tunnel_protect_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_tunnel_protect_details_msg_size(vapi_msg_ipsec_tunnel_protect_details *msg)
{
  return sizeof(*msg) + sizeof(msg->payload.tun.sa_in[0]) * msg->payload.tun.n_sa_in;
}

static inline int vapi_verify_ipsec_tunnel_protect_details_msg_size(vapi_msg_ipsec_tunnel_protect_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_tunnel_protect_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_tunnel_protect_details));
      return -1;
    }
  if (vapi_calc_ipsec_tunnel_protect_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_tunnel_protect_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_tunnel_protect_details()
{
  static const char name[] = "ipsec_tunnel_protect_details";
  static const char name_with_crc[] = "ipsec_tunnel_protect_details_21663a50";
  static vapi_message_desc_t __vapi_metadata_ipsec_tunnel_protect_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_tunnel_protect_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_tunnel_protect_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_tunnel_protect_details = vapi_register_msg(&__vapi_metadata_ipsec_tunnel_protect_details);
  VAPI_DBG("Assigned msg id %d to ipsec_tunnel_protect_details", vapi_msg_id_ipsec_tunnel_protect_details);
}

static inline void vapi_set_vapi_msg_ipsec_tunnel_protect_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_tunnel_protect_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_tunnel_protect_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_tunnel_protect_dump
#define defined_vapi_msg_ipsec_tunnel_protect_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ipsec_tunnel_protect_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_tunnel_protect_dump payload;
} vapi_msg_ipsec_tunnel_protect_dump;

static inline void vapi_msg_ipsec_tunnel_protect_dump_payload_hton(vapi_payload_ipsec_tunnel_protect_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_tunnel_protect_dump_payload_ntoh(vapi_payload_ipsec_tunnel_protect_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_tunnel_protect_dump_hton(vapi_msg_ipsec_tunnel_protect_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_tunnel_protect_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_tunnel_protect_dump_ntoh(vapi_msg_ipsec_tunnel_protect_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_tunnel_protect_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_tunnel_protect_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_tunnel_protect_dump_msg_size(vapi_msg_ipsec_tunnel_protect_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_tunnel_protect_dump_msg_size(vapi_msg_ipsec_tunnel_protect_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_tunnel_protect_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_tunnel_protect_dump));
      return -1;
    }
  if (vapi_calc_ipsec_tunnel_protect_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_tunnel_protect_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_tunnel_protect_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_tunnel_protect_dump* vapi_alloc_ipsec_tunnel_protect_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_tunnel_protect_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_tunnel_protect_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_tunnel_protect_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_tunnel_protect_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_tunnel_protect_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_tunnel_protect_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_tunnel_protect_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_tunnel_protect_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_tunnel_protect_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_tunnel_protect_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_tunnel_protect_dump()
{
  static const char name[] = "ipsec_tunnel_protect_dump";
  static const char name_with_crc[] = "ipsec_tunnel_protect_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_ipsec_tunnel_protect_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_tunnel_protect_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_tunnel_protect_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_tunnel_protect_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_tunnel_protect_dump = vapi_register_msg(&__vapi_metadata_ipsec_tunnel_protect_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_tunnel_protect_dump", vapi_msg_id_ipsec_tunnel_protect_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_spd_interface_details
#define defined_vapi_msg_ipsec_spd_interface_details
typedef struct __attribute__ ((__packed__)) {
  u32 spd_index;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ipsec_spd_interface_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_spd_interface_details payload;
} vapi_msg_ipsec_spd_interface_details;

static inline void vapi_msg_ipsec_spd_interface_details_payload_hton(vapi_payload_ipsec_spd_interface_details *payload)
{
  payload->spd_index = htobe32(payload->spd_index);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_spd_interface_details_payload_ntoh(vapi_payload_ipsec_spd_interface_details *payload)
{
  payload->spd_index = be32toh(payload->spd_index);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_spd_interface_details_hton(vapi_msg_ipsec_spd_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_interface_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_spd_interface_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_interface_details_ntoh(vapi_msg_ipsec_spd_interface_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_interface_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_interface_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_interface_details_msg_size(vapi_msg_ipsec_spd_interface_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_interface_details_msg_size(vapi_msg_ipsec_spd_interface_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_interface_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_interface_details));
      return -1;
    }
  if (vapi_calc_ipsec_spd_interface_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_interface_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_interface_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_interface_details()
{
  static const char name[] = "ipsec_spd_interface_details";
  static const char name_with_crc[] = "ipsec_spd_interface_details_7a0bcf3e";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_interface_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_spd_interface_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_interface_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_interface_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_interface_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_interface_details = vapi_register_msg(&__vapi_metadata_ipsec_spd_interface_details);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_interface_details", vapi_msg_id_ipsec_spd_interface_details);
}

static inline void vapi_set_vapi_msg_ipsec_spd_interface_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_spd_interface_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_spd_interface_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_spd_interface_dump
#define defined_vapi_msg_ipsec_spd_interface_dump
typedef struct __attribute__ ((__packed__)) {
  u32 spd_index;
  u8 spd_index_valid; 
} vapi_payload_ipsec_spd_interface_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_spd_interface_dump payload;
} vapi_msg_ipsec_spd_interface_dump;

static inline void vapi_msg_ipsec_spd_interface_dump_payload_hton(vapi_payload_ipsec_spd_interface_dump *payload)
{
  payload->spd_index = htobe32(payload->spd_index);
}

static inline void vapi_msg_ipsec_spd_interface_dump_payload_ntoh(vapi_payload_ipsec_spd_interface_dump *payload)
{
  payload->spd_index = be32toh(payload->spd_index);
}

static inline void vapi_msg_ipsec_spd_interface_dump_hton(vapi_msg_ipsec_spd_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_interface_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_spd_interface_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_spd_interface_dump_ntoh(vapi_msg_ipsec_spd_interface_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_spd_interface_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_spd_interface_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_spd_interface_dump_msg_size(vapi_msg_ipsec_spd_interface_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_spd_interface_dump_msg_size(vapi_msg_ipsec_spd_interface_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_spd_interface_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_spd_interface_dump));
      return -1;
    }
  if (vapi_calc_ipsec_spd_interface_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_spd_interface_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_spd_interface_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_spd_interface_dump* vapi_alloc_ipsec_spd_interface_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_spd_interface_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_spd_interface_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_spd_interface_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_spd_interface_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_spd_interface_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_spd_interface_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_spd_interface_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_spd_interface_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_spd_interface_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_spd_interface_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_spd_interface_dump()
{
  static const char name[] = "ipsec_spd_interface_dump";
  static const char name_with_crc[] = "ipsec_spd_interface_dump_8971de19";
  static vapi_message_desc_t __vapi_metadata_ipsec_spd_interface_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_spd_interface_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_spd_interface_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_interface_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_spd_interface_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_spd_interface_dump = vapi_register_msg(&__vapi_metadata_ipsec_spd_interface_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_spd_interface_dump", vapi_msg_id_ipsec_spd_interface_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_itf_create_reply
#define defined_vapi_msg_ipsec_itf_create_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval;
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ipsec_itf_create_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_itf_create_reply payload;
} vapi_msg_ipsec_itf_create_reply;

static inline void vapi_msg_ipsec_itf_create_reply_payload_hton(vapi_payload_ipsec_itf_create_reply *payload)
{
  payload->retval = htobe32(payload->retval);
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_itf_create_reply_payload_ntoh(vapi_payload_ipsec_itf_create_reply *payload)
{
  payload->retval = be32toh(payload->retval);
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_itf_create_reply_hton(vapi_msg_ipsec_itf_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_create_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_itf_create_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_itf_create_reply_ntoh(vapi_msg_ipsec_itf_create_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_create_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_itf_create_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_itf_create_reply_msg_size(vapi_msg_ipsec_itf_create_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_itf_create_reply_msg_size(vapi_msg_ipsec_itf_create_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_itf_create_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_itf_create_reply));
      return -1;
    }
  if (vapi_calc_ipsec_itf_create_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_create_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_itf_create_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_itf_create_reply()
{
  static const char name[] = "ipsec_itf_create_reply";
  static const char name_with_crc[] = "ipsec_itf_create_reply_5383d31f";
  static vapi_message_desc_t __vapi_metadata_ipsec_itf_create_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_itf_create_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_itf_create_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_create_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_create_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_itf_create_reply = vapi_register_msg(&__vapi_metadata_ipsec_itf_create_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_itf_create_reply", vapi_msg_id_ipsec_itf_create_reply);
}

static inline void vapi_set_vapi_msg_ipsec_itf_create_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_itf_create_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_itf_create_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_itf_create
#define defined_vapi_msg_ipsec_itf_create
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_itf itf; 
} vapi_payload_ipsec_itf_create;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_itf_create payload;
} vapi_msg_ipsec_itf_create;

static inline void vapi_msg_ipsec_itf_create_payload_hton(vapi_payload_ipsec_itf_create *payload)
{
  vapi_type_ipsec_itf_hton(&payload->itf);
}

static inline void vapi_msg_ipsec_itf_create_payload_ntoh(vapi_payload_ipsec_itf_create *payload)
{
  vapi_type_ipsec_itf_ntoh(&payload->itf);
}

static inline void vapi_msg_ipsec_itf_create_hton(vapi_msg_ipsec_itf_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_create'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_itf_create_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_itf_create_ntoh(vapi_msg_ipsec_itf_create *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_create'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_itf_create_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_itf_create_msg_size(vapi_msg_ipsec_itf_create *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_itf_create_msg_size(vapi_msg_ipsec_itf_create *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_itf_create) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_itf_create));
      return -1;
    }
  if (vapi_calc_ipsec_itf_create_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_create' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_itf_create_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_itf_create* vapi_alloc_ipsec_itf_create(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_itf_create *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_itf_create);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_itf_create*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_itf_create);

  return msg;
}

static inline vapi_error_e vapi_ipsec_itf_create(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_itf_create *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_itf_create_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_itf_create_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_itf_create_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_itf_create_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_itf_create()
{
  static const char name[] = "ipsec_itf_create";
  static const char name_with_crc[] = "ipsec_itf_create_6f50b3bc";
  static vapi_message_desc_t __vapi_metadata_ipsec_itf_create = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_itf_create, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_itf_create_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_create_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_create_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_itf_create = vapi_register_msg(&__vapi_metadata_ipsec_itf_create);
  VAPI_DBG("Assigned msg id %d to ipsec_itf_create", vapi_msg_id_ipsec_itf_create);
}
#endif

#ifndef defined_vapi_msg_ipsec_itf_delete_reply
#define defined_vapi_msg_ipsec_itf_delete_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_itf_delete_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_itf_delete_reply payload;
} vapi_msg_ipsec_itf_delete_reply;

static inline void vapi_msg_ipsec_itf_delete_reply_payload_hton(vapi_payload_ipsec_itf_delete_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_itf_delete_reply_payload_ntoh(vapi_payload_ipsec_itf_delete_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_itf_delete_reply_hton(vapi_msg_ipsec_itf_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_delete_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_itf_delete_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_itf_delete_reply_ntoh(vapi_msg_ipsec_itf_delete_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_delete_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_itf_delete_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_itf_delete_reply_msg_size(vapi_msg_ipsec_itf_delete_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_itf_delete_reply_msg_size(vapi_msg_ipsec_itf_delete_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_itf_delete_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_itf_delete_reply));
      return -1;
    }
  if (vapi_calc_ipsec_itf_delete_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_delete_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_itf_delete_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_itf_delete_reply()
{
  static const char name[] = "ipsec_itf_delete_reply";
  static const char name_with_crc[] = "ipsec_itf_delete_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_itf_delete_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_itf_delete_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_itf_delete_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_delete_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_delete_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_itf_delete_reply = vapi_register_msg(&__vapi_metadata_ipsec_itf_delete_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_itf_delete_reply", vapi_msg_id_ipsec_itf_delete_reply);
}

static inline void vapi_set_vapi_msg_ipsec_itf_delete_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_itf_delete_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_itf_delete_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_itf_delete
#define defined_vapi_msg_ipsec_itf_delete
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ipsec_itf_delete;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_itf_delete payload;
} vapi_msg_ipsec_itf_delete;

static inline void vapi_msg_ipsec_itf_delete_payload_hton(vapi_payload_ipsec_itf_delete *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_itf_delete_payload_ntoh(vapi_payload_ipsec_itf_delete *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_itf_delete_hton(vapi_msg_ipsec_itf_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_delete'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_itf_delete_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_itf_delete_ntoh(vapi_msg_ipsec_itf_delete *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_delete'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_itf_delete_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_itf_delete_msg_size(vapi_msg_ipsec_itf_delete *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_itf_delete_msg_size(vapi_msg_ipsec_itf_delete *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_itf_delete) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_itf_delete));
      return -1;
    }
  if (vapi_calc_ipsec_itf_delete_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_delete' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_itf_delete_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_itf_delete* vapi_alloc_ipsec_itf_delete(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_itf_delete *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_itf_delete);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_itf_delete*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_itf_delete);

  return msg;
}

static inline vapi_error_e vapi_ipsec_itf_delete(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_itf_delete *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_itf_delete_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_itf_delete_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_itf_delete_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_itf_delete_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_itf_delete()
{
  static const char name[] = "ipsec_itf_delete";
  static const char name_with_crc[] = "ipsec_itf_delete_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_ipsec_itf_delete = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_itf_delete, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_itf_delete_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_delete_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_delete_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_itf_delete = vapi_register_msg(&__vapi_metadata_ipsec_itf_delete);
  VAPI_DBG("Assigned msg id %d to ipsec_itf_delete", vapi_msg_id_ipsec_itf_delete);
}
#endif

#ifndef defined_vapi_msg_ipsec_itf_details
#define defined_vapi_msg_ipsec_itf_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_itf itf; 
} vapi_payload_ipsec_itf_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_itf_details payload;
} vapi_msg_ipsec_itf_details;

static inline void vapi_msg_ipsec_itf_details_payload_hton(vapi_payload_ipsec_itf_details *payload)
{
  vapi_type_ipsec_itf_hton(&payload->itf);
}

static inline void vapi_msg_ipsec_itf_details_payload_ntoh(vapi_payload_ipsec_itf_details *payload)
{
  vapi_type_ipsec_itf_ntoh(&payload->itf);
}

static inline void vapi_msg_ipsec_itf_details_hton(vapi_msg_ipsec_itf_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_itf_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_itf_details_ntoh(vapi_msg_ipsec_itf_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_itf_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_itf_details_msg_size(vapi_msg_ipsec_itf_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_itf_details_msg_size(vapi_msg_ipsec_itf_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_itf_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_itf_details));
      return -1;
    }
  if (vapi_calc_ipsec_itf_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_itf_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_itf_details()
{
  static const char name[] = "ipsec_itf_details";
  static const char name_with_crc[] = "ipsec_itf_details_548a73b8";
  static vapi_message_desc_t __vapi_metadata_ipsec_itf_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_itf_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_itf_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_itf_details = vapi_register_msg(&__vapi_metadata_ipsec_itf_details);
  VAPI_DBG("Assigned msg id %d to ipsec_itf_details", vapi_msg_id_ipsec_itf_details);
}

static inline void vapi_set_vapi_msg_ipsec_itf_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_itf_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_itf_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_itf_dump
#define defined_vapi_msg_ipsec_itf_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_interface_index sw_if_index; 
} vapi_payload_ipsec_itf_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_itf_dump payload;
} vapi_msg_ipsec_itf_dump;

static inline void vapi_msg_ipsec_itf_dump_payload_hton(vapi_payload_ipsec_itf_dump *payload)
{
  payload->sw_if_index = htobe32(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_itf_dump_payload_ntoh(vapi_payload_ipsec_itf_dump *payload)
{
  payload->sw_if_index = be32toh(payload->sw_if_index);
}

static inline void vapi_msg_ipsec_itf_dump_hton(vapi_msg_ipsec_itf_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_itf_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_itf_dump_ntoh(vapi_msg_ipsec_itf_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_itf_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_itf_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_itf_dump_msg_size(vapi_msg_ipsec_itf_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_itf_dump_msg_size(vapi_msg_ipsec_itf_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_itf_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_itf_dump));
      return -1;
    }
  if (vapi_calc_ipsec_itf_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_itf_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_itf_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_itf_dump* vapi_alloc_ipsec_itf_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_itf_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_itf_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_itf_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_itf_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_itf_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_itf_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_itf_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_itf_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_itf_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_itf_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_itf_dump()
{
  static const char name[] = "ipsec_itf_dump";
  static const char name_with_crc[] = "ipsec_itf_dump_f9e6675e";
  static vapi_message_desc_t __vapi_metadata_ipsec_itf_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_itf_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_itf_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_itf_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_itf_dump = vapi_register_msg(&__vapi_metadata_ipsec_itf_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_itf_dump", vapi_msg_id_ipsec_itf_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_sa_details
#define defined_vapi_msg_ipsec_sa_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry entry;
  vapi_type_interface_index sw_if_index;
  u32 salt;
  u64 seq_outbound;
  u64 last_seq_inbound;
  u64 replay_window;
  u32 stat_index; 
} vapi_payload_ipsec_sa_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sa_details payload;
} vapi_msg_ipsec_sa_details;

static inline void vapi_msg_ipsec_sa_details_payload_hton(vapi_payload_ipsec_sa_details *payload)
{
  vapi_type_ipsec_sad_entry_hton(&payload->entry);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->salt = htobe32(payload->salt);
  payload->seq_outbound = htobe64(payload->seq_outbound);
  payload->last_seq_inbound = htobe64(payload->last_seq_inbound);
  payload->replay_window = htobe64(payload->replay_window);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_details_payload_ntoh(vapi_payload_ipsec_sa_details *payload)
{
  vapi_type_ipsec_sad_entry_ntoh(&payload->entry);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->salt = be32toh(payload->salt);
  payload->seq_outbound = be64toh(payload->seq_outbound);
  payload->last_seq_inbound = be64toh(payload->last_seq_inbound);
  payload->replay_window = be64toh(payload->replay_window);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_details_hton(vapi_msg_ipsec_sa_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sa_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_details_ntoh(vapi_msg_ipsec_sa_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_details_msg_size(vapi_msg_ipsec_sa_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_details_msg_size(vapi_msg_ipsec_sa_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_details));
      return -1;
    }
  if (vapi_calc_ipsec_sa_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_details()
{
  static const char name[] = "ipsec_sa_details";
  static const char name_with_crc[] = "ipsec_sa_details_345d14a7";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sa_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_details = vapi_register_msg(&__vapi_metadata_ipsec_sa_details);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_details", vapi_msg_id_ipsec_sa_details);
}

static inline void vapi_set_vapi_msg_ipsec_sa_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sa_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sa_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sa_dump
#define defined_vapi_msg_ipsec_sa_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id; 
} vapi_payload_ipsec_sa_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sa_dump payload;
} vapi_msg_ipsec_sa_dump;

static inline void vapi_msg_ipsec_sa_dump_payload_hton(vapi_payload_ipsec_sa_dump *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_dump_payload_ntoh(vapi_payload_ipsec_sa_dump *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_dump_hton(vapi_msg_ipsec_sa_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sa_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_dump_ntoh(vapi_msg_ipsec_sa_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_dump_msg_size(vapi_msg_ipsec_sa_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_dump_msg_size(vapi_msg_ipsec_sa_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_dump));
      return -1;
    }
  if (vapi_calc_ipsec_sa_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sa_dump* vapi_alloc_ipsec_sa_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sa_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sa_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sa_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sa_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sa_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sa_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sa_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sa_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sa_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sa_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_dump()
{
  static const char name[] = "ipsec_sa_dump";
  static const char name_with_crc[] = "ipsec_sa_dump_2076c2f4";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sa_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_dump = vapi_register_msg(&__vapi_metadata_ipsec_sa_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_dump", vapi_msg_id_ipsec_sa_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_sa_v2_details
#define defined_vapi_msg_ipsec_sa_v2_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry_v2 entry;
  vapi_type_interface_index sw_if_index;
  u32 salt;
  u64 seq_outbound;
  u64 last_seq_inbound;
  u64 replay_window;
  u32 stat_index; 
} vapi_payload_ipsec_sa_v2_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sa_v2_details payload;
} vapi_msg_ipsec_sa_v2_details;

static inline void vapi_msg_ipsec_sa_v2_details_payload_hton(vapi_payload_ipsec_sa_v2_details *payload)
{
  vapi_type_ipsec_sad_entry_v2_hton(&payload->entry);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->salt = htobe32(payload->salt);
  payload->seq_outbound = htobe64(payload->seq_outbound);
  payload->last_seq_inbound = htobe64(payload->last_seq_inbound);
  payload->replay_window = htobe64(payload->replay_window);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v2_details_payload_ntoh(vapi_payload_ipsec_sa_v2_details *payload)
{
  vapi_type_ipsec_sad_entry_v2_ntoh(&payload->entry);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->salt = be32toh(payload->salt);
  payload->seq_outbound = be64toh(payload->seq_outbound);
  payload->last_seq_inbound = be64toh(payload->last_seq_inbound);
  payload->replay_window = be64toh(payload->replay_window);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v2_details_hton(vapi_msg_ipsec_sa_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v2_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v2_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v2_details_ntoh(vapi_msg_ipsec_sa_v2_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v2_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v2_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v2_details_msg_size(vapi_msg_ipsec_sa_v2_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v2_details_msg_size(vapi_msg_ipsec_sa_v2_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v2_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v2_details));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v2_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v2_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v2_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v2_details()
{
  static const char name[] = "ipsec_sa_v2_details";
  static const char name_with_crc[] = "ipsec_sa_v2_details_e2130051";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v2_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sa_v2_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v2_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v2_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v2_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v2_details = vapi_register_msg(&__vapi_metadata_ipsec_sa_v2_details);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v2_details", vapi_msg_id_ipsec_sa_v2_details);
}

static inline void vapi_set_vapi_msg_ipsec_sa_v2_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sa_v2_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sa_v2_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sa_v2_dump
#define defined_vapi_msg_ipsec_sa_v2_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id; 
} vapi_payload_ipsec_sa_v2_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sa_v2_dump payload;
} vapi_msg_ipsec_sa_v2_dump;

static inline void vapi_msg_ipsec_sa_v2_dump_payload_hton(vapi_payload_ipsec_sa_v2_dump *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v2_dump_payload_ntoh(vapi_payload_ipsec_sa_v2_dump *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v2_dump_hton(vapi_msg_ipsec_sa_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v2_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v2_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v2_dump_ntoh(vapi_msg_ipsec_sa_v2_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v2_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v2_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v2_dump_msg_size(vapi_msg_ipsec_sa_v2_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v2_dump_msg_size(vapi_msg_ipsec_sa_v2_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v2_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v2_dump));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v2_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v2_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v2_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sa_v2_dump* vapi_alloc_ipsec_sa_v2_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sa_v2_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sa_v2_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sa_v2_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sa_v2_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sa_v2_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sa_v2_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sa_v2_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sa_v2_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sa_v2_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sa_v2_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v2_dump()
{
  static const char name[] = "ipsec_sa_v2_dump";
  static const char name_with_crc[] = "ipsec_sa_v2_dump_2076c2f4";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v2_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sa_v2_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v2_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v2_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v2_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v2_dump = vapi_register_msg(&__vapi_metadata_ipsec_sa_v2_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v2_dump", vapi_msg_id_ipsec_sa_v2_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_sa_v3_details
#define defined_vapi_msg_ipsec_sa_v3_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry_v3 entry;
  vapi_type_interface_index sw_if_index;
  u64 seq_outbound;
  u64 last_seq_inbound;
  u64 replay_window;
  u32 stat_index; 
} vapi_payload_ipsec_sa_v3_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sa_v3_details payload;
} vapi_msg_ipsec_sa_v3_details;

static inline void vapi_msg_ipsec_sa_v3_details_payload_hton(vapi_payload_ipsec_sa_v3_details *payload)
{
  vapi_type_ipsec_sad_entry_v3_hton(&payload->entry);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->seq_outbound = htobe64(payload->seq_outbound);
  payload->last_seq_inbound = htobe64(payload->last_seq_inbound);
  payload->replay_window = htobe64(payload->replay_window);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v3_details_payload_ntoh(vapi_payload_ipsec_sa_v3_details *payload)
{
  vapi_type_ipsec_sad_entry_v3_ntoh(&payload->entry);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->seq_outbound = be64toh(payload->seq_outbound);
  payload->last_seq_inbound = be64toh(payload->last_seq_inbound);
  payload->replay_window = be64toh(payload->replay_window);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v3_details_hton(vapi_msg_ipsec_sa_v3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v3_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v3_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v3_details_ntoh(vapi_msg_ipsec_sa_v3_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v3_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v3_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v3_details_msg_size(vapi_msg_ipsec_sa_v3_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v3_details_msg_size(vapi_msg_ipsec_sa_v3_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v3_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v3_details));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v3_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v3_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v3_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v3_details()
{
  static const char name[] = "ipsec_sa_v3_details";
  static const char name_with_crc[] = "ipsec_sa_v3_details_2fc991ee";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v3_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sa_v3_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v3_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v3_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v3_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v3_details = vapi_register_msg(&__vapi_metadata_ipsec_sa_v3_details);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v3_details", vapi_msg_id_ipsec_sa_v3_details);
}

static inline void vapi_set_vapi_msg_ipsec_sa_v3_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sa_v3_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sa_v3_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sa_v3_dump
#define defined_vapi_msg_ipsec_sa_v3_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id; 
} vapi_payload_ipsec_sa_v3_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sa_v3_dump payload;
} vapi_msg_ipsec_sa_v3_dump;

static inline void vapi_msg_ipsec_sa_v3_dump_payload_hton(vapi_payload_ipsec_sa_v3_dump *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v3_dump_payload_ntoh(vapi_payload_ipsec_sa_v3_dump *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v3_dump_hton(vapi_msg_ipsec_sa_v3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v3_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v3_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v3_dump_ntoh(vapi_msg_ipsec_sa_v3_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v3_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v3_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v3_dump_msg_size(vapi_msg_ipsec_sa_v3_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v3_dump_msg_size(vapi_msg_ipsec_sa_v3_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v3_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v3_dump));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v3_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v3_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v3_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sa_v3_dump* vapi_alloc_ipsec_sa_v3_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sa_v3_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sa_v3_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sa_v3_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sa_v3_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sa_v3_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sa_v3_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sa_v3_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sa_v3_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sa_v3_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sa_v3_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v3_dump()
{
  static const char name[] = "ipsec_sa_v3_dump";
  static const char name_with_crc[] = "ipsec_sa_v3_dump_2076c2f4";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v3_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sa_v3_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v3_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v3_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v3_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v3_dump = vapi_register_msg(&__vapi_metadata_ipsec_sa_v3_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v3_dump", vapi_msg_id_ipsec_sa_v3_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_sa_v4_details
#define defined_vapi_msg_ipsec_sa_v4_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry_v3 entry;
  vapi_type_interface_index sw_if_index;
  u64 seq_outbound;
  u64 last_seq_inbound;
  u64 replay_window;
  u32 thread_index;
  u32 stat_index; 
} vapi_payload_ipsec_sa_v4_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sa_v4_details payload;
} vapi_msg_ipsec_sa_v4_details;

static inline void vapi_msg_ipsec_sa_v4_details_payload_hton(vapi_payload_ipsec_sa_v4_details *payload)
{
  vapi_type_ipsec_sad_entry_v3_hton(&payload->entry);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->seq_outbound = htobe64(payload->seq_outbound);
  payload->last_seq_inbound = htobe64(payload->last_seq_inbound);
  payload->replay_window = htobe64(payload->replay_window);
  payload->thread_index = htobe32(payload->thread_index);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v4_details_payload_ntoh(vapi_payload_ipsec_sa_v4_details *payload)
{
  vapi_type_ipsec_sad_entry_v3_ntoh(&payload->entry);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->seq_outbound = be64toh(payload->seq_outbound);
  payload->last_seq_inbound = be64toh(payload->last_seq_inbound);
  payload->replay_window = be64toh(payload->replay_window);
  payload->thread_index = be32toh(payload->thread_index);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v4_details_hton(vapi_msg_ipsec_sa_v4_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v4_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v4_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v4_details_ntoh(vapi_msg_ipsec_sa_v4_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v4_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v4_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v4_details_msg_size(vapi_msg_ipsec_sa_v4_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v4_details_msg_size(vapi_msg_ipsec_sa_v4_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v4_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v4_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v4_details));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v4_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v4_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v4_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v4_details()
{
  static const char name[] = "ipsec_sa_v4_details";
  static const char name_with_crc[] = "ipsec_sa_v4_details_87a322d7";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v4_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sa_v4_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v4_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v4_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v4_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v4_details = vapi_register_msg(&__vapi_metadata_ipsec_sa_v4_details);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v4_details", vapi_msg_id_ipsec_sa_v4_details);
}

static inline void vapi_set_vapi_msg_ipsec_sa_v4_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sa_v4_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sa_v4_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sa_v4_dump
#define defined_vapi_msg_ipsec_sa_v4_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id; 
} vapi_payload_ipsec_sa_v4_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sa_v4_dump payload;
} vapi_msg_ipsec_sa_v4_dump;

static inline void vapi_msg_ipsec_sa_v4_dump_payload_hton(vapi_payload_ipsec_sa_v4_dump *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v4_dump_payload_ntoh(vapi_payload_ipsec_sa_v4_dump *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v4_dump_hton(vapi_msg_ipsec_sa_v4_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v4_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v4_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v4_dump_ntoh(vapi_msg_ipsec_sa_v4_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v4_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v4_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v4_dump_msg_size(vapi_msg_ipsec_sa_v4_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v4_dump_msg_size(vapi_msg_ipsec_sa_v4_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v4_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v4_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v4_dump));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v4_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v4_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v4_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sa_v4_dump* vapi_alloc_ipsec_sa_v4_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sa_v4_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sa_v4_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sa_v4_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sa_v4_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sa_v4_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sa_v4_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sa_v4_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sa_v4_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sa_v4_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sa_v4_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v4_dump()
{
  static const char name[] = "ipsec_sa_v4_dump";
  static const char name_with_crc[] = "ipsec_sa_v4_dump_2076c2f4";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v4_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sa_v4_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v4_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v4_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v4_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v4_dump = vapi_register_msg(&__vapi_metadata_ipsec_sa_v4_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v4_dump", vapi_msg_id_ipsec_sa_v4_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_sa_v5_details
#define defined_vapi_msg_ipsec_sa_v5_details
typedef struct __attribute__ ((__packed__)) {
  vapi_type_ipsec_sad_entry_v4 entry;
  vapi_type_interface_index sw_if_index;
  u64 seq_outbound;
  u64 last_seq_inbound;
  u64 replay_window;
  u32 thread_index;
  u32 stat_index; 
} vapi_payload_ipsec_sa_v5_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_sa_v5_details payload;
} vapi_msg_ipsec_sa_v5_details;

static inline void vapi_msg_ipsec_sa_v5_details_payload_hton(vapi_payload_ipsec_sa_v5_details *payload)
{
  vapi_type_ipsec_sad_entry_v4_hton(&payload->entry);
  payload->sw_if_index = htobe32(payload->sw_if_index);
  payload->seq_outbound = htobe64(payload->seq_outbound);
  payload->last_seq_inbound = htobe64(payload->last_seq_inbound);
  payload->replay_window = htobe64(payload->replay_window);
  payload->thread_index = htobe32(payload->thread_index);
  payload->stat_index = htobe32(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v5_details_payload_ntoh(vapi_payload_ipsec_sa_v5_details *payload)
{
  vapi_type_ipsec_sad_entry_v4_ntoh(&payload->entry);
  payload->sw_if_index = be32toh(payload->sw_if_index);
  payload->seq_outbound = be64toh(payload->seq_outbound);
  payload->last_seq_inbound = be64toh(payload->last_seq_inbound);
  payload->replay_window = be64toh(payload->replay_window);
  payload->thread_index = be32toh(payload->thread_index);
  payload->stat_index = be32toh(payload->stat_index);
}

static inline void vapi_msg_ipsec_sa_v5_details_hton(vapi_msg_ipsec_sa_v5_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v5_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v5_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v5_details_ntoh(vapi_msg_ipsec_sa_v5_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v5_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v5_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v5_details_msg_size(vapi_msg_ipsec_sa_v5_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v5_details_msg_size(vapi_msg_ipsec_sa_v5_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v5_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v5_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v5_details));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v5_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v5_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v5_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v5_details()
{
  static const char name[] = "ipsec_sa_v5_details";
  static const char name_with_crc[] = "ipsec_sa_v5_details_3cfecfbd";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v5_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_sa_v5_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v5_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v5_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v5_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v5_details = vapi_register_msg(&__vapi_metadata_ipsec_sa_v5_details);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v5_details", vapi_msg_id_ipsec_sa_v5_details);
}

static inline void vapi_set_vapi_msg_ipsec_sa_v5_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_sa_v5_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_sa_v5_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_sa_v5_dump
#define defined_vapi_msg_ipsec_sa_v5_dump
typedef struct __attribute__ ((__packed__)) {
  u32 sa_id; 
} vapi_payload_ipsec_sa_v5_dump;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_sa_v5_dump payload;
} vapi_msg_ipsec_sa_v5_dump;

static inline void vapi_msg_ipsec_sa_v5_dump_payload_hton(vapi_payload_ipsec_sa_v5_dump *payload)
{
  payload->sa_id = htobe32(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v5_dump_payload_ntoh(vapi_payload_ipsec_sa_v5_dump *payload)
{
  payload->sa_id = be32toh(payload->sa_id);
}

static inline void vapi_msg_ipsec_sa_v5_dump_hton(vapi_msg_ipsec_sa_v5_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v5_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_sa_v5_dump_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_sa_v5_dump_ntoh(vapi_msg_ipsec_sa_v5_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_sa_v5_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_sa_v5_dump_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_sa_v5_dump_msg_size(vapi_msg_ipsec_sa_v5_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_sa_v5_dump_msg_size(vapi_msg_ipsec_sa_v5_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_sa_v5_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v5_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_sa_v5_dump));
      return -1;
    }
  if (vapi_calc_ipsec_sa_v5_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_sa_v5_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_sa_v5_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_sa_v5_dump* vapi_alloc_ipsec_sa_v5_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_sa_v5_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_sa_v5_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_sa_v5_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_sa_v5_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_sa_v5_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_sa_v5_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_sa_v5_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_sa_v5_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_sa_v5_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_sa_v5_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_sa_v5_dump()
{
  static const char name[] = "ipsec_sa_v5_dump";
  static const char name_with_crc[] = "ipsec_sa_v5_dump_2076c2f4";
  static vapi_message_desc_t __vapi_metadata_ipsec_sa_v5_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_sa_v5_dump, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_sa_v5_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v5_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_sa_v5_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_sa_v5_dump = vapi_register_msg(&__vapi_metadata_ipsec_sa_v5_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_sa_v5_dump", vapi_msg_id_ipsec_sa_v5_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_backend_details
#define defined_vapi_msg_ipsec_backend_details
typedef struct __attribute__ ((__packed__)) {
  u8 name[128];
  vapi_enum_ipsec_proto protocol;
  u8 index;
  bool active; 
} vapi_payload_ipsec_backend_details;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_backend_details payload;
} vapi_msg_ipsec_backend_details;

static inline void vapi_msg_ipsec_backend_details_payload_hton(vapi_payload_ipsec_backend_details *payload)
{
  payload->protocol = (vapi_enum_ipsec_proto)htobe32(payload->protocol);
}

static inline void vapi_msg_ipsec_backend_details_payload_ntoh(vapi_payload_ipsec_backend_details *payload)
{
  payload->protocol = (vapi_enum_ipsec_proto)be32toh(payload->protocol);
}

static inline void vapi_msg_ipsec_backend_details_hton(vapi_msg_ipsec_backend_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_backend_details'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_backend_details_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_backend_details_ntoh(vapi_msg_ipsec_backend_details *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_backend_details'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_backend_details_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_backend_details_msg_size(vapi_msg_ipsec_backend_details *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_backend_details_msg_size(vapi_msg_ipsec_backend_details *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_backend_details) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_backend_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_backend_details));
      return -1;
    }
  if (vapi_calc_ipsec_backend_details_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_backend_details' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_backend_details_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_backend_details()
{
  static const char name[] = "ipsec_backend_details";
  static const char name_with_crc[] = "ipsec_backend_details_ee601c29";
  static vapi_message_desc_t __vapi_metadata_ipsec_backend_details = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_backend_details, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_backend_details_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_backend_details_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_backend_details_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_backend_details = vapi_register_msg(&__vapi_metadata_ipsec_backend_details);
  VAPI_DBG("Assigned msg id %d to ipsec_backend_details", vapi_msg_id_ipsec_backend_details);
}

static inline void vapi_set_vapi_msg_ipsec_backend_details_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_backend_details *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_backend_details, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_backend_dump
#define defined_vapi_msg_ipsec_backend_dump
typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
} vapi_msg_ipsec_backend_dump;

static inline void vapi_msg_ipsec_backend_dump_hton(vapi_msg_ipsec_backend_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_backend_dump'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);

}

static inline void vapi_msg_ipsec_backend_dump_ntoh(vapi_msg_ipsec_backend_dump *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_backend_dump'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);

}

static inline uword vapi_calc_ipsec_backend_dump_msg_size(vapi_msg_ipsec_backend_dump *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_backend_dump_msg_size(vapi_msg_ipsec_backend_dump *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_backend_dump) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_backend_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_backend_dump));
      return -1;
    }
  if (vapi_calc_ipsec_backend_dump_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_backend_dump' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_backend_dump_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_backend_dump* vapi_alloc_ipsec_backend_dump(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_backend_dump *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_backend_dump);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_backend_dump*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_backend_dump);

  return msg;
}

static inline vapi_error_e vapi_ipsec_backend_dump(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_backend_dump *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_backend_details *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_backend_dump_hton(msg);
  if (VAPI_OK == (rv = vapi_send_with_control_ping (ctx, msg, req_context))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_backend_details, VAPI_REQUEST_DUMP, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_backend_dump_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_backend_dump()
{
  static const char name[] = "ipsec_backend_dump";
  static const char name_with_crc[] = "ipsec_backend_dump_51077d14";
  static vapi_message_desc_t __vapi_metadata_ipsec_backend_dump = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    VAPI_INVALID_MSG_ID,
    (verify_msg_size_fn_t)vapi_verify_ipsec_backend_dump_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_backend_dump_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_backend_dump_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_backend_dump = vapi_register_msg(&__vapi_metadata_ipsec_backend_dump);
  VAPI_DBG("Assigned msg id %d to ipsec_backend_dump", vapi_msg_id_ipsec_backend_dump);
}
#endif

#ifndef defined_vapi_msg_ipsec_select_backend_reply
#define defined_vapi_msg_ipsec_select_backend_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_select_backend_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_select_backend_reply payload;
} vapi_msg_ipsec_select_backend_reply;

static inline void vapi_msg_ipsec_select_backend_reply_payload_hton(vapi_payload_ipsec_select_backend_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_select_backend_reply_payload_ntoh(vapi_payload_ipsec_select_backend_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_select_backend_reply_hton(vapi_msg_ipsec_select_backend_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_select_backend_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_select_backend_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_select_backend_reply_ntoh(vapi_msg_ipsec_select_backend_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_select_backend_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_select_backend_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_select_backend_reply_msg_size(vapi_msg_ipsec_select_backend_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_select_backend_reply_msg_size(vapi_msg_ipsec_select_backend_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_select_backend_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_select_backend_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_select_backend_reply));
      return -1;
    }
  if (vapi_calc_ipsec_select_backend_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_select_backend_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_select_backend_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_select_backend_reply()
{
  static const char name[] = "ipsec_select_backend_reply";
  static const char name_with_crc[] = "ipsec_select_backend_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_select_backend_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_select_backend_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_select_backend_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_select_backend_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_select_backend_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_select_backend_reply = vapi_register_msg(&__vapi_metadata_ipsec_select_backend_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_select_backend_reply", vapi_msg_id_ipsec_select_backend_reply);
}

static inline void vapi_set_vapi_msg_ipsec_select_backend_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_select_backend_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_select_backend_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_select_backend
#define defined_vapi_msg_ipsec_select_backend
typedef struct __attribute__ ((__packed__)) {
  vapi_enum_ipsec_proto protocol;
  u8 index; 
} vapi_payload_ipsec_select_backend;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_select_backend payload;
} vapi_msg_ipsec_select_backend;

static inline void vapi_msg_ipsec_select_backend_payload_hton(vapi_payload_ipsec_select_backend *payload)
{
  payload->protocol = (vapi_enum_ipsec_proto)htobe32(payload->protocol);
}

static inline void vapi_msg_ipsec_select_backend_payload_ntoh(vapi_payload_ipsec_select_backend *payload)
{
  payload->protocol = (vapi_enum_ipsec_proto)be32toh(payload->protocol);
}

static inline void vapi_msg_ipsec_select_backend_hton(vapi_msg_ipsec_select_backend *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_select_backend'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_select_backend_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_select_backend_ntoh(vapi_msg_ipsec_select_backend *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_select_backend'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_select_backend_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_select_backend_msg_size(vapi_msg_ipsec_select_backend *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_select_backend_msg_size(vapi_msg_ipsec_select_backend *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_select_backend) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_select_backend' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_select_backend));
      return -1;
    }
  if (vapi_calc_ipsec_select_backend_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_select_backend' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_select_backend_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_select_backend* vapi_alloc_ipsec_select_backend(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_select_backend *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_select_backend);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_select_backend*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_select_backend);

  return msg;
}

static inline vapi_error_e vapi_ipsec_select_backend(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_select_backend *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_select_backend_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_select_backend_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_select_backend_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_select_backend_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_select_backend()
{
  static const char name[] = "ipsec_select_backend";
  static const char name_with_crc[] = "ipsec_select_backend_5bcfd3b7";
  static vapi_message_desc_t __vapi_metadata_ipsec_select_backend = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_select_backend, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_select_backend_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_select_backend_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_select_backend_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_select_backend = vapi_register_msg(&__vapi_metadata_ipsec_select_backend);
  VAPI_DBG("Assigned msg id %d to ipsec_select_backend", vapi_msg_id_ipsec_select_backend);
}
#endif

#ifndef defined_vapi_msg_ipsec_set_async_mode_reply
#define defined_vapi_msg_ipsec_set_async_mode_reply
typedef struct __attribute__ ((__packed__)) {
  i32 retval; 
} vapi_payload_ipsec_set_async_mode_reply;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header1_t header;
  vapi_payload_ipsec_set_async_mode_reply payload;
} vapi_msg_ipsec_set_async_mode_reply;

static inline void vapi_msg_ipsec_set_async_mode_reply_payload_hton(vapi_payload_ipsec_set_async_mode_reply *payload)
{
  payload->retval = htobe32(payload->retval);
}

static inline void vapi_msg_ipsec_set_async_mode_reply_payload_ntoh(vapi_payload_ipsec_set_async_mode_reply *payload)
{
  payload->retval = be32toh(payload->retval);
}

static inline void vapi_msg_ipsec_set_async_mode_reply_hton(vapi_msg_ipsec_set_async_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_set_async_mode_reply'@%p to big endian", msg);
  vapi_type_msg_header1_t_hton(&msg->header);
  vapi_msg_ipsec_set_async_mode_reply_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_set_async_mode_reply_ntoh(vapi_msg_ipsec_set_async_mode_reply *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_set_async_mode_reply'@%p to host byte order", msg);
  vapi_type_msg_header1_t_ntoh(&msg->header);
  vapi_msg_ipsec_set_async_mode_reply_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_set_async_mode_reply_msg_size(vapi_msg_ipsec_set_async_mode_reply *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_set_async_mode_reply_msg_size(vapi_msg_ipsec_set_async_mode_reply *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_set_async_mode_reply) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_set_async_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_set_async_mode_reply));
      return -1;
    }
  if (vapi_calc_ipsec_set_async_mode_reply_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_set_async_mode_reply' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_set_async_mode_reply_msg_size(msg));
      return -1;
    }
  return 0;
}

static void __attribute__((constructor)) __vapi_constructor_ipsec_set_async_mode_reply()
{
  static const char name[] = "ipsec_set_async_mode_reply";
  static const char name_with_crc[] = "ipsec_set_async_mode_reply_e8d4e804";
  static vapi_message_desc_t __vapi_metadata_ipsec_set_async_mode_reply = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header1_t, context),
    offsetof(vapi_msg_ipsec_set_async_mode_reply, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_set_async_mode_reply_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_set_async_mode_reply_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_set_async_mode_reply_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_set_async_mode_reply = vapi_register_msg(&__vapi_metadata_ipsec_set_async_mode_reply);
  VAPI_DBG("Assigned msg id %d to ipsec_set_async_mode_reply", vapi_msg_id_ipsec_set_async_mode_reply);
}

static inline void vapi_set_vapi_msg_ipsec_set_async_mode_reply_event_cb (
  struct vapi_ctx_s *ctx, 
  vapi_error_e (*callback)(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_payload_ipsec_set_async_mode_reply *payload),
  void *callback_ctx)
{
  vapi_set_event_cb(ctx, vapi_msg_id_ipsec_set_async_mode_reply, (vapi_event_cb)callback, callback_ctx);
};
#endif

#ifndef defined_vapi_msg_ipsec_set_async_mode
#define defined_vapi_msg_ipsec_set_async_mode
typedef struct __attribute__ ((__packed__)) {
  bool async_enable; 
} vapi_payload_ipsec_set_async_mode;

typedef struct __attribute__ ((__packed__)) {
  vapi_type_msg_header2_t header;
  vapi_payload_ipsec_set_async_mode payload;
} vapi_msg_ipsec_set_async_mode;

static inline void vapi_msg_ipsec_set_async_mode_payload_hton(vapi_payload_ipsec_set_async_mode *payload)
{

}

static inline void vapi_msg_ipsec_set_async_mode_payload_ntoh(vapi_payload_ipsec_set_async_mode *payload)
{

}

static inline void vapi_msg_ipsec_set_async_mode_hton(vapi_msg_ipsec_set_async_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_set_async_mode'@%p to big endian", msg);
  vapi_type_msg_header2_t_hton(&msg->header);
  vapi_msg_ipsec_set_async_mode_payload_hton(&msg->payload);
}

static inline void vapi_msg_ipsec_set_async_mode_ntoh(vapi_msg_ipsec_set_async_mode *msg)
{
  VAPI_DBG("Swapping `vapi_msg_ipsec_set_async_mode'@%p to host byte order", msg);
  vapi_type_msg_header2_t_ntoh(&msg->header);
  vapi_msg_ipsec_set_async_mode_payload_ntoh(&msg->payload);
}

static inline uword vapi_calc_ipsec_set_async_mode_msg_size(vapi_msg_ipsec_set_async_mode *msg)
{
  return sizeof(*msg);
}

static inline int vapi_verify_ipsec_set_async_mode_msg_size(vapi_msg_ipsec_set_async_mode *msg, uword buf_size)
{
  if (sizeof(vapi_msg_ipsec_set_async_mode) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_set_async_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        sizeof(vapi_msg_ipsec_set_async_mode));
      return -1;
    }
  if (vapi_calc_ipsec_set_async_mode_msg_size(msg) > buf_size)
    {
      VAPI_ERR("Truncated 'ipsec_set_async_mode' msg received, received %lu"
        "bytes, expected %lu bytes.", buf_size,
        vapi_calc_ipsec_set_async_mode_msg_size(msg));
      return -1;
    }
  return 0;
}

static inline vapi_msg_ipsec_set_async_mode* vapi_alloc_ipsec_set_async_mode(struct vapi_ctx_s *ctx)
{
  vapi_msg_ipsec_set_async_mode *msg = NULL;
  const size_t size = sizeof(vapi_msg_ipsec_set_async_mode);
  /* cast here required to play nicely with C++ world ... */
  msg = (vapi_msg_ipsec_set_async_mode*)vapi_msg_alloc(ctx, size);
  if (!msg) {
    return NULL;
  }
  msg->header.client_index = vapi_get_client_index(ctx);
  msg->header.context = 0;
  msg->header._vl_msg_id = vapi_lookup_vl_msg_id(ctx, vapi_msg_id_ipsec_set_async_mode);

  return msg;
}

static inline vapi_error_e vapi_ipsec_set_async_mode(struct vapi_ctx_s *ctx,
  vapi_msg_ipsec_set_async_mode *msg,
  vapi_error_e (*reply_callback)(struct vapi_ctx_s *ctx,
                                 void *callback_ctx,
                                 vapi_error_e rv,
                                 bool is_last,
                                 vapi_payload_ipsec_set_async_mode_reply *reply),
  void *reply_callback_ctx)
{
  if (!msg || !reply_callback) {
    return VAPI_EINVAL;
  }
  if (vapi_is_nonblocking(ctx) && vapi_requests_full(ctx)) {
    return VAPI_EAGAIN;
  }
  vapi_error_e rv;
  if (VAPI_OK != (rv = vapi_producer_lock (ctx))) {
    return rv;
  }
  u32 req_context = vapi_gen_req_context(ctx);
  msg->header.context = req_context;
  vapi_msg_ipsec_set_async_mode_hton(msg);
  if (VAPI_OK == (rv = vapi_send (ctx, msg))) {
    vapi_store_request(ctx, req_context, vapi_msg_id_ipsec_set_async_mode_reply, VAPI_REQUEST_REG, 
                       (vapi_cb_t)reply_callback, reply_callback_ctx);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
    if (vapi_is_nonblocking(ctx)) {
      rv = VAPI_OK;
    } else {
      rv = vapi_dispatch(ctx);
    }
  } else {
    vapi_msg_ipsec_set_async_mode_ntoh(msg);
    if (VAPI_OK != vapi_producer_unlock (ctx)) {
      abort (); /* this really shouldn't happen */
    }
  }
  return rv;
}


static void __attribute__((constructor)) __vapi_constructor_ipsec_set_async_mode()
{
  static const char name[] = "ipsec_set_async_mode";
  static const char name_with_crc[] = "ipsec_set_async_mode_a6465f7c";
  static vapi_message_desc_t __vapi_metadata_ipsec_set_async_mode = {
    name,
    sizeof(name) - 1,
    name_with_crc,
    sizeof(name_with_crc) - 1,
    true,
    offsetof(vapi_type_msg_header2_t, context),
    offsetof(vapi_msg_ipsec_set_async_mode, payload),
    (verify_msg_size_fn_t)vapi_verify_ipsec_set_async_mode_msg_size,
    (generic_swap_fn_t)vapi_msg_ipsec_set_async_mode_hton,
    (generic_swap_fn_t)vapi_msg_ipsec_set_async_mode_ntoh,
    VAPI_INVALID_MSG_ID,
  };

  vapi_msg_id_ipsec_set_async_mode = vapi_register_msg(&__vapi_metadata_ipsec_set_async_mode);
  VAPI_DBG("Assigned msg id %d to ipsec_set_async_mode", vapi_msg_id_ipsec_set_async_mode);
}
#endif


#ifdef __cplusplus
}
#endif

#endif
