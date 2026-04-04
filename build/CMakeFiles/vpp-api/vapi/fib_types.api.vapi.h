#ifndef __included_fib_types_api_json
#define __included_fib_types_api_json

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


#define DEFINE_VAPI_MSG_IDS_FIB_TYPES_API_JSON\



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

#ifndef defined_vapi_enum_fib_path_nh_proto
#define defined_vapi_enum_fib_path_nh_proto
typedef enum {
  FIB_API_PATH_NH_PROTO_IP4 = 0,
  FIB_API_PATH_NH_PROTO_IP6 = 1,
  FIB_API_PATH_NH_PROTO_MPLS = 2,
  FIB_API_PATH_NH_PROTO_ETHERNET = 3,
  FIB_API_PATH_NH_PROTO_BIER = 4,
}  vapi_enum_fib_path_nh_proto;

#endif

#ifndef defined_vapi_enum_fib_path_flags
#define defined_vapi_enum_fib_path_flags
typedef enum {
  FIB_API_PATH_FLAG_NONE = 0,
  FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1,
  FIB_API_PATH_FLAG_RESOLVE_VIA_HOST = 2,
  FIB_API_PATH_FLAG_POP_PW_CW = 4,
}  vapi_enum_fib_path_flags;

#endif

#ifndef defined_vapi_enum_fib_path_type
#define defined_vapi_enum_fib_path_type
typedef enum {
  FIB_API_PATH_TYPE_NORMAL = 0,
  FIB_API_PATH_TYPE_LOCAL = 1,
  FIB_API_PATH_TYPE_DROP = 2,
  FIB_API_PATH_TYPE_UDP_ENCAP = 3,
  FIB_API_PATH_TYPE_BIER_IMP = 4,
  FIB_API_PATH_TYPE_ICMP_UNREACH = 5,
  FIB_API_PATH_TYPE_ICMP_PROHIBIT = 6,
  FIB_API_PATH_TYPE_SOURCE_LOOKUP = 7,
  FIB_API_PATH_TYPE_DVR = 8,
  FIB_API_PATH_TYPE_INTERFACE_RX = 9,
  FIB_API_PATH_TYPE_CLASSIFY = 10,
}  vapi_enum_fib_path_type;

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

#ifndef defined_vapi_type_fib_mpls_label
#define defined_vapi_type_fib_mpls_label
typedef struct __attribute__((__packed__)) {
  u8 is_uniform;
  u32 label;
  u8 ttl;
  u8 exp;
} vapi_type_fib_mpls_label;

static inline void vapi_type_fib_mpls_label_hton(vapi_type_fib_mpls_label *msg)
{
  msg->label = htobe32(msg->label);
}

static inline void vapi_type_fib_mpls_label_ntoh(vapi_type_fib_mpls_label *msg)
{
  msg->label = be32toh(msg->label);
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

#ifndef defined_vapi_type_fib_path_nh
#define defined_vapi_type_fib_path_nh
typedef struct __attribute__((__packed__)) {
  vapi_union_address_union address;
  u32 via_label;
  u32 obj_id;
  u32 classify_table_index;
} vapi_type_fib_path_nh;

static inline void vapi_type_fib_path_nh_hton(vapi_type_fib_path_nh *msg)
{
  msg->via_label = htobe32(msg->via_label);
  msg->obj_id = htobe32(msg->obj_id);
  msg->classify_table_index = htobe32(msg->classify_table_index);
}

static inline void vapi_type_fib_path_nh_ntoh(vapi_type_fib_path_nh *msg)
{
  msg->via_label = be32toh(msg->via_label);
  msg->obj_id = be32toh(msg->obj_id);
  msg->classify_table_index = be32toh(msg->classify_table_index);
}
#endif

#ifndef defined_vapi_type_fib_path
#define defined_vapi_type_fib_path
typedef struct __attribute__((__packed__)) {
  u32 sw_if_index;
  u32 table_id;
  u32 rpf_id;
  u8 weight;
  u8 preference;
  vapi_enum_fib_path_type type;
  vapi_enum_fib_path_flags flags;
  vapi_enum_fib_path_nh_proto proto;
  vapi_type_fib_path_nh nh;
  u8 n_labels;
  vapi_type_fib_mpls_label label_stack[16];
} vapi_type_fib_path;

static inline void vapi_type_fib_path_hton(vapi_type_fib_path *msg)
{
  msg->sw_if_index = htobe32(msg->sw_if_index);
  msg->table_id = htobe32(msg->table_id);
  msg->rpf_id = htobe32(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)htobe32(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)htobe32(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)htobe32(msg->proto);
  vapi_type_fib_path_nh_hton(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_hton(&msg->label_stack[i]); } } while(0);
}

static inline void vapi_type_fib_path_ntoh(vapi_type_fib_path *msg)
{
  msg->sw_if_index = be32toh(msg->sw_if_index);
  msg->table_id = be32toh(msg->table_id);
  msg->rpf_id = be32toh(msg->rpf_id);
  msg->type = (vapi_enum_fib_path_type)be32toh(msg->type);
  msg->flags = (vapi_enum_fib_path_flags)be32toh(msg->flags);
  msg->proto = (vapi_enum_fib_path_nh_proto)be32toh(msg->proto);
  vapi_type_fib_path_nh_ntoh(&msg->nh);
  do { unsigned i; for (i = 0; i < 16; ++i) { vapi_type_fib_mpls_label_ntoh(&msg->label_stack[i]); } } while(0);
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


#ifdef __cplusplus
}
#endif

#endif
