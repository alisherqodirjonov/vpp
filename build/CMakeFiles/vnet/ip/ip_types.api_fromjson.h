/* Imported API files */
#ifndef included_ip_types_api_fromjson_h
#define included_ip_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
/* Manual print ip4_address */
/* Manual print ip6_address */
static inline int vl_api_address_family_t_fromjson(void **mp, int *len, cJSON *o, vl_api_address_family_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "ADDRESS_IP4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "ADDRESS_IP6") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ip_feature_location_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_feature_location_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_API_FEATURE_INPUT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IP_API_FEATURE_OUTPUT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IP_API_FEATURE_LOCAL") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IP_API_FEATURE_PUNT") == 0) {*a = 3; return 0;}
    if (strcmp(p, "IP_API_FEATURE_DROP") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ip_ecn_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_ecn_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_API_ECN_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IP_API_ECN_ECT0") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IP_API_ECN_ECT1") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IP_API_ECN_CE") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ip_dscp_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_dscp_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_API_DSCP_CS0") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS1") == 0) {*a = 8; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF11") == 0) {*a = 10; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF12") == 0) {*a = 12; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF13") == 0) {*a = 14; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS2") == 0) {*a = 16; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF21") == 0) {*a = 18; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF22") == 0) {*a = 20; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF23") == 0) {*a = 22; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS3") == 0) {*a = 24; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF31") == 0) {*a = 26; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF32") == 0) {*a = 28; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF33") == 0) {*a = 30; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS4") == 0) {*a = 32; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF41") == 0) {*a = 34; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF42") == 0) {*a = 36; return 0;}
    if (strcmp(p, "IP_API_DSCP_AF43") == 0) {*a = 38; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS5") == 0) {*a = 40; return 0;}
    if (strcmp(p, "IP_API_DSCP_EF") == 0) {*a = 46; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS6") == 0) {*a = 48; return 0;}
    if (strcmp(p, "IP_API_DSCP_CS7") == 0) {*a = 50; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_ip_proto_t_fromjson(void **mp, int *len, cJSON *o, vl_api_ip_proto_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "IP_API_PROTO_HOPOPT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "IP_API_PROTO_ICMP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "IP_API_PROTO_IGMP") == 0) {*a = 2; return 0;}
    if (strcmp(p, "IP_API_PROTO_TCP") == 0) {*a = 6; return 0;}
    if (strcmp(p, "IP_API_PROTO_UDP") == 0) {*a = 17; return 0;}
    if (strcmp(p, "IP_API_PROTO_GRE") == 0) {*a = 47; return 0;}
    if (strcmp(p, "IP_API_PROTO_ESP") == 0) {*a = 50; return 0;}
    if (strcmp(p, "IP_API_PROTO_AH") == 0) {*a = 51; return 0;}
    if (strcmp(p, "IP_API_PROTO_ICMP6") == 0) {*a = 58; return 0;}
    if (strcmp(p, "IP_API_PROTO_EIGRP") == 0) {*a = 88; return 0;}
    if (strcmp(p, "IP_API_PROTO_OSPF") == 0) {*a = 89; return 0;}
    if (strcmp(p, "IP_API_PROTO_SCTP") == 0) {*a = 132; return 0;}
    if (strcmp(p, "IP_API_PROTO_RESERVED") == 0) {*a = 255; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_address_union_t_fromjson (void **mp, int *len, cJSON *o, vl_api_address_union_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    item = cJSON_GetObjectItem(o, "ip4");
    if (item) {
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->ip4) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip6");
    if (item) {
    if (vl_api_ip6_address_t_fromjson(mp, len, item, &a->ip6) < 0) goto error;
    };

    return 0;

  error:
    return -1;
}
/* Manual print address */
/* Manual print prefix */
static inline int vl_api_ip4_address_and_mask_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip4_address_and_mask_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->mask) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_ip6_address_and_mask_t_fromjson (void **mp, int *len, cJSON *o, vl_api_ip6_address_and_mask_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson(mp, len, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mask");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson(mp, len, item, &a->mask) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_mprefix_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mprefix_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson(mp, len, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "grp_address_length");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->grp_address_length);

    item = cJSON_GetObjectItem(o, "grp_address");
    if (!item) goto error;
    if (vl_api_address_union_t_fromjson(mp, len, item, &a->grp_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_address");
    if (!item) goto error;
    if (vl_api_address_union_t_fromjson(mp, len, item, &a->src_address) < 0) goto error;

    return 0;

  error:
    return -1;
}
/* Manual print ip6_prefix */
/* Manual print ip4_prefix */
/* Manual print address_with_prefix */
/* Manual print ip4_address_with_prefix */
/* Manual print ip6_address_with_prefix */
static inline int vl_api_prefix_matcher_t_fromjson (void **mp, int *len, cJSON *o, vl_api_prefix_matcher_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "le");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->le);

    item = cJSON_GetObjectItem(o, "ge");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ge);

    return 0;

  error:
    return -1;
}
#endif
