/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#ifndef included_acl_types_api_fromjson_h
#define included_acl_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_acl_action_t_fromjson(void **mp, int *len, cJSON *o, vl_api_acl_action_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "ACL_ACTION_API_DENY") == 0) {*a = 0; return 0;}
    if (strcmp(p, "ACL_ACTION_API_PERMIT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "ACL_ACTION_API_PERMIT_REFLECT") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_acl_rule_t_fromjson (void **mp, int *len, cJSON *o, vl_api_acl_rule_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "is_permit");
    if (!item) goto error;
    if (vl_api_acl_action_t_fromjson(mp, len, item, &a->is_permit) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->src_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->dst_prefix) < 0) goto error;

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "srcport_or_icmptype_first");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->srcport_or_icmptype_first);

    item = cJSON_GetObjectItem(o, "srcport_or_icmptype_last");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->srcport_or_icmptype_last);

    item = cJSON_GetObjectItem(o, "dstport_or_icmpcode_first");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->dstport_or_icmpcode_first);

    item = cJSON_GetObjectItem(o, "dstport_or_icmpcode_last");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->dstport_or_icmpcode_last);

    item = cJSON_GetObjectItem(o, "tcp_flags_mask");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tcp_flags_mask);

    item = cJSON_GetObjectItem(o, "tcp_flags_value");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tcp_flags_value);

    return 0;

  error:
    return -1;
}
static inline int vl_api_macip_acl_rule_t_fromjson (void **mp, int *len, cJSON *o, vl_api_macip_acl_rule_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "is_permit");
    if (!item) goto error;
    if (vl_api_acl_action_t_fromjson(mp, len, item, &a->is_permit) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->src_mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_mac_mask");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->src_mac_mask) < 0) goto error;

    item = cJSON_GetObjectItem(o, "src_prefix");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->src_prefix) < 0) goto error;

    return 0;

  error:
    return -1;
}
#endif
