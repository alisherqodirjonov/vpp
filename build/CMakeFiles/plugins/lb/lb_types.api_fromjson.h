/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_lb_types_api_fromjson_h
#define included_lb_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_lb_srv_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lb_srv_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LB_API_SRV_TYPE_CLUSTERIP") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LB_API_SRV_TYPE_NODEPORT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "LB_API_SRV_N_TYPES") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_lb_encap_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lb_encap_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LB_API_ENCAP_TYPE_GRE4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LB_API_ENCAP_TYPE_GRE6") == 0) {*a = 1; return 0;}
    if (strcmp(p, "LB_API_ENCAP_TYPE_L3DSR") == 0) {*a = 2; return 0;}
    if (strcmp(p, "LB_API_ENCAP_TYPE_NAT4") == 0) {*a = 3; return 0;}
    if (strcmp(p, "LB_API_ENCAP_TYPE_NAT6") == 0) {*a = 4; return 0;}
    if (strcmp(p, "LB_API_ENCAP_N_TYPES") == 0) {*a = 5; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_lb_lkp_type_t_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lb_lkp_type_t_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LB_API_LKP_SAME_IP_PORT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LB_API_LKP_DIFF_IP_PORT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "LB_API_LKP_ALL_PORT_IP") == 0) {*a = 2; return 0;}
    if (strcmp(p, "LB_API_LKP_N_TYPES") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_lb_vip_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lb_vip_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LB_API_VIP_TYPE_IP6_GRE6") == 0) {*a = 0; return 0;}
    if (strcmp(p, "LB_API_VIP_TYPE_IP6_GRE4") == 0) {*a = 1; return 0;}
    if (strcmp(p, "LB_API_VIP_TYPE_IP4_GRE6") == 0) {*a = 2; return 0;}
    if (strcmp(p, "LB_API_VIP_TYPE_IP4_GRE4") == 0) {*a = 3; return 0;}
    if (strcmp(p, "LB_API_VIP_TYPE_IP4_L3DSR") == 0) {*a = 4; return 0;}
    if (strcmp(p, "LB_API_VIP_TYPE_IP4_NAT4") == 0) {*a = 5; return 0;}
    if (strcmp(p, "LB_API_VIP_TYPE_IP6_NAT6") == 0) {*a = 6; return 0;}
    if (strcmp(p, "LB_API_VIP_N_TYPES") == 0) {*a = 7; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_lb_nat_protocol_t_fromjson(void **mp, int *len, cJSON *o, vl_api_lb_nat_protocol_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "LB_API_NAT_PROTOCOL_UDP") == 0) {*a = 6; return 0;}
    if (strcmp(p, "LB_API_NAT_PROTOCOL_TCP") == 0) {*a = 23; return 0;}
    if (strcmp(p, "LB_API_NAT_PROTOCOL_ANY") == 0) {*a = 4294967295; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_lb_vip_t_fromjson (void **mp, int *len, cJSON *o, vl_api_lb_vip_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "pfx");
    if (!item) goto error;
    if (vl_api_address_with_prefix_t_fromjson(mp, len, item, &a->pfx) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    return 0;

  error:
    return -1;
}
#endif
