/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_tunnel_types_api_fromjson_h
#define included_tunnel_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_tunnel_encap_decap_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_tunnel_encap_decap_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DF") == 0) {*a = 1; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_SET_DF") == 0) {*a = 2; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP") == 0) {*a = 4; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN") == 0) {*a = 8; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_DECAP_COPY_ECN") == 0) {*a = 16; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_INNER_HASH") == 0) {*a = 32; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_HOP_LIMIT") == 0) {*a = 64; return 0;}
    if (strcmp(p, "TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_FLOW_LABEL") == 0) {*a = 128; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_tunnel_mode_t_fromjson(void **mp, int *len, cJSON *o, vl_api_tunnel_mode_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "TUNNEL_API_MODE_P2P") == 0) {*a = 0; return 0;}
    if (strcmp(p, "TUNNEL_API_MODE_MP") == 0) {*a = 1; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_tunnel_flags_t_fromjson (void **mp, int *len, cJSON *o, vl_api_tunnel_flags_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "TUNNEL_API_FLAG_TRACK_MTU") == 0) *a |= 1;
    }
   return 0;
}
static inline int vl_api_tunnel_t_fromjson (void **mp, int *len, cJSON *o, vl_api_tunnel_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->instance);

    item = cJSON_GetObjectItem(o, "src");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->src) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->dst) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "encap_decap_flags");
    if (!item) goto error;
    if (vl_api_tunnel_encap_decap_flags_t_fromjson(mp, len, item, &a->encap_decap_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mode");
    if (!item) goto error;
    if (vl_api_tunnel_mode_t_fromjson(mp, len, item, &a->mode) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_tunnel_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dscp");
    if (!item) goto error;
    if (vl_api_ip_dscp_t_fromjson(mp, len, item, &a->dscp) < 0) goto error;

    item = cJSON_GetObjectItem(o, "hop_limit");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->hop_limit);

    return 0;

  error:
    return -1;
}
#endif
