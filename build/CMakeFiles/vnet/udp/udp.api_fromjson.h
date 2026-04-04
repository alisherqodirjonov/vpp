/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_udp_api_fromjson_h
#define included_udp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_udp_encap_t_fromjson (void **mp, int *len, cJSON *o, vl_api_udp_encap_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->src_port);

    item = cJSON_GetObjectItem(o, "dst_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->dst_port);

    item = cJSON_GetObjectItem(o, "src_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->src_ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "dst_ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->dst_ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    return 0;

  error:
    return -1;
}
static inline int vl_api_udp_decap_next_proto_t_fromjson(void **mp, int *len, cJSON *o, vl_api_udp_decap_next_proto_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "UDP_API_DECAP_PROTO_IP4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "UDP_API_DECAP_PROTO_IP6") == 0) {*a = 1; return 0;}
    if (strcmp(p, "UDP_API_DECAP_PROTO_MPLS") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_udp_decap_t_fromjson (void **mp, int *len, cJSON *o, vl_api_udp_decap_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "is_ip4");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_ip4);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "next_proto");
    if (!item) goto error;
    if (vl_api_udp_decap_next_proto_t_fromjson(mp, len, item, &a->next_proto) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_udp_encap_add_t *vl_api_udp_encap_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_encap_add_t);
    vl_api_udp_encap_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "udp_encap");
    if (!item) goto error;
    if (vl_api_udp_encap_t_fromjson((void **)&a, &l, item, &a->udp_encap) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_encap_add_reply_t *vl_api_udp_encap_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_encap_add_reply_t);
    vl_api_udp_encap_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_encap_del_t *vl_api_udp_encap_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_encap_del_t);
    vl_api_udp_encap_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_encap_del_reply_t *vl_api_udp_encap_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_encap_del_reply_t);
    vl_api_udp_encap_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_encap_dump_t *vl_api_udp_encap_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_encap_dump_t);
    vl_api_udp_encap_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_udp_encap_details_t *vl_api_udp_encap_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_encap_details_t);
    vl_api_udp_encap_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "udp_encap");
    if (!item) goto error;
    if (vl_api_udp_encap_t_fromjson((void **)&a, &l, item, &a->udp_encap) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_decap_add_del_t *vl_api_udp_decap_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_decap_add_del_t);
    vl_api_udp_decap_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "udp_decap");
    if (!item) goto error;
    if (vl_api_udp_decap_t_fromjson((void **)&a, &l, item, &a->udp_decap) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_udp_decap_add_del_reply_t *vl_api_udp_decap_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_udp_decap_add_del_reply_t);
    vl_api_udp_decap_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
