/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_punt_api_fromjson_h
#define included_punt_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_punt_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_punt_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "PUNT_API_TYPE_L4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "PUNT_API_TYPE_IP_PROTO") == 0) {*a = 1; return 0;}
    if (strcmp(p, "PUNT_API_TYPE_EXCEPTION") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_punt_l4_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_l4_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson(mp, len, item, &a->af) < 0) goto error;

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
static inline int vl_api_punt_ip_proto_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_ip_proto_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "af");
    if (!item) goto error;
    if (vl_api_address_family_t_fromjson(mp, len, item, &a->af) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    if (vl_api_ip_proto_t_fromjson(mp, len, item, &a->protocol) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_punt_exception_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_exception_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    return 0;

  error:
    return -1;
}
static inline int vl_api_punt_union_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_union_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    item = cJSON_GetObjectItem(o, "exception");
    if (item) {
    if (vl_api_punt_exception_t_fromjson(mp, len, item, &a->exception) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "l4");
    if (item) {
    if (vl_api_punt_l4_t_fromjson(mp, len, item, &a->l4) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "ip_proto");
    if (item) {
    if (vl_api_punt_ip_proto_t_fromjson(mp, len, item, &a->ip_proto) < 0) goto error;
    };

    return 0;

  error:
    return -1;
}
static inline int vl_api_punt_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_punt_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_union_t_fromjson(mp, len, item, &a->punt) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_punt_reason_t_fromjson (void **mp, int *len, cJSON *o, vl_api_punt_reason_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    *mp = cJSON_realloc(*mp, *len + plen);
    if (*mp == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)*mp + *len - sizeof(vl_api_string_t));
    *len += plen;

    return 0;

  error:
    return -1;
}
static inline vl_api_set_punt_t *vl_api_set_punt_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_punt_t);
    vl_api_set_punt_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_set_punt_reply_t *vl_api_set_punt_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_set_punt_reply_t);
    vl_api_set_punt_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_socket_register_t *vl_api_punt_socket_register_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_socket_register_t);
    vl_api_punt_socket_register_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "header_version");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->header_version);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pathname");
    if (!item) goto error;
    strncpy_s((char *)a->pathname, sizeof(a->pathname), cJSON_GetStringValue(item), sizeof(a->pathname) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_socket_register_reply_t *vl_api_punt_socket_register_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_socket_register_reply_t);
    vl_api_punt_socket_register_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "pathname");
    if (!item) goto error;
    strncpy_s((char *)a->pathname, sizeof(a->pathname), cJSON_GetStringValue(item), sizeof(a->pathname) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_socket_dump_t *vl_api_punt_socket_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_socket_dump_t);
    vl_api_punt_socket_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_punt_type_t_fromjson((void **)&a, &l, item, &a->type) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_socket_details_t *vl_api_punt_socket_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_socket_details_t);
    vl_api_punt_socket_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pathname");
    if (!item) goto error;
    strncpy_s((char *)a->pathname, sizeof(a->pathname), cJSON_GetStringValue(item), sizeof(a->pathname) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_socket_deregister_t *vl_api_punt_socket_deregister_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_socket_deregister_t);
    vl_api_punt_socket_deregister_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "punt");
    if (!item) goto error;
    if (vl_api_punt_t_fromjson((void **)&a, &l, item, &a->punt) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_socket_deregister_reply_t *vl_api_punt_socket_deregister_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_socket_deregister_reply_t);
    vl_api_punt_socket_deregister_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_reason_dump_t *vl_api_punt_reason_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_reason_dump_t);
    vl_api_punt_reason_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "reason");
    if (!item) goto error;
    if (vl_api_punt_reason_t_fromjson((void **)&a, &l, item, &a->reason) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_punt_reason_details_t *vl_api_punt_reason_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_punt_reason_details_t);
    vl_api_punt_reason_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "reason");
    if (!item) goto error;
    if (vl_api_punt_reason_t_fromjson((void **)&a, &l, item, &a->reason) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
