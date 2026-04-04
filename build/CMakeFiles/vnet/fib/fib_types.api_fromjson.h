/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_fib_types_api_fromjson_h
#define included_fib_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_fib_mpls_label_t_fromjson (void **mp, int *len, cJSON *o, vl_api_fib_mpls_label_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "is_uniform");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->is_uniform);

    item = cJSON_GetObjectItem(o, "label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->label);

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->ttl);

    item = cJSON_GetObjectItem(o, "exp");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->exp);

    return 0;

  error:
    return -1;
}
static inline int vl_api_fib_path_nh_proto_t_fromjson(void **mp, int *len, cJSON *o, vl_api_fib_path_nh_proto_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FIB_API_PATH_NH_PROTO_IP4") == 0) {*a = 0; return 0;}
    if (strcmp(p, "FIB_API_PATH_NH_PROTO_IP6") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FIB_API_PATH_NH_PROTO_MPLS") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FIB_API_PATH_NH_PROTO_ETHERNET") == 0) {*a = 3; return 0;}
    if (strcmp(p, "FIB_API_PATH_NH_PROTO_BIER") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_fib_path_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_fib_path_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FIB_API_PATH_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FIB_API_PATH_FLAG_RESOLVE_VIA_HOST") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FIB_API_PATH_FLAG_POP_PW_CW") == 0) {*a = 4; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_fib_path_nh_t_fromjson (void **mp, int *len, cJSON *o, vl_api_fib_path_nh_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_address_union_t_fromjson(mp, len, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "via_label");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->via_label);

    item = cJSON_GetObjectItem(o, "obj_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->obj_id);

    item = cJSON_GetObjectItem(o, "classify_table_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->classify_table_index);

    return 0;

  error:
    return -1;
}
static inline int vl_api_fib_path_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_fib_path_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "FIB_API_PATH_TYPE_NORMAL") == 0) {*a = 0; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_LOCAL") == 0) {*a = 1; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_DROP") == 0) {*a = 2; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_UDP_ENCAP") == 0) {*a = 3; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_BIER_IMP") == 0) {*a = 4; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_ICMP_UNREACH") == 0) {*a = 5; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_ICMP_PROHIBIT") == 0) {*a = 6; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_SOURCE_LOOKUP") == 0) {*a = 7; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_DVR") == 0) {*a = 8; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_INTERFACE_RX") == 0) {*a = 9; return 0;}
    if (strcmp(p, "FIB_API_PATH_TYPE_CLASSIFY") == 0) {*a = 10; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_fib_path_t_fromjson (void **mp, int *len, cJSON *o, vl_api_fib_path_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sw_if_index);

    item = cJSON_GetObjectItem(o, "table_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_id);

    item = cJSON_GetObjectItem(o, "rpf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->rpf_id);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "preference");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->preference);

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_fib_path_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_fib_path_flags_t_fromjson(mp, len, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "proto");
    if (!item) goto error;
    if (vl_api_fib_path_nh_proto_t_fromjson(mp, len, item, &a->proto) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nh");
    if (!item) goto error;
    if (vl_api_fib_path_nh_t_fromjson(mp, len, item, &a->nh) < 0) goto error;

    item = cJSON_GetObjectItem(o, "n_labels");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->n_labels);

    item = cJSON_GetObjectItem(o, "label_stack");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "label_stack");
        int size = cJSON_GetArraySize(array);
        if (size != 16) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_fib_mpls_label_t_fromjson(mp, len, e, &a->label_stack[i]) < 0) goto error;
        }
    }

    return 0;

  error:
    return -1;
}
#endif
