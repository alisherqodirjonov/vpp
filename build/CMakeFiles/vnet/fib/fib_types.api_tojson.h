/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_fib_types_api_tojson_h
#define included_fib_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_fib_mpls_label_t_tojson (vl_api_fib_mpls_label_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "is_uniform", a->is_uniform);
    cJSON_AddNumberToObject(o, "label", a->label);
    cJSON_AddNumberToObject(o, "ttl", a->ttl);
    cJSON_AddNumberToObject(o, "exp", a->exp);
    return o;
}
static inline cJSON *vl_api_fib_path_nh_proto_t_tojson (vl_api_fib_path_nh_proto_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("FIB_API_PATH_NH_PROTO_IP4");
    case 1:
        return cJSON_CreateString("FIB_API_PATH_NH_PROTO_IP6");
    case 2:
        return cJSON_CreateString("FIB_API_PATH_NH_PROTO_MPLS");
    case 3:
        return cJSON_CreateString("FIB_API_PATH_NH_PROTO_ETHERNET");
    case 4:
        return cJSON_CreateString("FIB_API_PATH_NH_PROTO_BIER");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_fib_path_flags_t_tojson (vl_api_fib_path_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("FIB_API_PATH_FLAG_NONE");
    case 1:
        return cJSON_CreateString("FIB_API_PATH_FLAG_RESOLVE_VIA_ATTACHED");
    case 2:
        return cJSON_CreateString("FIB_API_PATH_FLAG_RESOLVE_VIA_HOST");
    case 4:
        return cJSON_CreateString("FIB_API_PATH_FLAG_POP_PW_CW");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_fib_path_nh_t_tojson (vl_api_fib_path_nh_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "address", vl_api_address_union_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "via_label", a->via_label);
    cJSON_AddNumberToObject(o, "obj_id", a->obj_id);
    cJSON_AddNumberToObject(o, "classify_table_index", a->classify_table_index);
    return o;
}
static inline cJSON *vl_api_fib_path_type_t_tojson (vl_api_fib_path_type_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("FIB_API_PATH_TYPE_NORMAL");
    case 1:
        return cJSON_CreateString("FIB_API_PATH_TYPE_LOCAL");
    case 2:
        return cJSON_CreateString("FIB_API_PATH_TYPE_DROP");
    case 3:
        return cJSON_CreateString("FIB_API_PATH_TYPE_UDP_ENCAP");
    case 4:
        return cJSON_CreateString("FIB_API_PATH_TYPE_BIER_IMP");
    case 5:
        return cJSON_CreateString("FIB_API_PATH_TYPE_ICMP_UNREACH");
    case 6:
        return cJSON_CreateString("FIB_API_PATH_TYPE_ICMP_PROHIBIT");
    case 7:
        return cJSON_CreateString("FIB_API_PATH_TYPE_SOURCE_LOOKUP");
    case 8:
        return cJSON_CreateString("FIB_API_PATH_TYPE_DVR");
    case 9:
        return cJSON_CreateString("FIB_API_PATH_TYPE_INTERFACE_RX");
    case 10:
        return cJSON_CreateString("FIB_API_PATH_TYPE_CLASSIFY");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_fib_path_t_tojson (vl_api_fib_path_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "rpf_id", a->rpf_id);
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddNumberToObject(o, "preference", a->preference);
    cJSON_AddItemToObject(o, "type", vl_api_fib_path_type_t_tojson(a->type));
    cJSON_AddItemToObject(o, "flags", vl_api_fib_path_flags_t_tojson(a->flags));
    cJSON_AddItemToObject(o, "proto", vl_api_fib_path_nh_proto_t_tojson(a->proto));
    cJSON_AddItemToObject(o, "nh", vl_api_fib_path_nh_t_tojson(&a->nh));
    cJSON_AddNumberToObject(o, "n_labels", a->n_labels);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "label_stack");
        for (i = 0; i < 16; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_mpls_label_t_tojson(&a->label_stack[i]));
        }
    }
    return o;
}
#endif
