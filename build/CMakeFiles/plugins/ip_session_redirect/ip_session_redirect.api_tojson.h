/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/fib/fib_types.api_tojson.h>
#ifndef included_ip_session_redirect_api_tojson_h
#define included_ip_session_redirect_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ip_session_redirect_add_t_tojson (vl_api_ip_session_redirect_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_add");
    cJSON_AddStringToObject(o, "_crc", "2f78ffda");
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddNumberToObject(o, "match_len", a->match_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->match, 80);
    cJSON_AddStringToObject(o, "match", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "opaque_index", a->opaque_index);
    cJSON_AddBoolToObject(o, "is_punt", a->is_punt);
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_add_reply_t_tojson (vl_api_ip_session_redirect_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_add_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_add_v2_t_tojson (vl_api_ip_session_redirect_add_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_add_v2");
    cJSON_AddStringToObject(o, "_crc", "0765f51f");
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddNumberToObject(o, "opaque_index", a->opaque_index);
    cJSON_AddItemToObject(o, "proto", vl_api_fib_path_nh_proto_t_tojson(a->proto));
    cJSON_AddBoolToObject(o, "is_punt", a->is_punt);
    cJSON_AddNumberToObject(o, "match_len", a->match_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->match, 80);
    cJSON_AddStringToObject(o, "match", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_add_v2_reply_t_tojson (vl_api_ip_session_redirect_add_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_add_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_del_t_tojson (vl_api_ip_session_redirect_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_del");
    cJSON_AddStringToObject(o, "_crc", "fb643388");
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddNumberToObject(o, "match_len", a->match_len);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->match, a->match_len);
    cJSON_AddStringToObject(o, "match", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_del_reply_t_tojson (vl_api_ip_session_redirect_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_dump_t_tojson (vl_api_ip_session_redirect_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_dump");
    cJSON_AddStringToObject(o, "_crc", "33554253");
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    return o;
}
static inline cJSON *vl_api_ip_session_redirect_details_t_tojson (vl_api_ip_session_redirect_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ip_session_redirect_details");
    cJSON_AddStringToObject(o, "_crc", "4487a233");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "table_index", a->table_index);
    cJSON_AddNumberToObject(o, "opaque_index", a->opaque_index);
    cJSON_AddBoolToObject(o, "is_punt", a->is_punt);
    cJSON_AddBoolToObject(o, "is_ip6", a->is_ip6);
    cJSON_AddNumberToObject(o, "match_length", a->match_length);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->match, 80);
    cJSON_AddStringToObject(o, "match", s);
    vec_free(s);
    }
    cJSON_AddNumberToObject(o, "n_paths", a->n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "paths");
        for (i = 0; i < a->n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->paths[i]));
        }
    }
    return o;
}
#endif
