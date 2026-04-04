/* Imported API files */
#ifndef included_dns_api_tojson_h
#define included_dns_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_dns_enable_disable_t_tojson (vl_api_dns_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "8050327d");
    cJSON_AddNumberToObject(o, "enable", a->enable);
    return o;
}
static inline cJSON *vl_api_dns_enable_disable_reply_t_tojson (vl_api_dns_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dns_name_server_add_del_t_tojson (vl_api_dns_name_server_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_name_server_add_del");
    cJSON_AddStringToObject(o, "_crc", "3bb05d8c");
    cJSON_AddNumberToObject(o, "is_ip6", a->is_ip6);
    cJSON_AddNumberToObject(o, "is_add", a->is_add);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->server_address, 16);
    cJSON_AddStringToObject(o, "server_address", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_dns_name_server_add_del_reply_t_tojson (vl_api_dns_name_server_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_name_server_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_dns_resolve_name_t_tojson (vl_api_dns_resolve_name_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_resolve_name");
    cJSON_AddStringToObject(o, "_crc", "c6566676");
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->name, 256);
    cJSON_AddStringToObject(o, "name", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_dns_resolve_name_reply_t_tojson (vl_api_dns_resolve_name_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_resolve_name_reply");
    cJSON_AddStringToObject(o, "_crc", "c2d758c3");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "ip4_set", a->ip4_set);
    cJSON_AddNumberToObject(o, "ip6_set", a->ip6_set);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->ip4_address, 4);
    cJSON_AddStringToObject(o, "ip4_address", s);
    vec_free(s);
    }
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->ip6_address, 16);
    cJSON_AddStringToObject(o, "ip6_address", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_dns_resolve_ip_t_tojson (vl_api_dns_resolve_ip_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_resolve_ip");
    cJSON_AddStringToObject(o, "_crc", "ae96a1a3");
    cJSON_AddNumberToObject(o, "is_ip6", a->is_ip6);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->address, 16);
    cJSON_AddStringToObject(o, "address", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_dns_resolve_ip_reply_t_tojson (vl_api_dns_resolve_ip_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "dns_resolve_ip_reply");
    cJSON_AddStringToObject(o, "_crc", "49ed78d6");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->name, 256);
    cJSON_AddStringToObject(o, "name", s);
    vec_free(s);
    }
    return o;
}
#endif
