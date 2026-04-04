/* Imported API files */
#ifndef included_tls_openssl_api_tojson_h
#define included_tls_openssl_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_tls_openssl_set_engine_t_tojson (vl_api_tls_openssl_set_engine_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tls_openssl_set_engine");
    cJSON_AddStringToObject(o, "_crc", "e34d95c1");
    cJSON_AddNumberToObject(o, "async_enable", a->async_enable);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->engine, 64);
    cJSON_AddStringToObject(o, "engine", s);
    vec_free(s);
    }
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->algorithm, 64);
    cJSON_AddStringToObject(o, "algorithm", s);
    vec_free(s);
    }
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->ciphers, 64);
    cJSON_AddStringToObject(o, "ciphers", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_tls_openssl_set_engine_reply_t_tojson (vl_api_tls_openssl_set_engine_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "tls_openssl_set_engine_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
