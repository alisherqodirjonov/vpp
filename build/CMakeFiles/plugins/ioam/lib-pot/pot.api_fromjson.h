/* Imported API files */
#ifndef included_pot_api_fromjson_h
#define included_pot_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline vl_api_pot_profile_add_t *vl_api_pot_profile_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_add_t);
    vl_api_pot_profile_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "validator");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->validator);

    item = cJSON_GetObjectItem(o, "secret_key");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret_key);

    item = cJSON_GetObjectItem(o, "secret_share");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret_share);

    item = cJSON_GetObjectItem(o, "prime");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->prime);

    item = cJSON_GetObjectItem(o, "max_bits");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->max_bits);

    item = cJSON_GetObjectItem(o, "lpc");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->lpc);

    item = cJSON_GetObjectItem(o, "polynomial_public");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->polynomial_public);

    item = cJSON_GetObjectItem(o, "list_name");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_add_reply_t *vl_api_pot_profile_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_add_reply_t);
    vl_api_pot_profile_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_activate_t *vl_api_pot_profile_activate_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_activate_t);
    vl_api_pot_profile_activate_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "list_name");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_activate_reply_t *vl_api_pot_profile_activate_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_activate_reply_t);
    vl_api_pot_profile_activate_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_del_t *vl_api_pot_profile_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_del_t);
    vl_api_pot_profile_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "list_name");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    a = cJSON_realloc(a, l + plen);
    if (a == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)a + l - sizeof(vl_api_string_t));
    l += plen;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_del_reply_t *vl_api_pot_profile_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_del_reply_t);
    vl_api_pot_profile_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_show_config_dump_t *vl_api_pot_profile_show_config_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_show_config_dump_t);
    vl_api_pot_profile_show_config_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_pot_profile_show_config_details_t *vl_api_pot_profile_show_config_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_pot_profile_show_config_details_t);
    vl_api_pot_profile_show_config_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->id);

    item = cJSON_GetObjectItem(o, "validator");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->validator);

    item = cJSON_GetObjectItem(o, "secret_key");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret_key);

    item = cJSON_GetObjectItem(o, "secret_share");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->secret_share);

    item = cJSON_GetObjectItem(o, "prime");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->prime);

    item = cJSON_GetObjectItem(o, "bit_mask");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->bit_mask);

    item = cJSON_GetObjectItem(o, "lpc");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->lpc);

    item = cJSON_GetObjectItem(o, "polynomial_public");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->polynomial_public);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
