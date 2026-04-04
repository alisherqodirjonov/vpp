/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_lisp_types_api_fromjson_h
#define included_lisp_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_local_locator_t_fromjson (void **mp, int *len, cJSON *o, vl_api_local_locator_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->weight);

    return 0;

  error:
    return -1;
}
static inline int vl_api_remote_locator_t_fromjson (void **mp, int *len, cJSON *o, vl_api_remote_locator_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "priority");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->priority);

    item = cJSON_GetObjectItem(o, "weight");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->weight);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->ip_address) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_eid_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_eid_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "EID_TYPE_API_PREFIX") == 0) {*a = 0; return 0;}
    if (strcmp(p, "EID_TYPE_API_MAC") == 0) {*a = 1; return 0;}
    if (strcmp(p, "EID_TYPE_API_NSH") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_nsh_t_fromjson (void **mp, int *len, cJSON *o, vl_api_nsh_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "spi");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->spi);

    item = cJSON_GetObjectItem(o, "si");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->si);

    return 0;

  error:
    return -1;
}
static inline int vl_api_eid_address_t_fromjson (void **mp, int *len, cJSON *o, vl_api_eid_address_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    item = cJSON_GetObjectItem(o, "prefix");
    if (item) {
    if (vl_api_prefix_t_fromjson(mp, len, item, &a->prefix) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "mac");
    if (item) {
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac) < 0) goto error;
    };
    item = cJSON_GetObjectItem(o, "nsh");
    if (item) {
    if (vl_api_nsh_t_fromjson(mp, len, item, &a->nsh) < 0) goto error;
    };

    return 0;

  error:
    return -1;
}
static inline int vl_api_eid_t_fromjson (void **mp, int *len, cJSON *o, vl_api_eid_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "type");
    if (!item) goto error;
    if (vl_api_eid_type_t_fromjson(mp, len, item, &a->type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_eid_address_t_fromjson(mp, len, item, &a->address) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline int vl_api_hmac_key_id_t_fromjson(void **mp, int *len, cJSON *o, vl_api_hmac_key_id_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "KEY_ID_API_HMAC_NO_KEY") == 0) {*a = 0; return 0;}
    if (strcmp(p, "KEY_ID_API_HMAC_SHA_1_96") == 0) {*a = 1; return 0;}
    if (strcmp(p, "KEY_ID_API_HMAC_SHA_256_128") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_hmac_key_t_fromjson (void **mp, int *len, cJSON *o, vl_api_hmac_key_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "id");
    if (!item) goto error;
    if (vl_api_hmac_key_id_t_fromjson(mp, len, item, &a->id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "key");
    if (!item) goto error;
    if (u8string_fromjson2(o, "key", a->key) < 0) goto error;

    return 0;

  error:
    return -1;
}
#endif
