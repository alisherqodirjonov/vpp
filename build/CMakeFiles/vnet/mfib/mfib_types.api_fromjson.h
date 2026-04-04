/* Imported API files */
#include <vnet/fib/fib_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_mfib_types_api_fromjson_h
#define included_mfib_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_mfib_entry_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_mfib_entry_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "MFIB_API_ENTRY_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "MFIB_API_ENTRY_FLAG_SIGNAL") == 0) {*a = 1; return 0;}
    if (strcmp(p, "MFIB_API_ENTRY_FLAG_DROP") == 0) {*a = 2; return 0;}
    if (strcmp(p, "MFIB_API_ENTRY_FLAG_CONNECTED") == 0) {*a = 4; return 0;}
    if (strcmp(p, "MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF") == 0) {*a = 8; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_mfib_itf_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_mfib_itf_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "MFIB_API_ITF_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "MFIB_API_ITF_FLAG_NEGATE_SIGNAL") == 0) {*a = 1; return 0;}
    if (strcmp(p, "MFIB_API_ITF_FLAG_ACCEPT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "MFIB_API_ITF_FLAG_FORWARD") == 0) {*a = 4; return 0;}
    if (strcmp(p, "MFIB_API_ITF_FLAG_SIGNAL_PRESENT") == 0) {*a = 8; return 0;}
    if (strcmp(p, "MFIB_API_ITF_FLAG_DONT_PRESERVE") == 0) {*a = 16; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_mfib_path_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mfib_path_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "itf_flags");
    if (!item) goto error;
    if (vl_api_mfib_itf_flags_t_fromjson(mp, len, item, &a->itf_flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "path");
    if (!item) goto error;
    if (vl_api_fib_path_t_fromjson(mp, len, item, &a->path) < 0) goto error;

    return 0;

  error:
    return -1;
}
#endif
