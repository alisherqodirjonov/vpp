/* Imported API files */
#include <vnet/fib/fib_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_mfib_types_api_tojson_h
#define included_mfib_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_mfib_entry_flags_t_tojson (vl_api_mfib_entry_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("MFIB_API_ENTRY_FLAG_NONE");
    case 1:
        return cJSON_CreateString("MFIB_API_ENTRY_FLAG_SIGNAL");
    case 2:
        return cJSON_CreateString("MFIB_API_ENTRY_FLAG_DROP");
    case 4:
        return cJSON_CreateString("MFIB_API_ENTRY_FLAG_CONNECTED");
    case 8:
        return cJSON_CreateString("MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_mfib_itf_flags_t_tojson (vl_api_mfib_itf_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("MFIB_API_ITF_FLAG_NONE");
    case 1:
        return cJSON_CreateString("MFIB_API_ITF_FLAG_NEGATE_SIGNAL");
    case 2:
        return cJSON_CreateString("MFIB_API_ITF_FLAG_ACCEPT");
    case 4:
        return cJSON_CreateString("MFIB_API_ITF_FLAG_FORWARD");
    case 8:
        return cJSON_CreateString("MFIB_API_ITF_FLAG_SIGNAL_PRESENT");
    case 16:
        return cJSON_CreateString("MFIB_API_ITF_FLAG_DONT_PRESERVE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_mfib_path_t_tojson (vl_api_mfib_path_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddItemToObject(o, "itf_flags", vl_api_mfib_itf_flags_t_tojson(a->itf_flags));
    cJSON_AddItemToObject(o, "path", vl_api_fib_path_t_tojson(&a->path));
    return o;
}
#endif
