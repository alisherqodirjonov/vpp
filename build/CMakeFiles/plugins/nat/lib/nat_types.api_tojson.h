/* Imported API files */
#ifndef included_nat_types_api_tojson_h
#define included_nat_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_nat_timeouts_t_tojson (vl_api_nat_timeouts_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "udp", a->udp);
    cJSON_AddNumberToObject(o, "tcp_established", a->tcp_established);
    cJSON_AddNumberToObject(o, "tcp_transitory", a->tcp_transitory);
    cJSON_AddNumberToObject(o, "icmp", a->icmp);
    return o;
}
static inline cJSON *vl_api_nat_log_level_t_tojson (vl_api_nat_log_level_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("NAT_LOG_NONE");
    case 1:
        return cJSON_CreateString("NAT_LOG_ERROR");
    case 2:
        return cJSON_CreateString("NAT_LOG_WARNING");
    case 3:
        return cJSON_CreateString("NAT_LOG_NOTICE");
    case 4:
        return cJSON_CreateString("NAT_LOG_INFO");
    case 5:
        return cJSON_CreateString("NAT_LOG_DEBUG");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_nat_config_flags_t_tojson (vl_api_nat_config_flags_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("NAT_IS_NONE");
    case 1:
        return cJSON_CreateString("NAT_IS_TWICE_NAT");
    case 2:
        return cJSON_CreateString("NAT_IS_SELF_TWICE_NAT");
    case 4:
        return cJSON_CreateString("NAT_IS_OUT2IN_ONLY");
    case 8:
        return cJSON_CreateString("NAT_IS_ADDR_ONLY");
    case 16:
        return cJSON_CreateString("NAT_IS_OUTSIDE");
    case 32:
        return cJSON_CreateString("NAT_IS_INSIDE");
    case 64:
        return cJSON_CreateString("NAT_IS_STATIC");
    case 128:
        return cJSON_CreateString("NAT_IS_EXT_HOST_VALID");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
#endif
