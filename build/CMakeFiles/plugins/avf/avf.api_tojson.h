/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#ifndef included_avf_api_tojson_h
#define included_avf_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_avf_create_t_tojson (vl_api_avf_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "avf_create");
    cJSON_AddStringToObject(o, "_crc", "daab8ae2");
    cJSON_AddNumberToObject(o, "pci_addr", a->pci_addr);
    cJSON_AddNumberToObject(o, "enable_elog", a->enable_elog);
    cJSON_AddNumberToObject(o, "rxq_num", a->rxq_num);
    cJSON_AddNumberToObject(o, "rxq_size", a->rxq_size);
    cJSON_AddNumberToObject(o, "txq_size", a->txq_size);
    return o;
}
static inline cJSON *vl_api_avf_create_reply_t_tojson (vl_api_avf_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "avf_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_avf_delete_t_tojson (vl_api_avf_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "avf_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_avf_delete_reply_t_tojson (vl_api_avf_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "avf_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
