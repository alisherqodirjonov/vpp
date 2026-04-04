/* Imported API files */
#ifndef included_pci_types_api_tojson_h
#define included_pci_types_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_pci_address_t_tojson (vl_api_pci_address_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "domain", a->domain);
    cJSON_AddNumberToObject(o, "bus", a->bus);
    cJSON_AddNumberToObject(o, "slot", a->slot);
    cJSON_AddNumberToObject(o, "function", a->function);
    return o;
}
#endif
