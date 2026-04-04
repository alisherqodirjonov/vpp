/* Imported API files */
#ifndef included_pci_types_api_fromjson_h
#define included_pci_types_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_pci_address_t_fromjson (void **mp, int *len, cJSON *o, vl_api_pci_address_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "domain");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->domain);

    item = cJSON_GetObjectItem(o, "bus");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bus);

    item = cJSON_GetObjectItem(o, "slot");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->slot);

    item = cJSON_GetObjectItem(o, "function");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->function);

    return 0;

  error:
    return -1;
}
#endif
