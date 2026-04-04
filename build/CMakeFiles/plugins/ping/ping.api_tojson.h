/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#ifndef included_ping_api_tojson_h
#define included_ping_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_want_ping_finished_events_t_tojson (vl_api_want_ping_finished_events_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ping_finished_events");
    cJSON_AddStringToObject(o, "_crc", "e79ee58b");
    cJSON_AddItemToObject(o, "address", vl_api_address_t_tojson(&a->address));
    cJSON_AddNumberToObject(o, "repeat", a->repeat);
    cJSON_AddNumberToObject(o, "interval", a->interval);
    return o;
}
static inline cJSON *vl_api_want_ping_finished_events_reply_t_tojson (vl_api_want_ping_finished_events_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "want_ping_finished_events_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ping_finished_event_t_tojson (vl_api_ping_finished_event_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ping_finished_event");
    cJSON_AddStringToObject(o, "_crc", "397ccf72");
    cJSON_AddNumberToObject(o, "request_count", a->request_count);
    cJSON_AddNumberToObject(o, "reply_count", a->reply_count);
    return o;
}
#endif
