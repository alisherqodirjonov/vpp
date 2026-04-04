/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ethernet/ethernet_types.api_tojson.h>
#ifndef included_memif_api_tojson_h
#define included_memif_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_memif_role_t_tojson (vl_api_memif_role_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("MEMIF_ROLE_API_MASTER");
    case 1:
        return cJSON_CreateString("MEMIF_ROLE_API_SLAVE");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_memif_mode_t_tojson (vl_api_memif_mode_t a) {
    switch(a) {
    case 0:
        return cJSON_CreateString("MEMIF_MODE_API_ETHERNET");
    case 1:
        return cJSON_CreateString("MEMIF_MODE_API_IP");
    case 2:
        return cJSON_CreateString("MEMIF_MODE_API_PUNT_INJECT");
    default: return cJSON_CreateString("Invalid ENUM");
    }
    return 0;
}
static inline cJSON *vl_api_memif_socket_filename_add_del_t_tojson (vl_api_memif_socket_filename_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_socket_filename_add_del");
    cJSON_AddStringToObject(o, "_crc", "a2ce1a10");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    cJSON_AddStringToObject(o, "socket_filename", (char *)a->socket_filename);
    return o;
}
static inline cJSON *vl_api_memif_socket_filename_add_del_reply_t_tojson (vl_api_memif_socket_filename_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_socket_filename_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_memif_socket_filename_add_del_v2_t_tojson (vl_api_memif_socket_filename_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_socket_filename_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "34223bdf");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    vl_api_string_cJSON_AddToObject(o, "socket_filename", &a->socket_filename);
    return o;
}
static inline cJSON *vl_api_memif_socket_filename_add_del_v2_reply_t_tojson (vl_api_memif_socket_filename_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_socket_filename_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "9f29bdb9");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    return o;
}
static inline cJSON *vl_api_memif_create_t_tojson (vl_api_memif_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_create");
    cJSON_AddStringToObject(o, "_crc", "b1b25061");
    cJSON_AddItemToObject(o, "role", vl_api_memif_role_t_tojson(a->role));
    cJSON_AddItemToObject(o, "mode", vl_api_memif_mode_t_tojson(a->mode));
    cJSON_AddNumberToObject(o, "rx_queues", a->rx_queues);
    cJSON_AddNumberToObject(o, "tx_queues", a->tx_queues);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    cJSON_AddNumberToObject(o, "ring_size", a->ring_size);
    cJSON_AddNumberToObject(o, "buffer_size", a->buffer_size);
    cJSON_AddBoolToObject(o, "no_zero_copy", a->no_zero_copy);
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddStringToObject(o, "secret", (char *)a->secret);
    return o;
}
static inline cJSON *vl_api_memif_create_reply_t_tojson (vl_api_memif_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_memif_create_v2_t_tojson (vl_api_memif_create_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_create_v2");
    cJSON_AddStringToObject(o, "_crc", "8c7de5f7");
    cJSON_AddItemToObject(o, "role", vl_api_memif_role_t_tojson(a->role));
    cJSON_AddItemToObject(o, "mode", vl_api_memif_mode_t_tojson(a->mode));
    cJSON_AddNumberToObject(o, "rx_queues", a->rx_queues);
    cJSON_AddNumberToObject(o, "tx_queues", a->tx_queues);
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    cJSON_AddNumberToObject(o, "ring_size", a->ring_size);
    cJSON_AddNumberToObject(o, "buffer_size", a->buffer_size);
    cJSON_AddBoolToObject(o, "no_zero_copy", a->no_zero_copy);
    cJSON_AddBoolToObject(o, "use_dma", a->use_dma);
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddStringToObject(o, "secret", (char *)a->secret);
    return o;
}
static inline cJSON *vl_api_memif_create_v2_reply_t_tojson (vl_api_memif_create_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_create_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_memif_delete_t_tojson (vl_api_memif_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_memif_delete_reply_t_tojson (vl_api_memif_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_memif_socket_filename_details_t_tojson (vl_api_memif_socket_filename_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_socket_filename_details");
    cJSON_AddStringToObject(o, "_crc", "7ff326f7");
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    cJSON_AddStringToObject(o, "socket_filename", (char *)a->socket_filename);
    return o;
}
static inline cJSON *vl_api_memif_socket_filename_dump_t_tojson (vl_api_memif_socket_filename_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_socket_filename_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_memif_details_t_tojson (vl_api_memif_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_details");
    cJSON_AddStringToObject(o, "_crc", "da34feb9");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "hw_addr", vl_api_mac_address_t_tojson(&a->hw_addr));
    cJSON_AddNumberToObject(o, "id", a->id);
    cJSON_AddItemToObject(o, "role", vl_api_memif_role_t_tojson(a->role));
    cJSON_AddItemToObject(o, "mode", vl_api_memif_mode_t_tojson(a->mode));
    cJSON_AddBoolToObject(o, "zero_copy", a->zero_copy);
    cJSON_AddNumberToObject(o, "socket_id", a->socket_id);
    cJSON_AddNumberToObject(o, "ring_size", a->ring_size);
    cJSON_AddNumberToObject(o, "buffer_size", a->buffer_size);
    cJSON_AddItemToObject(o, "flags", vl_api_if_status_flags_t_tojson(a->flags));
    cJSON_AddStringToObject(o, "if_name", (char *)a->if_name);
    return o;
}
static inline cJSON *vl_api_memif_dump_t_tojson (vl_api_memif_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "memif_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
#endif
