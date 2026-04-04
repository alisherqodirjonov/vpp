/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_lldp_api_fromjson_h
#define included_lldp_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_port_id_subtype_t_fromjson(void **mp, int *len, cJSON *o, vl_api_port_id_subtype_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "PORT_ID_SUBTYPE_RESERVED") == 0) {*a = 0; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_INTF_ALIAS") == 0) {*a = 1; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_PORT_COMP") == 0) {*a = 2; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_MAC_ADDR") == 0) {*a = 3; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_NET_ADDR") == 0) {*a = 4; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_INTF_NAME") == 0) {*a = 5; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID") == 0) {*a = 6; return 0;}
    if (strcmp(p, "PORT_ID_SUBTYPE_LOCAL") == 0) {*a = 7; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_chassis_id_subtype_t_fromjson(void **mp, int *len, cJSON *o, vl_api_chassis_id_subtype_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_RESERVED") == 0) {*a = 0; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_CHASSIS_COMP") == 0) {*a = 1; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_INTF_ALIAS") == 0) {*a = 2; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_PORT_COMP") == 0) {*a = 3; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_MAC_ADDR") == 0) {*a = 4; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_NET_ADDR") == 0) {*a = 5; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_INTF_NAME") == 0) {*a = 6; return 0;}
    if (strcmp(p, "CHASSIS_ID_SUBTYPE_LOCAL") == 0) {*a = 7; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_lldp_config_t *vl_api_lldp_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lldp_config_t);
    vl_api_lldp_config_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tx_hold");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_hold);

    item = cJSON_GetObjectItem(o, "tx_interval");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tx_interval);

    item = cJSON_GetObjectItem(o, "system_name");
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
static inline vl_api_lldp_config_reply_t *vl_api_lldp_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lldp_config_reply_t);
    vl_api_lldp_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_lldp_t *vl_api_sw_interface_set_lldp_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_lldp_t);
    vl_api_sw_interface_set_lldp_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mgmt_ip4");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->mgmt_ip4) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mgmt_ip6");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->mgmt_ip6) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mgmt_oid");
    if (!item) goto error;
    if (u8string_fromjson2(o, "mgmt_oid", a->mgmt_oid) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "port_desc");
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
static inline vl_api_sw_interface_set_lldp_reply_t *vl_api_sw_interface_set_lldp_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_lldp_reply_t);
    vl_api_sw_interface_set_lldp_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lldp_dump_t *vl_api_lldp_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lldp_dump_t);
    vl_api_lldp_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lldp_dump_reply_t *vl_api_lldp_dump_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lldp_dump_reply_t);
    vl_api_lldp_dump_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_lldp_details_t *vl_api_lldp_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_lldp_details_t);
    vl_api_lldp_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "last_heard");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->last_heard);

    item = cJSON_GetObjectItem(o, "last_sent");
    if (!item) goto error;
    vl_api_f64_fromjson(item, &a->last_sent);

    item = cJSON_GetObjectItem(o, "chassis_id");
    if (!item) goto error;
    if (u8string_fromjson2(o, "chassis_id", a->chassis_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "chassis_id_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->chassis_id_len);

    item = cJSON_GetObjectItem(o, "port_id");
    if (!item) goto error;
    if (u8string_fromjson2(o, "port_id", a->port_id) < 0) goto error;

    item = cJSON_GetObjectItem(o, "port_id_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->port_id_len);

    item = cJSON_GetObjectItem(o, "ttl");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ttl);

    item = cJSON_GetObjectItem(o, "port_id_subtype");
    if (!item) goto error;
    if (vl_api_port_id_subtype_t_fromjson((void **)&a, &l, item, &a->port_id_subtype) < 0) goto error;

    item = cJSON_GetObjectItem(o, "chassis_id_subtype");
    if (!item) goto error;
    if (vl_api_chassis_id_subtype_t_fromjson((void **)&a, &l, item, &a->chassis_id_subtype) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
