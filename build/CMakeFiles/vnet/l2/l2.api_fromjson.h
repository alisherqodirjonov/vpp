/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/ethernet/ethernet_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_l2_api_fromjson_h
#define included_l2_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_mac_event_action_t_fromjson(void **mp, int *len, cJSON *o, vl_api_mac_event_action_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "MAC_EVENT_ACTION_API_ADD") == 0) {*a = 0; return 0;}
    if (strcmp(p, "MAC_EVENT_ACTION_API_DELETE") == 0) {*a = 1; return 0;}
    if (strcmp(p, "MAC_EVENT_ACTION_API_MOVE") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_mac_entry_t_fromjson (void **mp, int *len, cJSON *o, vl_api_mac_entry_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mac_addr");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "action");
    if (!item) goto error;
    if (vl_api_mac_event_action_t_fromjson(mp, len, item, &a->action) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->flags);

    return 0;

  error:
    return -1;
}
static inline int vl_api_bridge_domain_sw_if_t_fromjson (void **mp, int *len, cJSON *o, vl_api_bridge_domain_sw_if_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "context");
    if (!item) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson(mp, len, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "shg");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->shg);

    return 0;

  error:
    return -1;
}
static inline int vl_api_bd_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_bd_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "BRIDGE_API_FLAG_NONE") == 0) {*a = 0; return 0;}
    if (strcmp(p, "BRIDGE_API_FLAG_LEARN") == 0) {*a = 1; return 0;}
    if (strcmp(p, "BRIDGE_API_FLAG_FWD") == 0) {*a = 2; return 0;}
    if (strcmp(p, "BRIDGE_API_FLAG_FLOOD") == 0) {*a = 4; return 0;}
    if (strcmp(p, "BRIDGE_API_FLAG_UU_FLOOD") == 0) {*a = 8; return 0;}
    if (strcmp(p, "BRIDGE_API_FLAG_ARP_TERM") == 0) {*a = 16; return 0;}
    if (strcmp(p, "BRIDGE_API_FLAG_ARP_UFWD") == 0) {*a = 32; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_l2_port_type_t_fromjson(void **mp, int *len, cJSON *o, vl_api_l2_port_type_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "L2_API_PORT_TYPE_NORMAL") == 0) {*a = 0; return 0;}
    if (strcmp(p, "L2_API_PORT_TYPE_BVI") == 0) {*a = 1; return 0;}
    if (strcmp(p, "L2_API_PORT_TYPE_UU_FWD") == 0) {*a = 2; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_bd_ip_mac_t_fromjson (void **mp, int *len, cJSON *o, vl_api_bd_ip_mac_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson(mp, len, item, &a->ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson(mp, len, item, &a->mac) < 0) goto error;

    return 0;

  error:
    return -1;
}
static inline vl_api_l2_xconnect_details_t *vl_api_l2_xconnect_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_xconnect_details_t);
    vl_api_l2_xconnect_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->tx_sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_xconnect_dump_t *vl_api_l2_xconnect_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_xconnect_dump_t);
    vl_api_l2_xconnect_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_l2_fib_table_details_t *vl_api_l2_fib_table_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_fib_table_details_t);
    vl_api_l2_fib_table_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "static_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->static_mac);

    item = cJSON_GetObjectItem(o, "filter_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->filter_mac);

    item = cJSON_GetObjectItem(o, "bvi_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bvi_mac);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_fib_table_dump_t *vl_api_l2_fib_table_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_fib_table_dump_t);
    vl_api_l2_fib_table_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_fib_clear_table_t *vl_api_l2_fib_clear_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_fib_clear_table_t);
    vl_api_l2_fib_clear_table_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_l2_fib_clear_table_reply_t *vl_api_l2_fib_clear_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_fib_clear_table_reply_t);
    vl_api_l2_fib_clear_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_flush_all_t *vl_api_l2fib_flush_all_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_flush_all_t);
    vl_api_l2fib_flush_all_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_l2fib_flush_all_reply_t *vl_api_l2fib_flush_all_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_flush_all_reply_t);
    vl_api_l2fib_flush_all_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_flush_bd_t *vl_api_l2fib_flush_bd_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_flush_bd_t);
    vl_api_l2fib_flush_bd_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_flush_bd_reply_t *vl_api_l2fib_flush_bd_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_flush_bd_reply_t);
    vl_api_l2fib_flush_bd_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_flush_int_t *vl_api_l2fib_flush_int_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_flush_int_t);
    vl_api_l2fib_flush_int_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_flush_int_reply_t *vl_api_l2fib_flush_int_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_flush_int_reply_t);
    vl_api_l2fib_flush_int_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_add_del_t *vl_api_l2fib_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_add_del_t);
    vl_api_l2fib_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "static_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->static_mac);

    item = cJSON_GetObjectItem(o, "filter_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->filter_mac);

    item = cJSON_GetObjectItem(o, "bvi_mac");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->bvi_mac);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_add_del_reply_t *vl_api_l2fib_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_add_del_reply_t);
    vl_api_l2fib_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_l2_macs_events_t *vl_api_want_l2_macs_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_l2_macs_events_t);
    vl_api_want_l2_macs_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "learn_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->learn_limit);

    item = cJSON_GetObjectItem(o, "scan_delay");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->scan_delay);

    item = cJSON_GetObjectItem(o, "max_macs_in_event");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->max_macs_in_event);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_l2_macs_events_reply_t *vl_api_want_l2_macs_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_l2_macs_events_reply_t);
    vl_api_want_l2_macs_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_l2_macs_events2_t *vl_api_want_l2_macs_events2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_l2_macs_events2_t);
    vl_api_want_l2_macs_events2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "max_macs_in_event");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->max_macs_in_event);

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_l2_macs_events2_reply_t *vl_api_want_l2_macs_events2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_l2_macs_events2_reply_t);
    vl_api_want_l2_macs_events2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_set_scan_delay_t *vl_api_l2fib_set_scan_delay_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_set_scan_delay_t);
    vl_api_l2fib_set_scan_delay_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "scan_delay");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->scan_delay);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2fib_set_scan_delay_reply_t *vl_api_l2fib_set_scan_delay_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2fib_set_scan_delay_reply_t);
    vl_api_l2fib_set_scan_delay_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_macs_event_t *vl_api_l2_macs_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_macs_event_t);
    vl_api_l2_macs_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "mac");
        int size = cJSON_GetArraySize(array);
        a->n_macs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_mac_entry_t) * size);
        vl_api_mac_entry_t *d = (void *)a + l;
        l += sizeof(vl_api_mac_entry_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_mac_entry_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_flags_t *vl_api_l2_flags_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_flags_t);
    vl_api_l2_flags_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_set);

    item = cJSON_GetObjectItem(o, "feature_bitmap");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->feature_bitmap);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_flags_reply_t *vl_api_l2_flags_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_flags_reply_t);
    vl_api_l2_flags_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "resulting_feature_bitmap");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->resulting_feature_bitmap);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_set_mac_age_t *vl_api_bridge_domain_set_mac_age_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_set_mac_age_t);
    vl_api_bridge_domain_set_mac_age_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "mac_age");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mac_age);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_set_mac_age_reply_t *vl_api_bridge_domain_set_mac_age_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_set_mac_age_reply_t);
    vl_api_bridge_domain_set_mac_age_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_set_default_learn_limit_t *vl_api_bridge_domain_set_default_learn_limit_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_set_default_learn_limit_t);
    vl_api_bridge_domain_set_default_learn_limit_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "learn_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->learn_limit);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_set_default_learn_limit_reply_t *vl_api_bridge_domain_set_default_learn_limit_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_set_default_learn_limit_reply_t);
    vl_api_bridge_domain_set_default_learn_limit_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_set_learn_limit_t *vl_api_bridge_domain_set_learn_limit_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_set_learn_limit_t);
    vl_api_bridge_domain_set_learn_limit_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "learn_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->learn_limit);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_set_learn_limit_reply_t *vl_api_bridge_domain_set_learn_limit_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_set_learn_limit_reply_t);
    vl_api_bridge_domain_set_learn_limit_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_add_del_t *vl_api_bridge_domain_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_add_del_t);
    vl_api_bridge_domain_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "flood");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->flood);

    item = cJSON_GetObjectItem(o, "uu_flood");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->uu_flood);

    item = cJSON_GetObjectItem(o, "forward");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->forward);

    item = cJSON_GetObjectItem(o, "learn");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->learn);

    item = cJSON_GetObjectItem(o, "arp_term");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->arp_term);

    item = cJSON_GetObjectItem(o, "arp_ufwd");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->arp_ufwd);

    item = cJSON_GetObjectItem(o, "mac_age");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mac_age);

    item = cJSON_GetObjectItem(o, "bd_tag");
    if (!item) goto error;
    strncpy_s((char *)a->bd_tag, sizeof(a->bd_tag), cJSON_GetStringValue(item), sizeof(a->bd_tag) - 1);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_add_del_reply_t *vl_api_bridge_domain_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_add_del_reply_t);
    vl_api_bridge_domain_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_add_del_v2_t *vl_api_bridge_domain_add_del_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_add_del_v2_t);
    vl_api_bridge_domain_add_del_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "flood");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->flood);

    item = cJSON_GetObjectItem(o, "uu_flood");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->uu_flood);

    item = cJSON_GetObjectItem(o, "forward");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->forward);

    item = cJSON_GetObjectItem(o, "learn");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->learn);

    item = cJSON_GetObjectItem(o, "arp_term");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->arp_term);

    item = cJSON_GetObjectItem(o, "arp_ufwd");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->arp_ufwd);

    item = cJSON_GetObjectItem(o, "mac_age");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mac_age);

    item = cJSON_GetObjectItem(o, "bd_tag");
    if (!item) goto error;
    strncpy_s((char *)a->bd_tag, sizeof(a->bd_tag), cJSON_GetStringValue(item), sizeof(a->bd_tag) - 1);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_add_del_v2_reply_t *vl_api_bridge_domain_add_del_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_add_del_v2_reply_t);
    vl_api_bridge_domain_add_del_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_dump_t *vl_api_bridge_domain_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_dump_t);
    vl_api_bridge_domain_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_domain_details_t *vl_api_bridge_domain_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_domain_details_t);
    vl_api_bridge_domain_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "flood");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->flood);

    item = cJSON_GetObjectItem(o, "uu_flood");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->uu_flood);

    item = cJSON_GetObjectItem(o, "forward");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->forward);

    item = cJSON_GetObjectItem(o, "learn");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->learn);

    item = cJSON_GetObjectItem(o, "arp_term");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->arp_term);

    item = cJSON_GetObjectItem(o, "arp_ufwd");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->arp_ufwd);

    item = cJSON_GetObjectItem(o, "mac_age");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->mac_age);

    item = cJSON_GetObjectItem(o, "bd_tag");
    if (!item) goto error;
    strncpy_s((char *)a->bd_tag, sizeof(a->bd_tag), cJSON_GetStringValue(item), sizeof(a->bd_tag) - 1);

    item = cJSON_GetObjectItem(o, "bvi_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->bvi_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "uu_fwd_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->uu_fwd_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_details");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "sw_if_details");
        int size = cJSON_GetArraySize(array);
        a->n_sw_ifs = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_bridge_domain_sw_if_t) * size);
        vl_api_bridge_domain_sw_if_t *d = (void *)a + l;
        l += sizeof(vl_api_bridge_domain_sw_if_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_bridge_domain_sw_if_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_flags_t *vl_api_bridge_flags_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_flags_t);
    vl_api_bridge_flags_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "is_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_set);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_bd_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bridge_flags_reply_t *vl_api_bridge_flags_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bridge_flags_reply_t);
    vl_api_bridge_flags_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "resulting_feature_bitmap");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->resulting_feature_bitmap);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_interface_vlan_tag_rewrite_t *vl_api_l2_interface_vlan_tag_rewrite_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_interface_vlan_tag_rewrite_t);
    vl_api_l2_interface_vlan_tag_rewrite_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vtr_op");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vtr_op);

    item = cJSON_GetObjectItem(o, "push_dot1q");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->push_dot1q);

    item = cJSON_GetObjectItem(o, "tag1");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tag1);

    item = cJSON_GetObjectItem(o, "tag2");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tag2);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_interface_vlan_tag_rewrite_reply_t *vl_api_l2_interface_vlan_tag_rewrite_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_interface_vlan_tag_rewrite_reply_t);
    vl_api_l2_interface_vlan_tag_rewrite_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_interface_pbb_tag_rewrite_t *vl_api_l2_interface_pbb_tag_rewrite_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_interface_pbb_tag_rewrite_t);
    vl_api_l2_interface_pbb_tag_rewrite_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vtr_op");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vtr_op);

    item = cJSON_GetObjectItem(o, "outer_tag");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->outer_tag);

    item = cJSON_GetObjectItem(o, "b_dmac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->b_dmac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "b_smac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->b_smac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "b_vlanid");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->b_vlanid);

    item = cJSON_GetObjectItem(o, "i_sid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->i_sid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_interface_pbb_tag_rewrite_reply_t *vl_api_l2_interface_pbb_tag_rewrite_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_interface_pbb_tag_rewrite_reply_t);
    vl_api_l2_interface_pbb_tag_rewrite_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_patch_add_del_t *vl_api_l2_patch_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_patch_add_del_t);
    vl_api_l2_patch_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->tx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_patch_add_del_reply_t *vl_api_l2_patch_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_patch_add_del_reply_t);
    vl_api_l2_patch_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_l2_xconnect_t *vl_api_sw_interface_set_l2_xconnect_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_l2_xconnect_t);
    vl_api_sw_interface_set_l2_xconnect_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "tx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->tx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_l2_xconnect_reply_t *vl_api_sw_interface_set_l2_xconnect_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_l2_xconnect_reply_t);
    vl_api_sw_interface_set_l2_xconnect_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_l2_bridge_t *vl_api_sw_interface_set_l2_bridge_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_l2_bridge_t);
    vl_api_sw_interface_set_l2_bridge_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "rx_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->rx_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    item = cJSON_GetObjectItem(o, "port_type");
    if (!item) goto error;
    if (vl_api_l2_port_type_t_fromjson((void **)&a, &l, item, &a->port_type) < 0) goto error;

    item = cJSON_GetObjectItem(o, "shg");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->shg);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_l2_bridge_reply_t *vl_api_sw_interface_set_l2_bridge_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_l2_bridge_reply_t);
    vl_api_sw_interface_set_l2_bridge_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bd_ip_mac_add_del_t *vl_api_bd_ip_mac_add_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bd_ip_mac_add_del_t);
    vl_api_bd_ip_mac_add_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_bd_ip_mac_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bd_ip_mac_add_del_reply_t *vl_api_bd_ip_mac_add_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bd_ip_mac_add_del_reply_t);
    vl_api_bd_ip_mac_add_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bd_ip_mac_flush_t *vl_api_bd_ip_mac_flush_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bd_ip_mac_flush_t);
    vl_api_bd_ip_mac_flush_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bd_ip_mac_flush_reply_t *vl_api_bd_ip_mac_flush_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bd_ip_mac_flush_reply_t);
    vl_api_bd_ip_mac_flush_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bd_ip_mac_details_t *vl_api_bd_ip_mac_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bd_ip_mac_details_t);
    vl_api_bd_ip_mac_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "entry");
    if (!item) goto error;
    if (vl_api_bd_ip_mac_t_fromjson((void **)&a, &l, item, &a->entry) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bd_ip_mac_dump_t *vl_api_bd_ip_mac_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bd_ip_mac_dump_t);
    vl_api_bd_ip_mac_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "bd_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->bd_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_interface_efp_filter_t *vl_api_l2_interface_efp_filter_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_interface_efp_filter_t);
    vl_api_l2_interface_efp_filter_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable_disable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable_disable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_interface_efp_filter_reply_t *vl_api_l2_interface_efp_filter_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_interface_efp_filter_reply_t);
    vl_api_l2_interface_efp_filter_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_vpath_t *vl_api_sw_interface_set_vpath_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_vpath_t);
    vl_api_sw_interface_set_vpath_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_sw_interface_set_vpath_reply_t *vl_api_sw_interface_set_vpath_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_sw_interface_set_vpath_reply_t);
    vl_api_sw_interface_set_vpath_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bvi_create_t *vl_api_bvi_create_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bvi_create_t);
    vl_api_bvi_create_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac) < 0) goto error;

    item = cJSON_GetObjectItem(o, "user_instance");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_instance);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bvi_create_reply_t *vl_api_bvi_create_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bvi_create_reply_t);
    vl_api_bvi_create_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bvi_delete_t *vl_api_bvi_delete_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bvi_delete_t);
    vl_api_bvi_delete_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bvi_delete_reply_t *vl_api_bvi_delete_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bvi_delete_reply_t);
    vl_api_bvi_delete_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_l2_arp_term_events_t *vl_api_want_l2_arp_term_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_l2_arp_term_events_t);
    vl_api_want_l2_arp_term_events_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_l2_arp_term_events_reply_t *vl_api_want_l2_arp_term_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_l2_arp_term_events_reply_t);
    vl_api_want_l2_arp_term_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_l2_arp_term_event_t *vl_api_l2_arp_term_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_l2_arp_term_event_t);
    vl_api_l2_arp_term_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "ip");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->ip) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "mac");
    if (!item) goto error;
    if (vl_api_mac_address_t_fromjson((void **)&a, &l, item, &a->mac) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
