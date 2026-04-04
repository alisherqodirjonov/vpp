/* Imported API files */
#include <vnet/interface_types.api_fromjson.h>
#include <vnet/ip/ip_types.api_fromjson.h>
#ifndef included_bfd_api_fromjson_h
#define included_bfd_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_bfd_state_t_fromjson(void **mp, int *len, cJSON *o, vl_api_bfd_state_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "BFD_STATE_API_ADMIN_DOWN") == 0) {*a = 0; return 0;}
    if (strcmp(p, "BFD_STATE_API_DOWN") == 0) {*a = 1; return 0;}
    if (strcmp(p, "BFD_STATE_API_INIT") == 0) {*a = 2; return 0;}
    if (strcmp(p, "BFD_STATE_API_UP") == 0) {*a = 3; return 0;}
    *a = 0;
    return -1;
}
static inline vl_api_bfd_udp_set_echo_source_t *vl_api_bfd_udp_set_echo_source_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_set_echo_source_t);
    vl_api_bfd_udp_set_echo_source_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_set_echo_source_reply_t *vl_api_bfd_udp_set_echo_source_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_set_echo_source_reply_t);
    vl_api_bfd_udp_set_echo_source_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_del_echo_source_t *vl_api_bfd_udp_del_echo_source_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_del_echo_source_t);
    vl_api_bfd_udp_del_echo_source_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bfd_udp_del_echo_source_reply_t *vl_api_bfd_udp_del_echo_source_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_del_echo_source_reply_t);
    vl_api_bfd_udp_del_echo_source_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_get_echo_source_t *vl_api_bfd_udp_get_echo_source_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_get_echo_source_t);
    vl_api_bfd_udp_get_echo_source_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bfd_udp_get_echo_source_reply_t *vl_api_bfd_udp_get_echo_source_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_get_echo_source_reply_t);
    vl_api_bfd_udp_get_echo_source_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_set");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_set);

    item = cJSON_GetObjectItem(o, "have_usable_ip4");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->have_usable_ip4);

    item = cJSON_GetObjectItem(o, "ip4_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip4_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "have_usable_ip6");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->have_usable_ip6);

    item = cJSON_GetObjectItem(o, "ip6_addr");
    if (!item) goto error;
    if (vl_api_ip6_address_t_fromjson((void **)&a, &l, item, &a->ip6_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_add_t *vl_api_bfd_udp_add_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_add_t);
    vl_api_bfd_udp_add_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "desired_min_tx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->desired_min_tx);

    item = cJSON_GetObjectItem(o, "required_min_rx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->required_min_rx);

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "detect_mult");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->detect_mult);

    item = cJSON_GetObjectItem(o, "is_authenticated");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_authenticated);

    item = cJSON_GetObjectItem(o, "bfd_key_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bfd_key_id);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_add_reply_t *vl_api_bfd_udp_add_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_add_reply_t);
    vl_api_bfd_udp_add_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_upd_t *vl_api_bfd_udp_upd_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_upd_t);
    vl_api_bfd_udp_upd_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "desired_min_tx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->desired_min_tx);

    item = cJSON_GetObjectItem(o, "required_min_rx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->required_min_rx);

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "detect_mult");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->detect_mult);

    item = cJSON_GetObjectItem(o, "is_authenticated");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_authenticated);

    item = cJSON_GetObjectItem(o, "bfd_key_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bfd_key_id);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_upd_reply_t *vl_api_bfd_udp_upd_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_upd_reply_t);
    vl_api_bfd_udp_upd_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "stats_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->stats_index);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_mod_t *vl_api_bfd_udp_mod_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_mod_t);
    vl_api_bfd_udp_mod_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "desired_min_tx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->desired_min_tx);

    item = cJSON_GetObjectItem(o, "required_min_rx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->required_min_rx);

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "detect_mult");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->detect_mult);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_mod_reply_t *vl_api_bfd_udp_mod_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_mod_reply_t);
    vl_api_bfd_udp_mod_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_del_t *vl_api_bfd_udp_del_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_del_t);
    vl_api_bfd_udp_del_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_del_reply_t *vl_api_bfd_udp_del_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_del_reply_t);
    vl_api_bfd_udp_del_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_session_dump_t *vl_api_bfd_udp_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_session_dump_t);
    vl_api_bfd_udp_session_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bfd_udp_session_details_t *vl_api_bfd_udp_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_session_details_t);
    vl_api_bfd_udp_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_bfd_state_t_fromjson((void **)&a, &l, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_authenticated");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_authenticated);

    item = cJSON_GetObjectItem(o, "bfd_key_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bfd_key_id);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    item = cJSON_GetObjectItem(o, "required_min_rx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->required_min_rx);

    item = cJSON_GetObjectItem(o, "desired_min_tx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->desired_min_tx);

    item = cJSON_GetObjectItem(o, "detect_mult");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->detect_mult);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_session_set_flags_t *vl_api_bfd_udp_session_set_flags_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_session_set_flags_t);
    vl_api_bfd_udp_session_set_flags_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_if_status_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_session_set_flags_reply_t *vl_api_bfd_udp_session_set_flags_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_session_set_flags_reply_t);
    vl_api_bfd_udp_session_set_flags_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_want_bfd_events_t *vl_api_want_bfd_events_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_bfd_events_t);
    vl_api_want_bfd_events_t *a = cJSON_malloc(l);

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
static inline vl_api_want_bfd_events_reply_t *vl_api_want_bfd_events_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_want_bfd_events_reply_t);
    vl_api_want_bfd_events_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_session_event_t *vl_api_bfd_udp_session_event_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_session_event_t);
    vl_api_bfd_udp_session_event_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pid");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->pid);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "state");
    if (!item) goto error;
    if (vl_api_bfd_state_t_fromjson((void **)&a, &l, item, &a->state) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_authenticated");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_authenticated);

    item = cJSON_GetObjectItem(o, "bfd_key_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bfd_key_id);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    item = cJSON_GetObjectItem(o, "required_min_rx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->required_min_rx);

    item = cJSON_GetObjectItem(o, "desired_min_tx");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->desired_min_tx);

    item = cJSON_GetObjectItem(o, "detect_mult");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->detect_mult);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_auth_set_key_t *vl_api_bfd_auth_set_key_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_auth_set_key_t);
    vl_api_bfd_auth_set_key_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    item = cJSON_GetObjectItem(o, "key_len");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->key_len);

    item = cJSON_GetObjectItem(o, "auth_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->auth_type);

    item = cJSON_GetObjectItem(o, "key");
    if (!item) goto error;
    if (u8string_fromjson2(o, "key", a->key) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_auth_set_key_reply_t *vl_api_bfd_auth_set_key_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_auth_set_key_reply_t);
    vl_api_bfd_auth_set_key_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_auth_del_key_t *vl_api_bfd_auth_del_key_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_auth_del_key_t);
    vl_api_bfd_auth_del_key_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_auth_del_key_reply_t *vl_api_bfd_auth_del_key_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_auth_del_key_reply_t);
    vl_api_bfd_auth_del_key_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_auth_keys_dump_t *vl_api_bfd_auth_keys_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_auth_keys_dump_t);
    vl_api_bfd_auth_keys_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bfd_auth_keys_details_t *vl_api_bfd_auth_keys_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_auth_keys_details_t);
    vl_api_bfd_auth_keys_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    item = cJSON_GetObjectItem(o, "use_count");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->use_count);

    item = cJSON_GetObjectItem(o, "auth_type");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->auth_type);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_auth_activate_t *vl_api_bfd_udp_auth_activate_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_auth_activate_t);
    vl_api_bfd_udp_auth_activate_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_delayed");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_delayed);

    item = cJSON_GetObjectItem(o, "bfd_key_id");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->bfd_key_id);

    item = cJSON_GetObjectItem(o, "conf_key_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->conf_key_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_auth_activate_reply_t *vl_api_bfd_udp_auth_activate_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_auth_activate_reply_t);
    vl_api_bfd_udp_auth_activate_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_auth_deactivate_t *vl_api_bfd_udp_auth_deactivate_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_auth_deactivate_t);
    vl_api_bfd_udp_auth_deactivate_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->local_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "peer_addr");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->peer_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "is_delayed");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_delayed);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_auth_deactivate_reply_t *vl_api_bfd_udp_auth_deactivate_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_auth_deactivate_reply_t);
    vl_api_bfd_udp_auth_deactivate_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_enable_multihop_t *vl_api_bfd_udp_enable_multihop_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_enable_multihop_t);
    vl_api_bfd_udp_enable_multihop_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bfd_udp_enable_multihop_reply_t *vl_api_bfd_udp_enable_multihop_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_enable_multihop_reply_t);
    vl_api_bfd_udp_enable_multihop_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_set_tos_t *vl_api_bfd_udp_set_tos_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_set_tos_t);
    vl_api_bfd_udp_set_tos_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "tos");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tos);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_set_tos_reply_t *vl_api_bfd_udp_set_tos_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_set_tos_reply_t);
    vl_api_bfd_udp_set_tos_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_bfd_udp_get_tos_t *vl_api_bfd_udp_get_tos_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_get_tos_t);
    vl_api_bfd_udp_get_tos_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_bfd_udp_get_tos_reply_t *vl_api_bfd_udp_get_tos_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_bfd_udp_get_tos_reply_t);
    vl_api_bfd_udp_get_tos_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "tos");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->tos);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
