/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#include <nat/lib/nat_types.api_fromjson.h>
#ifndef included_nat44_ed_api_fromjson_h
#define included_nat44_ed_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_nat44_config_flags_t_fromjson(void **mp, int *len, cJSON *o, vl_api_nat44_config_flags_t *a) {
    char *p = cJSON_GetStringValue(o);
    if (strcmp(p, "NAT44_IS_ENDPOINT_INDEPENDENT") == 0) {*a = 0; return 0;}
    if (strcmp(p, "NAT44_IS_ENDPOINT_DEPENDENT") == 0) {*a = 1; return 0;}
    if (strcmp(p, "NAT44_IS_STATIC_MAPPING_ONLY") == 0) {*a = 2; return 0;}
    if (strcmp(p, "NAT44_IS_CONNECTION_TRACKING") == 0) {*a = 4; return 0;}
    if (strcmp(p, "NAT44_IS_OUT2IN_DPO") == 0) {*a = 8; return 0;}
    *a = 0;
    return -1;
}
static inline int vl_api_nat44_lb_addr_port_t_fromjson (void **mp, int *len, cJSON *o, vl_api_nat44_lb_addr_port_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson(mp, len, item, &a->addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "probability");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->probability);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    return 0;

  error:
    return -1;
}
static inline vl_api_nat44_ed_plugin_enable_disable_t *vl_api_nat44_ed_plugin_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_plugin_enable_disable_t);
    vl_api_nat44_ed_plugin_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "inside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->inside_vrf);

    item = cJSON_GetObjectItem(o, "outside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outside_vrf);

    item = cJSON_GetObjectItem(o, "sessions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sessions);

    item = cJSON_GetObjectItem(o, "session_memory");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->session_memory);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat44_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_plugin_enable_disable_reply_t *vl_api_nat44_ed_plugin_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_plugin_enable_disable_reply_t);
    vl_api_nat44_ed_plugin_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_forwarding_enable_disable_t *vl_api_nat44_forwarding_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_forwarding_enable_disable_t);
    vl_api_nat44_forwarding_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_forwarding_enable_disable_reply_t *vl_api_nat44_forwarding_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_forwarding_enable_disable_reply_t);
    vl_api_nat44_forwarding_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_ipfix_enable_disable_t *vl_api_nat_ipfix_enable_disable_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_ipfix_enable_disable_t);
    vl_api_nat_ipfix_enable_disable_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "domain_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->domain_id);

    item = cJSON_GetObjectItem(o, "src_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->src_port);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_ipfix_enable_disable_reply_t *vl_api_nat_ipfix_enable_disable_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_ipfix_enable_disable_reply_t);
    vl_api_nat_ipfix_enable_disable_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_set_timeouts_t *vl_api_nat_set_timeouts_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_set_timeouts_t);
    vl_api_nat_set_timeouts_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "udp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->udp);

    item = cJSON_GetObjectItem(o, "tcp_established");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_established);

    item = cJSON_GetObjectItem(o, "tcp_transitory");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->tcp_transitory);

    item = cJSON_GetObjectItem(o, "icmp");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->icmp);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_set_timeouts_reply_t *vl_api_nat_set_timeouts_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_set_timeouts_reply_t);
    vl_api_nat_set_timeouts_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_set_session_limit_t *vl_api_nat44_set_session_limit_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_set_session_limit_t);
    vl_api_nat44_set_session_limit_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "session_limit");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->session_limit);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_set_session_limit_reply_t *vl_api_nat44_set_session_limit_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_set_session_limit_reply_t);
    vl_api_nat44_set_session_limit_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_show_running_config_t *vl_api_nat44_show_running_config_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_show_running_config_t);
    vl_api_nat44_show_running_config_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_show_running_config_reply_t *vl_api_nat44_show_running_config_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_show_running_config_reply_t);
    vl_api_nat44_show_running_config_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "inside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->inside_vrf);

    item = cJSON_GetObjectItem(o, "outside_vrf");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->outside_vrf);

    item = cJSON_GetObjectItem(o, "users");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->users);

    item = cJSON_GetObjectItem(o, "sessions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->sessions);

    item = cJSON_GetObjectItem(o, "user_sessions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_sessions);

    item = cJSON_GetObjectItem(o, "user_buckets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->user_buckets);

    item = cJSON_GetObjectItem(o, "translation_buckets");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->translation_buckets);

    item = cJSON_GetObjectItem(o, "forwarding_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->forwarding_enabled);

    item = cJSON_GetObjectItem(o, "ipfix_logging_enabled");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->ipfix_logging_enabled);

    item = cJSON_GetObjectItem(o, "timeouts");
    if (!item) goto error;
    if (vl_api_nat_timeouts_t_fromjson((void **)&a, &l, item, &a->timeouts) < 0) goto error;

    item = cJSON_GetObjectItem(o, "log_level");
    if (!item) goto error;
    if (vl_api_nat_log_level_t_fromjson((void **)&a, &l, item, &a->log_level) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat44_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_set_workers_t *vl_api_nat_set_workers_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_set_workers_t);
    vl_api_nat_set_workers_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "worker_mask");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->worker_mask);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_set_workers_reply_t *vl_api_nat_set_workers_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_set_workers_reply_t);
    vl_api_nat_set_workers_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_worker_dump_t *vl_api_nat_worker_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_worker_dump_t);
    vl_api_nat_worker_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat_worker_details_t *vl_api_nat_worker_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_worker_details_t);
    vl_api_nat_worker_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "worker_index");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->worker_index);

    item = cJSON_GetObjectItem(o, "lcore_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->lcore_id);

    item = cJSON_GetObjectItem(o, "name");
    if (!item) goto error;
    strncpy_s((char *)a->name, sizeof(a->name), cJSON_GetStringValue(item), sizeof(a->name) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_add_del_vrf_table_t *vl_api_nat44_ed_add_del_vrf_table_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_add_del_vrf_table_t);
    vl_api_nat44_ed_add_del_vrf_table_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_vrf_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_add_del_vrf_table_reply_t *vl_api_nat44_ed_add_del_vrf_table_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_add_del_vrf_table_reply_t);
    vl_api_nat44_ed_add_del_vrf_table_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_add_del_vrf_route_t *vl_api_nat44_ed_add_del_vrf_route_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_add_del_vrf_route_t);
    vl_api_nat44_ed_add_del_vrf_route_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_vrf_id);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_add_del_vrf_route_reply_t *vl_api_nat44_ed_add_del_vrf_route_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_add_del_vrf_route_reply_t);
    vl_api_nat44_ed_add_del_vrf_route_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_vrf_tables_dump_t *vl_api_nat44_ed_vrf_tables_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_vrf_tables_dump_t);
    vl_api_nat44_ed_vrf_tables_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_ed_vrf_tables_details_t *vl_api_nat44_ed_vrf_tables_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_vrf_tables_details_t);
    vl_api_nat44_ed_vrf_tables_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_vrf_id);

    item = cJSON_GetObjectItem(o, "vrf_ids");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "vrf_ids");
        int size = cJSON_GetArraySize(array);
        a->n_vrf_ids = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_vrf_tables_v2_dump_t *vl_api_nat44_ed_vrf_tables_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_vrf_tables_v2_dump_t);
    vl_api_nat44_ed_vrf_tables_v2_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_ed_vrf_tables_v2_details_t *vl_api_nat44_ed_vrf_tables_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_vrf_tables_v2_details_t);
    vl_api_nat44_ed_vrf_tables_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "table_vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->table_vrf_id);

    item = cJSON_GetObjectItem(o, "vrf_ids");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "vrf_ids");
        int size = cJSON_GetArraySize(array);
        a->n_vrf_ids = size;
        a = cJSON_realloc(a, l + sizeof(u32) * size);
        u32 *d = (void *)a + l;
        l += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_set_mss_clamping_t *vl_api_nat_set_mss_clamping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_set_mss_clamping_t);
    vl_api_nat_set_mss_clamping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "mss_value");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->mss_value);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_set_mss_clamping_reply_t *vl_api_nat_set_mss_clamping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_set_mss_clamping_reply_t);
    vl_api_nat_set_mss_clamping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat_get_mss_clamping_t *vl_api_nat_get_mss_clamping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_get_mss_clamping_t);
    vl_api_nat_get_mss_clamping_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat_get_mss_clamping_reply_t *vl_api_nat_get_mss_clamping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat_get_mss_clamping_reply_t);
    vl_api_nat_get_mss_clamping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "mss_value");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->mss_value);

    item = cJSON_GetObjectItem(o, "enable");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->enable);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_set_fq_options_t *vl_api_nat44_ed_set_fq_options_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_set_fq_options_t);
    vl_api_nat44_ed_set_fq_options_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "frame_queue_nelts");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->frame_queue_nelts);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_set_fq_options_reply_t *vl_api_nat44_ed_set_fq_options_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_set_fq_options_reply_t);
    vl_api_nat44_ed_set_fq_options_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_show_fq_options_t *vl_api_nat44_ed_show_fq_options_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_show_fq_options_t);
    vl_api_nat44_ed_show_fq_options_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_ed_show_fq_options_reply_t *vl_api_nat44_ed_show_fq_options_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_show_fq_options_reply_t);
    vl_api_nat44_ed_show_fq_options_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    item = cJSON_GetObjectItem(o, "frame_queue_nelts");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->frame_queue_nelts);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_interface_addr_t *vl_api_nat44_add_del_interface_addr_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_interface_addr_t);
    vl_api_nat44_add_del_interface_addr_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_interface_addr_reply_t *vl_api_nat44_add_del_interface_addr_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_interface_addr_reply_t);
    vl_api_nat44_add_del_interface_addr_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_interface_addr_dump_t *vl_api_nat44_interface_addr_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_interface_addr_dump_t);
    vl_api_nat44_interface_addr_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_interface_addr_details_t *vl_api_nat44_interface_addr_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_interface_addr_details_t);
    vl_api_nat44_interface_addr_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_address_range_t *vl_api_nat44_add_del_address_range_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_address_range_t);
    vl_api_nat44_add_del_address_range_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "first_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->first_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "last_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->last_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_address_range_reply_t *vl_api_nat44_add_del_address_range_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_address_range_reply_t);
    vl_api_nat44_add_del_address_range_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_address_dump_t *vl_api_nat44_address_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_address_dump_t);
    vl_api_nat44_address_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_address_details_t *vl_api_nat44_address_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_address_details_t);
    vl_api_nat44_address_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_interface_add_del_feature_t *vl_api_nat44_interface_add_del_feature_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_interface_add_del_feature_t);
    vl_api_nat44_interface_add_del_feature_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_interface_add_del_feature_reply_t *vl_api_nat44_interface_add_del_feature_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_interface_add_del_feature_reply_t);
    vl_api_nat44_interface_add_del_feature_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_interface_dump_t *vl_api_nat44_interface_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_interface_dump_t);
    vl_api_nat44_interface_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_interface_details_t *vl_api_nat44_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_interface_details_t);
    vl_api_nat44_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_add_del_output_interface_t *vl_api_nat44_ed_add_del_output_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_add_del_output_interface_t);
    vl_api_nat44_ed_add_del_output_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_add_del_output_interface_reply_t *vl_api_nat44_ed_add_del_output_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_add_del_output_interface_reply_t);
    vl_api_nat44_ed_add_del_output_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_output_interface_get_t *vl_api_nat44_ed_output_interface_get_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_output_interface_get_t);
    vl_api_nat44_ed_output_interface_get_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "cursor");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->cursor);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_ed_output_interface_get_reply_t *vl_api_nat44_ed_output_interface_get_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_output_interface_get_reply_t);
    vl_api_nat44_ed_output_interface_get_reply_t *a = cJSON_malloc(l);

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
static inline vl_api_nat44_ed_output_interface_details_t *vl_api_nat44_ed_output_interface_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_ed_output_interface_details_t);
    vl_api_nat44_ed_output_interface_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_static_mapping_t *vl_api_nat44_add_del_static_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_static_mapping_t);
    vl_api_nat44_add_del_static_mapping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->local_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->external_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "local_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port);

    item = cJSON_GetObjectItem(o, "external_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->external_port);

    item = cJSON_GetObjectItem(o, "external_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->external_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_static_mapping_reply_t *vl_api_nat44_add_del_static_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_static_mapping_reply_t);
    vl_api_nat44_add_del_static_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_static_mapping_v2_t *vl_api_nat44_add_del_static_mapping_v2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_static_mapping_v2_t);
    vl_api_nat44_add_del_static_mapping_v2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "match_pool");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->match_pool);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "pool_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->pool_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->local_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->external_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "local_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port);

    item = cJSON_GetObjectItem(o, "external_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->external_port);

    item = cJSON_GetObjectItem(o, "external_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->external_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_static_mapping_v2_reply_t *vl_api_nat44_add_del_static_mapping_v2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_static_mapping_v2_reply_t);
    vl_api_nat44_add_del_static_mapping_v2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_static_mapping_dump_t *vl_api_nat44_static_mapping_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_static_mapping_dump_t);
    vl_api_nat44_static_mapping_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_static_mapping_details_t *vl_api_nat44_static_mapping_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_static_mapping_details_t);
    vl_api_nat44_static_mapping_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "local_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->local_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->external_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "local_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->local_port);

    item = cJSON_GetObjectItem(o, "external_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->external_port);

    item = cJSON_GetObjectItem(o, "external_sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->external_sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_identity_mapping_t *vl_api_nat44_add_del_identity_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_identity_mapping_t);
    vl_api_nat44_add_del_identity_mapping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_identity_mapping_reply_t *vl_api_nat44_add_del_identity_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_identity_mapping_reply_t);
    vl_api_nat44_add_del_identity_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_identity_mapping_dump_t *vl_api_nat44_identity_mapping_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_identity_mapping_dump_t);
    vl_api_nat44_identity_mapping_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_identity_mapping_details_t *vl_api_nat44_identity_mapping_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_identity_mapping_details_t);
    vl_api_nat44_identity_mapping_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_lb_static_mapping_t *vl_api_nat44_add_del_lb_static_mapping_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_lb_static_mapping_t);
    vl_api_nat44_add_del_lb_static_mapping_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->external_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->external_port);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "affinity");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->affinity);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "locals");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "locals");
        int size = cJSON_GetArraySize(array);
        a->local_num = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_nat44_lb_addr_port_t) * size);
        vl_api_nat44_lb_addr_port_t *d = (void *)a + l;
        l += sizeof(vl_api_nat44_lb_addr_port_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_nat44_lb_addr_port_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_add_del_lb_static_mapping_reply_t *vl_api_nat44_add_del_lb_static_mapping_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_add_del_lb_static_mapping_reply_t);
    vl_api_nat44_add_del_lb_static_mapping_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_lb_static_mapping_add_del_local_t *vl_api_nat44_lb_static_mapping_add_del_local_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_lb_static_mapping_add_del_local_t);
    vl_api_nat44_lb_static_mapping_add_del_local_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "is_add");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_add);

    item = cJSON_GetObjectItem(o, "external_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->external_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->external_port);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "local");
    if (!item) goto error;
    if (vl_api_nat44_lb_addr_port_t_fromjson((void **)&a, &l, item, &a->local) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_lb_static_mapping_add_del_local_reply_t *vl_api_nat44_lb_static_mapping_add_del_local_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_lb_static_mapping_add_del_local_reply_t);
    vl_api_nat44_lb_static_mapping_add_del_local_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_lb_static_mapping_dump_t *vl_api_nat44_lb_static_mapping_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_lb_static_mapping_dump_t);
    vl_api_nat44_lb_static_mapping_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_lb_static_mapping_details_t *vl_api_nat44_lb_static_mapping_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_lb_static_mapping_details_t);
    vl_api_nat44_lb_static_mapping_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "external_addr");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->external_addr) < 0) goto error;

    item = cJSON_GetObjectItem(o, "external_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->external_port);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "affinity");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->affinity);

    item = cJSON_GetObjectItem(o, "tag");
    if (!item) goto error;
    strncpy_s((char *)a->tag, sizeof(a->tag), cJSON_GetStringValue(item), sizeof(a->tag) - 1);

    item = cJSON_GetObjectItem(o, "locals");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "locals");
        int size = cJSON_GetArraySize(array);
        a->local_num = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_nat44_lb_addr_port_t) * size);
        vl_api_nat44_lb_addr_port_t *d = (void *)a + l;
        l += sizeof(vl_api_nat44_lb_addr_port_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_nat44_lb_addr_port_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_del_session_t *vl_api_nat44_del_session_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_del_session_t);
    vl_api_nat44_del_session_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u8_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->port);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_del_session_reply_t *vl_api_nat44_del_session_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_del_session_reply_t);
    vl_api_nat44_del_session_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_dump_t *vl_api_nat44_user_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_dump_t);
    vl_api_nat44_user_dump_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_nat44_user_details_t *vl_api_nat44_user_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_details_t);
    vl_api_nat44_user_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "nsessions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nsessions);

    item = cJSON_GetObjectItem(o, "nstaticsessions");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->nstaticsessions);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_session_dump_t *vl_api_nat44_user_session_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_session_dump_t);
    vl_api_nat44_user_session_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_session_details_t *vl_api_nat44_user_session_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_session_details_t);
    vl_api_nat44_user_session_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "outside_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->outside_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "outside_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->outside_port);

    item = cJSON_GetObjectItem(o, "inside_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->inside_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "inside_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->inside_port);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "last_heard");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_heard);

    item = cJSON_GetObjectItem(o, "total_bytes");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_bytes);

    item = cJSON_GetObjectItem(o, "total_pkts");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->total_pkts);

    item = cJSON_GetObjectItem(o, "ext_host_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_port);

    item = cJSON_GetObjectItem(o, "ext_host_nat_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_nat_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_nat_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_nat_port);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_session_v2_dump_t *vl_api_nat44_user_session_v2_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_session_v2_dump_t);
    vl_api_nat44_user_session_v2_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_session_v2_details_t *vl_api_nat44_user_session_v2_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_session_v2_details_t);
    vl_api_nat44_user_session_v2_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "outside_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->outside_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "outside_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->outside_port);

    item = cJSON_GetObjectItem(o, "inside_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->inside_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "inside_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->inside_port);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "last_heard");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_heard);

    item = cJSON_GetObjectItem(o, "total_bytes");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_bytes);

    item = cJSON_GetObjectItem(o, "total_pkts");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->total_pkts);

    item = cJSON_GetObjectItem(o, "ext_host_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_port);

    item = cJSON_GetObjectItem(o, "ext_host_nat_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_nat_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_nat_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_nat_port);

    item = cJSON_GetObjectItem(o, "is_timed_out");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_timed_out);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_session_v3_details_t *vl_api_nat44_user_session_v3_details_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_session_v3_details_t);
    vl_api_nat44_user_session_v3_details_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "outside_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->outside_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "outside_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->outside_port);

    item = cJSON_GetObjectItem(o, "inside_ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->inside_ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "inside_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->inside_port);

    item = cJSON_GetObjectItem(o, "protocol");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->protocol);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_nat_config_flags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    item = cJSON_GetObjectItem(o, "last_heard");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->last_heard);

    item = cJSON_GetObjectItem(o, "time_since_last_heard");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->time_since_last_heard);

    item = cJSON_GetObjectItem(o, "total_bytes");
    if (!item) goto error;
    vl_api_u64_fromjson(item, &a->total_bytes);

    item = cJSON_GetObjectItem(o, "total_pkts");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->total_pkts);

    item = cJSON_GetObjectItem(o, "ext_host_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_port);

    item = cJSON_GetObjectItem(o, "ext_host_nat_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ext_host_nat_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "ext_host_nat_port");
    if (!item) goto error;
    vl_api_u16_fromjson(item, &a->ext_host_nat_port);

    item = cJSON_GetObjectItem(o, "is_timed_out");
    if (!item) goto error;
    vl_api_bool_fromjson(item, &a->is_timed_out);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_nat44_user_session_v3_dump_t *vl_api_nat44_user_session_v3_dump_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_nat44_user_session_v3_dump_t);
    vl_api_nat44_user_session_v3_dump_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "ip_address");
    if (!item) goto error;
    if (vl_api_ip4_address_t_fromjson((void **)&a, &l, item, &a->ip_address) < 0) goto error;

    item = cJSON_GetObjectItem(o, "vrf_id");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->vrf_id);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
