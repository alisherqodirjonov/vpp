/* Imported API files */
#include <vnet/ipsec/ipsec_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#include <vnet/tunnel/tunnel_types.api_tojson.h>
#ifndef included_ipsec_api_tojson_h
#define included_ipsec_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_ipsec_tunnel_protect_t_tojson (vl_api_ipsec_tunnel_protect_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "nh", vl_api_address_t_tojson(&a->nh));
    cJSON_AddNumberToObject(o, "sa_out", a->sa_out);
    cJSON_AddNumberToObject(o, "n_sa_in", a->n_sa_in);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "sa_in");
        for (i = 0; i < a->n_sa_in; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->sa_in[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_ipsec_itf_t_tojson (vl_api_ipsec_itf_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "user_instance", a->user_instance);
    cJSON_AddItemToObject(o, "mode", vl_api_tunnel_mode_t_tojson(a->mode));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_add_del_t_tojson (vl_api_ipsec_spd_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_add_del");
    cJSON_AddStringToObject(o, "_crc", "20e89a95");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "spd_id", a->spd_id);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_add_del_reply_t_tojson (vl_api_ipsec_spd_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_interface_add_del_spd_t_tojson (vl_api_ipsec_interface_add_del_spd_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_interface_add_del_spd");
    cJSON_AddStringToObject(o, "_crc", "80f80cbb");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "spd_id", a->spd_id);
    return o;
}
static inline cJSON *vl_api_ipsec_interface_add_del_spd_reply_t_tojson (vl_api_ipsec_interface_add_del_spd_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_interface_add_del_spd_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_entry_add_del_t_tojson (vl_api_ipsec_spd_entry_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_entry_add_del");
    cJSON_AddStringToObject(o, "_crc", "338b7411");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_spd_entry_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_spd_entry_add_del_v2_t_tojson (vl_api_ipsec_spd_entry_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_entry_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "7bfe69fc");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_spd_entry_v2_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_spd_entry_add_del_reply_t_tojson (vl_api_ipsec_spd_entry_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_entry_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_entry_add_del_v2_reply_t_tojson (vl_api_ipsec_spd_entry_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_entry_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_spds_dump_t_tojson (vl_api_ipsec_spds_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spds_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ipsec_spds_details_t_tojson (vl_api_ipsec_spds_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spds_details");
    cJSON_AddStringToObject(o, "_crc", "a04bb254");
    cJSON_AddNumberToObject(o, "spd_id", a->spd_id);
    cJSON_AddNumberToObject(o, "npolicies", a->npolicies);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_dump_t_tojson (vl_api_ipsec_spd_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_dump");
    cJSON_AddStringToObject(o, "_crc", "afefbf7d");
    cJSON_AddNumberToObject(o, "spd_id", a->spd_id);
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_details_t_tojson (vl_api_ipsec_spd_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_details");
    cJSON_AddStringToObject(o, "_crc", "5813d7a2");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_spd_entry_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_del_t_tojson (vl_api_ipsec_sad_entry_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_del");
    cJSON_AddStringToObject(o, "_crc", "ab64b5c6");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_del_v2_t_tojson (vl_api_ipsec_sad_entry_add_del_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_del_v2");
    cJSON_AddStringToObject(o, "_crc", "aca78b27");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v2_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_del_v3_t_tojson (vl_api_ipsec_sad_entry_add_del_v3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_del_v3");
    cJSON_AddStringToObject(o, "_crc", "c77ebd92");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v3_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_t_tojson (vl_api_ipsec_sad_entry_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add");
    cJSON_AddStringToObject(o, "_crc", "50229353");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v3_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_v2_t_tojson (vl_api_ipsec_sad_entry_add_v2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_v2");
    cJSON_AddStringToObject(o, "_crc", "9611297a");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v4_t_tojson(&a->entry));
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_del_t_tojson (vl_api_ipsec_sad_entry_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_del");
    cJSON_AddStringToObject(o, "_crc", "3a91bde5");
    cJSON_AddNumberToObject(o, "id", a->id);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_del_reply_t_tojson (vl_api_ipsec_sad_entry_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_bind_t_tojson (vl_api_ipsec_sad_bind_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_bind");
    cJSON_AddStringToObject(o, "_crc", "0649c0d9");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    cJSON_AddNumberToObject(o, "worker", a->worker);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_bind_reply_t_tojson (vl_api_ipsec_sad_bind_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_bind_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_unbind_t_tojson (vl_api_ipsec_sad_unbind_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_unbind");
    cJSON_AddStringToObject(o, "_crc", "2076c2f4");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_unbind_reply_t_tojson (vl_api_ipsec_sad_unbind_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_unbind_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_update_t_tojson (vl_api_ipsec_sad_entry_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_update");
    cJSON_AddStringToObject(o, "_crc", "1412af86");
    cJSON_AddNumberToObject(o, "sad_id", a->sad_id);
    cJSON_AddBoolToObject(o, "is_tun", a->is_tun);
    cJSON_AddItemToObject(o, "tunnel", vl_api_tunnel_t_tojson(&a->tunnel));
    cJSON_AddNumberToObject(o, "udp_src_port", a->udp_src_port);
    cJSON_AddNumberToObject(o, "udp_dst_port", a->udp_dst_port);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_update_reply_t_tojson (vl_api_ipsec_sad_entry_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_del_reply_t_tojson (vl_api_ipsec_sad_entry_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_del_v2_reply_t_tojson (vl_api_ipsec_sad_entry_add_del_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_del_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_del_v3_reply_t_tojson (vl_api_ipsec_sad_entry_add_del_v3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_del_v3_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_reply_t_tojson (vl_api_ipsec_sad_entry_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sad_entry_add_v2_reply_t_tojson (vl_api_ipsec_sad_entry_add_v2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sad_entry_add_v2_reply");
    cJSON_AddStringToObject(o, "_crc", "9ffac24b");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_tunnel_protect_update_t_tojson (vl_api_ipsec_tunnel_protect_update_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_tunnel_protect_update");
    cJSON_AddStringToObject(o, "_crc", "30d5f133");
    cJSON_AddItemToObject(o, "tunnel", vl_api_ipsec_tunnel_protect_t_tojson(&a->tunnel));
    return o;
}
static inline cJSON *vl_api_ipsec_tunnel_protect_update_reply_t_tojson (vl_api_ipsec_tunnel_protect_update_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_tunnel_protect_update_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_tunnel_protect_del_t_tojson (vl_api_ipsec_tunnel_protect_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_tunnel_protect_del");
    cJSON_AddStringToObject(o, "_crc", "cd239930");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddItemToObject(o, "nh", vl_api_address_t_tojson(&a->nh));
    return o;
}
static inline cJSON *vl_api_ipsec_tunnel_protect_del_reply_t_tojson (vl_api_ipsec_tunnel_protect_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_tunnel_protect_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_tunnel_protect_dump_t_tojson (vl_api_ipsec_tunnel_protect_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_tunnel_protect_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipsec_tunnel_protect_details_t_tojson (vl_api_ipsec_tunnel_protect_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_tunnel_protect_details");
    cJSON_AddStringToObject(o, "_crc", "21663a50");
    cJSON_AddItemToObject(o, "tun", vl_api_ipsec_tunnel_protect_t_tojson(&a->tun));
    return o;
}
static inline cJSON *vl_api_ipsec_spd_interface_dump_t_tojson (vl_api_ipsec_spd_interface_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_interface_dump");
    cJSON_AddStringToObject(o, "_crc", "8971de19");
    cJSON_AddNumberToObject(o, "spd_index", a->spd_index);
    cJSON_AddNumberToObject(o, "spd_index_valid", a->spd_index_valid);
    return o;
}
static inline cJSON *vl_api_ipsec_spd_interface_details_t_tojson (vl_api_ipsec_spd_interface_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_spd_interface_details");
    cJSON_AddStringToObject(o, "_crc", "7a0bcf3e");
    cJSON_AddNumberToObject(o, "spd_index", a->spd_index);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipsec_itf_create_t_tojson (vl_api_ipsec_itf_create_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_itf_create");
    cJSON_AddStringToObject(o, "_crc", "6f50b3bc");
    cJSON_AddItemToObject(o, "itf", vl_api_ipsec_itf_t_tojson(&a->itf));
    return o;
}
static inline cJSON *vl_api_ipsec_itf_create_reply_t_tojson (vl_api_ipsec_itf_create_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_itf_create_reply");
    cJSON_AddStringToObject(o, "_crc", "5383d31f");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipsec_itf_delete_t_tojson (vl_api_ipsec_itf_delete_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_itf_delete");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipsec_itf_delete_reply_t_tojson (vl_api_ipsec_itf_delete_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_itf_delete_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_itf_dump_t_tojson (vl_api_ipsec_itf_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_itf_dump");
    cJSON_AddStringToObject(o, "_crc", "f9e6675e");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_ipsec_itf_details_t_tojson (vl_api_ipsec_itf_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_itf_details");
    cJSON_AddStringToObject(o, "_crc", "548a73b8");
    cJSON_AddItemToObject(o, "itf", vl_api_ipsec_itf_t_tojson(&a->itf));
    return o;
}
static inline cJSON *vl_api_ipsec_sa_dump_t_tojson (vl_api_ipsec_sa_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_dump");
    cJSON_AddStringToObject(o, "_crc", "2076c2f4");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v2_dump_t_tojson (vl_api_ipsec_sa_v2_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v2_dump");
    cJSON_AddStringToObject(o, "_crc", "2076c2f4");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v3_dump_t_tojson (vl_api_ipsec_sa_v3_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v3_dump");
    cJSON_AddStringToObject(o, "_crc", "2076c2f4");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v4_dump_t_tojson (vl_api_ipsec_sa_v4_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v4_dump");
    cJSON_AddStringToObject(o, "_crc", "2076c2f4");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v5_dump_t_tojson (vl_api_ipsec_sa_v5_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v5_dump");
    cJSON_AddStringToObject(o, "_crc", "2076c2f4");
    cJSON_AddNumberToObject(o, "sa_id", a->sa_id);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_details_t_tojson (vl_api_ipsec_sa_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_details");
    cJSON_AddStringToObject(o, "_crc", "345d14a7");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_t_tojson(&a->entry));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "salt", a->salt);
    cJSON_AddNumberToObject(o, "seq_outbound", a->seq_outbound);
    cJSON_AddNumberToObject(o, "last_seq_inbound", a->last_seq_inbound);
    cJSON_AddNumberToObject(o, "replay_window", a->replay_window);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v2_details_t_tojson (vl_api_ipsec_sa_v2_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v2_details");
    cJSON_AddStringToObject(o, "_crc", "e2130051");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v2_t_tojson(&a->entry));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "salt", a->salt);
    cJSON_AddNumberToObject(o, "seq_outbound", a->seq_outbound);
    cJSON_AddNumberToObject(o, "last_seq_inbound", a->last_seq_inbound);
    cJSON_AddNumberToObject(o, "replay_window", a->replay_window);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v3_details_t_tojson (vl_api_ipsec_sa_v3_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v3_details");
    cJSON_AddStringToObject(o, "_crc", "2fc991ee");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v3_t_tojson(&a->entry));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "seq_outbound", a->seq_outbound);
    cJSON_AddNumberToObject(o, "last_seq_inbound", a->last_seq_inbound);
    cJSON_AddNumberToObject(o, "replay_window", a->replay_window);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v4_details_t_tojson (vl_api_ipsec_sa_v4_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v4_details");
    cJSON_AddStringToObject(o, "_crc", "87a322d7");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v3_t_tojson(&a->entry));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "seq_outbound", a->seq_outbound);
    cJSON_AddNumberToObject(o, "last_seq_inbound", a->last_seq_inbound);
    cJSON_AddNumberToObject(o, "replay_window", a->replay_window);
    cJSON_AddNumberToObject(o, "thread_index", a->thread_index);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_sa_v5_details_t_tojson (vl_api_ipsec_sa_v5_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_sa_v5_details");
    cJSON_AddStringToObject(o, "_crc", "3cfecfbd");
    cJSON_AddItemToObject(o, "entry", vl_api_ipsec_sad_entry_v4_t_tojson(&a->entry));
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    cJSON_AddNumberToObject(o, "seq_outbound", a->seq_outbound);
    cJSON_AddNumberToObject(o, "last_seq_inbound", a->last_seq_inbound);
    cJSON_AddNumberToObject(o, "replay_window", a->replay_window);
    cJSON_AddNumberToObject(o, "thread_index", a->thread_index);
    cJSON_AddNumberToObject(o, "stat_index", a->stat_index);
    return o;
}
static inline cJSON *vl_api_ipsec_backend_dump_t_tojson (vl_api_ipsec_backend_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_backend_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_ipsec_backend_details_t_tojson (vl_api_ipsec_backend_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_backend_details");
    cJSON_AddStringToObject(o, "_crc", "ee601c29");
    cJSON_AddStringToObject(o, "name", (char *)a->name);
    cJSON_AddItemToObject(o, "protocol", vl_api_ipsec_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "index", a->index);
    cJSON_AddBoolToObject(o, "active", a->active);
    return o;
}
static inline cJSON *vl_api_ipsec_select_backend_t_tojson (vl_api_ipsec_select_backend_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_select_backend");
    cJSON_AddStringToObject(o, "_crc", "5bcfd3b7");
    cJSON_AddItemToObject(o, "protocol", vl_api_ipsec_proto_t_tojson(a->protocol));
    cJSON_AddNumberToObject(o, "index", a->index);
    return o;
}
static inline cJSON *vl_api_ipsec_select_backend_reply_t_tojson (vl_api_ipsec_select_backend_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_select_backend_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_ipsec_set_async_mode_t_tojson (vl_api_ipsec_set_async_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_set_async_mode");
    cJSON_AddStringToObject(o, "_crc", "a6465f7c");
    cJSON_AddBoolToObject(o, "async_enable", a->async_enable);
    return o;
}
static inline cJSON *vl_api_ipsec_set_async_mode_reply_t_tojson (vl_api_ipsec_set_async_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "ipsec_set_async_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
