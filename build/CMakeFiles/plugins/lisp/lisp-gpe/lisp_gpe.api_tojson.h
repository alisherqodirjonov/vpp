/* Imported API files */
#include <vnet/interface_types.api_tojson.h>
#include <lisp/lisp-cp/lisp_types.api_tojson.h>
#ifndef included_lisp_gpe_api_tojson_h
#define included_lisp_gpe_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_gpe_locator_t_tojson (vl_api_gpe_locator_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "weight", a->weight);
    cJSON_AddItemToObject(o, "addr", vl_api_address_t_tojson(&a->addr));
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entry_t_tojson (vl_api_gpe_fwd_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "fwd_entry_index", a->fwd_entry_index);
    cJSON_AddNumberToObject(o, "dp_table", a->dp_table);
    cJSON_AddItemToObject(o, "leid", vl_api_eid_t_tojson(&a->leid));
    cJSON_AddItemToObject(o, "reid", vl_api_eid_t_tojson(&a->reid));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddNumberToObject(o, "action", a->action);
    return o;
}
static inline cJSON *vl_api_gpe_native_fwd_rpath_t_tojson (vl_api_gpe_native_fwd_rpath_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "fib_index", a->fib_index);
    cJSON_AddNumberToObject(o, "nh_sw_if_index", a->nh_sw_if_index);
    cJSON_AddItemToObject(o, "nh_addr", vl_api_address_t_tojson(&a->nh_addr));
    return o;
}
static inline cJSON *vl_api_gpe_add_del_fwd_entry_t_tojson (vl_api_gpe_add_del_fwd_entry_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_add_del_fwd_entry");
    cJSON_AddStringToObject(o, "_crc", "f0847644");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddItemToObject(o, "rmt_eid", vl_api_eid_t_tojson(&a->rmt_eid));
    cJSON_AddItemToObject(o, "lcl_eid", vl_api_eid_t_tojson(&a->lcl_eid));
    cJSON_AddNumberToObject(o, "vni", a->vni);
    cJSON_AddNumberToObject(o, "dp_table", a->dp_table);
    cJSON_AddNumberToObject(o, "action", a->action);
    cJSON_AddNumberToObject(o, "loc_num", a->loc_num);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "locs");
        for (i = 0; i < a->loc_num; i++) {
            cJSON_AddItemToArray(array, vl_api_gpe_locator_t_tojson(&a->locs[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_gpe_add_del_fwd_entry_reply_t_tojson (vl_api_gpe_add_del_fwd_entry_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_add_del_fwd_entry_reply");
    cJSON_AddStringToObject(o, "_crc", "efe5f176");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "fwd_entry_index", a->fwd_entry_index);
    return o;
}
static inline cJSON *vl_api_gpe_enable_disable_t_tojson (vl_api_gpe_enable_disable_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_enable_disable");
    cJSON_AddStringToObject(o, "_crc", "c264d7bf");
    cJSON_AddBoolToObject(o, "is_enable", a->is_enable);
    return o;
}
static inline cJSON *vl_api_gpe_enable_disable_reply_t_tojson (vl_api_gpe_enable_disable_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_enable_disable_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gpe_add_del_iface_t_tojson (vl_api_gpe_add_del_iface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_add_del_iface");
    cJSON_AddStringToObject(o, "_crc", "3ccff273");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddBoolToObject(o, "is_l2", a->is_l2);
    cJSON_AddNumberToObject(o, "dp_table", a->dp_table);
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_gpe_add_del_iface_reply_t_tojson (vl_api_gpe_add_del_iface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_add_del_iface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entry_vnis_get_t_tojson (vl_api_gpe_fwd_entry_vnis_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_fwd_entry_vnis_get");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entry_vnis_get_reply_t_tojson (vl_api_gpe_fwd_entry_vnis_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_fwd_entry_vnis_get_reply");
    cJSON_AddStringToObject(o, "_crc", "aa70da20");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "vnis");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->vnis[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entries_get_t_tojson (vl_api_gpe_fwd_entries_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_fwd_entries_get");
    cJSON_AddStringToObject(o, "_crc", "8d1f2fe9");
    cJSON_AddNumberToObject(o, "vni", a->vni);
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entries_get_reply_t_tojson (vl_api_gpe_fwd_entries_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_fwd_entries_get_reply");
    cJSON_AddStringToObject(o, "_crc", "c4844876");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "entries");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_gpe_fwd_entry_t_tojson(&a->entries[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entry_path_dump_t_tojson (vl_api_gpe_fwd_entry_path_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_fwd_entry_path_dump");
    cJSON_AddStringToObject(o, "_crc", "39bce980");
    cJSON_AddNumberToObject(o, "fwd_entry_index", a->fwd_entry_index);
    return o;
}
static inline cJSON *vl_api_gpe_fwd_entry_path_details_t_tojson (vl_api_gpe_fwd_entry_path_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_fwd_entry_path_details");
    cJSON_AddStringToObject(o, "_crc", "483df51a");
    cJSON_AddItemToObject(o, "lcl_loc", vl_api_gpe_locator_t_tojson(&a->lcl_loc));
    cJSON_AddItemToObject(o, "rmt_loc", vl_api_gpe_locator_t_tojson(&a->rmt_loc));
    return o;
}
static inline cJSON *vl_api_gpe_set_encap_mode_t_tojson (vl_api_gpe_set_encap_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_set_encap_mode");
    cJSON_AddStringToObject(o, "_crc", "bd819eac");
    cJSON_AddBoolToObject(o, "is_vxlan", a->is_vxlan);
    return o;
}
static inline cJSON *vl_api_gpe_set_encap_mode_reply_t_tojson (vl_api_gpe_set_encap_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_set_encap_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gpe_get_encap_mode_t_tojson (vl_api_gpe_get_encap_mode_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_get_encap_mode");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_gpe_get_encap_mode_reply_t_tojson (vl_api_gpe_get_encap_mode_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_get_encap_mode_reply");
    cJSON_AddStringToObject(o, "_crc", "36e3f7ca");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "encap_mode", a->encap_mode);
    return o;
}
static inline cJSON *vl_api_gpe_add_del_native_fwd_rpath_t_tojson (vl_api_gpe_add_del_native_fwd_rpath_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_add_del_native_fwd_rpath");
    cJSON_AddStringToObject(o, "_crc", "43fc8b54");
    cJSON_AddBoolToObject(o, "is_add", a->is_add);
    cJSON_AddNumberToObject(o, "table_id", a->table_id);
    cJSON_AddNumberToObject(o, "nh_sw_if_index", a->nh_sw_if_index);
    cJSON_AddItemToObject(o, "nh_addr", vl_api_address_t_tojson(&a->nh_addr));
    return o;
}
static inline cJSON *vl_api_gpe_add_del_native_fwd_rpath_reply_t_tojson (vl_api_gpe_add_del_native_fwd_rpath_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_add_del_native_fwd_rpath_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_gpe_native_fwd_rpaths_get_t_tojson (vl_api_gpe_native_fwd_rpaths_get_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_native_fwd_rpaths_get");
    cJSON_AddStringToObject(o, "_crc", "f652ceb4");
    cJSON_AddBoolToObject(o, "is_ip4", a->is_ip4);
    return o;
}
static inline cJSON *vl_api_gpe_native_fwd_rpaths_get_reply_t_tojson (vl_api_gpe_native_fwd_rpaths_get_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "gpe_native_fwd_rpaths_get_reply");
    cJSON_AddStringToObject(o, "_crc", "7a1ca5a2");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "entries");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_gpe_native_fwd_rpath_t_tojson(&a->entries[i]));
        }
    }
    return o;
}
#endif
