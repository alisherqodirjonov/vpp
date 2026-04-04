/* Imported API files */
#include <vnet/fib/fib_types.api_tojson.h>
#ifndef included_bier_api_tojson_h
#define included_bier_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_bier_table_id_t_tojson (vl_api_bier_table_id_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "bt_set", a->bt_set);
    cJSON_AddNumberToObject(o, "bt_sub_domain", a->bt_sub_domain);
    cJSON_AddNumberToObject(o, "bt_hdr_len_id", a->bt_hdr_len_id);
    return o;
}
static inline cJSON *vl_api_bier_route_t_tojson (vl_api_bier_route_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "br_bp", a->br_bp);
    cJSON_AddItemToObject(o, "br_tbl_id", vl_api_bier_table_id_t_tojson(&a->br_tbl_id));
    cJSON_AddNumberToObject(o, "br_n_paths", a->br_n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "br_paths");
        for (i = 0; i < a->br_n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->br_paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_bier_table_add_del_t_tojson (vl_api_bier_table_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_table_add_del");
    cJSON_AddStringToObject(o, "_crc", "35e59209");
    cJSON_AddItemToObject(o, "bt_tbl_id", vl_api_bier_table_id_t_tojson(&a->bt_tbl_id));
    cJSON_AddNumberToObject(o, "bt_label", a->bt_label);
    cJSON_AddBoolToObject(o, "bt_is_add", a->bt_is_add);
    return o;
}
static inline cJSON *vl_api_bier_table_add_del_reply_t_tojson (vl_api_bier_table_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_table_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bier_table_dump_t_tojson (vl_api_bier_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_table_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bier_table_details_t_tojson (vl_api_bier_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_table_details");
    cJSON_AddStringToObject(o, "_crc", "fc44a9dd");
    cJSON_AddNumberToObject(o, "bt_label", a->bt_label);
    cJSON_AddItemToObject(o, "bt_tbl_id", vl_api_bier_table_id_t_tojson(&a->bt_tbl_id));
    return o;
}
static inline cJSON *vl_api_bier_route_add_del_t_tojson (vl_api_bier_route_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_route_add_del");
    cJSON_AddStringToObject(o, "_crc", "fd02f3ea");
    cJSON_AddBoolToObject(o, "br_is_add", a->br_is_add);
    cJSON_AddBoolToObject(o, "br_is_replace", a->br_is_replace);
    cJSON_AddItemToObject(o, "br_route", vl_api_bier_route_t_tojson(&a->br_route));
    return o;
}
static inline cJSON *vl_api_bier_route_add_del_reply_t_tojson (vl_api_bier_route_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_route_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bier_route_dump_t_tojson (vl_api_bier_route_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_route_dump");
    cJSON_AddStringToObject(o, "_crc", "38339846");
    cJSON_AddItemToObject(o, "br_tbl_id", vl_api_bier_table_id_t_tojson(&a->br_tbl_id));
    return o;
}
static inline cJSON *vl_api_bier_route_details_t_tojson (vl_api_bier_route_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_route_details");
    cJSON_AddStringToObject(o, "_crc", "4008caee");
    cJSON_AddItemToObject(o, "br_route", vl_api_bier_route_t_tojson(&a->br_route));
    return o;
}
static inline cJSON *vl_api_bier_imp_add_t_tojson (vl_api_bier_imp_add_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_imp_add");
    cJSON_AddStringToObject(o, "_crc", "3856dc3d");
    cJSON_AddItemToObject(o, "bi_tbl_id", vl_api_bier_table_id_t_tojson(&a->bi_tbl_id));
    cJSON_AddNumberToObject(o, "bi_src", a->bi_src);
    cJSON_AddNumberToObject(o, "bi_n_bytes", a->bi_n_bytes);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->bi_bytes, a->bi_n_bytes);
    cJSON_AddStringToObject(o, "bi_bytes", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_bier_imp_add_reply_t_tojson (vl_api_bier_imp_add_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_imp_add_reply");
    cJSON_AddStringToObject(o, "_crc", "d49c5793");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    cJSON_AddNumberToObject(o, "bi_index", a->bi_index);
    return o;
}
static inline cJSON *vl_api_bier_imp_del_t_tojson (vl_api_bier_imp_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_imp_del");
    cJSON_AddStringToObject(o, "_crc", "7d45edf6");
    cJSON_AddNumberToObject(o, "bi_index", a->bi_index);
    return o;
}
static inline cJSON *vl_api_bier_imp_del_reply_t_tojson (vl_api_bier_imp_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_imp_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bier_imp_dump_t_tojson (vl_api_bier_imp_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_imp_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bier_imp_details_t_tojson (vl_api_bier_imp_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_imp_details");
    cJSON_AddStringToObject(o, "_crc", "b76192df");
    cJSON_AddItemToObject(o, "bi_tbl_id", vl_api_bier_table_id_t_tojson(&a->bi_tbl_id));
    cJSON_AddNumberToObject(o, "bi_src", a->bi_src);
    cJSON_AddNumberToObject(o, "bi_n_bytes", a->bi_n_bytes);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->bi_bytes, a->bi_n_bytes);
    cJSON_AddStringToObject(o, "bi_bytes", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_bier_disp_table_add_del_t_tojson (vl_api_bier_disp_table_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_table_add_del");
    cJSON_AddStringToObject(o, "_crc", "889657ac");
    cJSON_AddNumberToObject(o, "bdt_tbl_id", a->bdt_tbl_id);
    cJSON_AddBoolToObject(o, "bdt_is_add", a->bdt_is_add);
    return o;
}
static inline cJSON *vl_api_bier_disp_table_add_del_reply_t_tojson (vl_api_bier_disp_table_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_table_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bier_disp_table_dump_t_tojson (vl_api_bier_disp_table_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_table_dump");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_bier_disp_table_details_t_tojson (vl_api_bier_disp_table_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_table_details");
    cJSON_AddStringToObject(o, "_crc", "d27942c0");
    cJSON_AddNumberToObject(o, "bdt_tbl_id", a->bdt_tbl_id);
    return o;
}
static inline cJSON *vl_api_bier_disp_entry_add_del_t_tojson (vl_api_bier_disp_entry_add_del_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_entry_add_del");
    cJSON_AddStringToObject(o, "_crc", "9eb80cb4");
    cJSON_AddNumberToObject(o, "bde_bp", a->bde_bp);
    cJSON_AddNumberToObject(o, "bde_tbl_id", a->bde_tbl_id);
    cJSON_AddBoolToObject(o, "bde_is_add", a->bde_is_add);
    cJSON_AddNumberToObject(o, "bde_payload_proto", a->bde_payload_proto);
    cJSON_AddNumberToObject(o, "bde_n_paths", a->bde_n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "bde_paths");
        for (i = 0; i < a->bde_n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->bde_paths[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_bier_disp_entry_add_del_reply_t_tojson (vl_api_bier_disp_entry_add_del_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_entry_add_del_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_bier_disp_entry_dump_t_tojson (vl_api_bier_disp_entry_dump_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_entry_dump");
    cJSON_AddStringToObject(o, "_crc", "b5fa54ad");
    cJSON_AddNumberToObject(o, "bde_tbl_id", a->bde_tbl_id);
    return o;
}
static inline cJSON *vl_api_bier_disp_entry_details_t_tojson (vl_api_bier_disp_entry_details_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "bier_disp_entry_details");
    cJSON_AddStringToObject(o, "_crc", "84c218f1");
    cJSON_AddNumberToObject(o, "bde_bp", a->bde_bp);
    cJSON_AddNumberToObject(o, "bde_tbl_id", a->bde_tbl_id);
    cJSON_AddBoolToObject(o, "bde_is_add", a->bde_is_add);
    cJSON_AddNumberToObject(o, "bde_payload_proto", a->bde_payload_proto);
    cJSON_AddNumberToObject(o, "bde_n_paths", a->bde_n_paths);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "bde_paths");
        for (i = 0; i < a->bde_n_paths; i++) {
            cJSON_AddItemToArray(array, vl_api_fib_path_t_tojson(&a->bde_paths[i]));
        }
    }
    return o;
}
#endif
