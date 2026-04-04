/* Imported API files */
#include <vnet/ip/ip_types.api_tojson.h>
#include <vnet/interface_types.api_tojson.h>
#ifndef included_vat2_test_api_tojson_h
#define included_vat2_test_api_tojson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

static inline cJSON *vl_api_test_enumflags_t_tojson (vl_api_test_enumflags_t a) {
    cJSON *array = cJSON_CreateArray();
    if (a & RED)
       cJSON_AddItemToArray(array, cJSON_CreateString("RED"));
    if (a & BLUE)
       cJSON_AddItemToArray(array, cJSON_CreateString("BLUE"));
    if (a & GREEN)
       cJSON_AddItemToArray(array, cJSON_CreateString("GREEN"));
    return array;
}
static inline cJSON *vl_api_test_stringtype_t_tojson (vl_api_test_stringtype_t *a) {
    cJSON *o = cJSON_CreateObject();
    vl_api_string_cJSON_AddToObject(o, "str", &a->str);
    return o;
}
static inline cJSON *vl_api_test_vlatype_t_tojson (vl_api_test_vlatype_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "data", a->data);
    return o;
}
static inline cJSON *vl_api_test_vlatype2_t_tojson (vl_api_test_vlatype2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "vla");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->vla[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_test_vlatype3_t_tojson (vl_api_test_vlatype3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "count", a->count);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->vla, a->count);
    cJSON_AddStringToObject(o, "vla", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_test_prefix_t_tojson (vl_api_test_prefix_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_prefix");
    cJSON_AddStringToObject(o, "_crc", "d866c1a9");
    cJSON_AddItemToObject(o, "pref", vl_api_prefix_t_tojson(&a->pref));
    return o;
}
static inline cJSON *vl_api_test_prefix_reply_t_tojson (vl_api_test_prefix_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_prefix_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_enum_t_tojson (vl_api_test_enum_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_enum");
    cJSON_AddStringToObject(o, "_crc", "e3190a2e");
    cJSON_AddItemToObject(o, "flags", vl_api_test_enumflags_t_tojson(a->flags));
    return o;
}
static inline cJSON *vl_api_test_enum_reply_t_tojson (vl_api_test_enum_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_enum_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_string_t_tojson (vl_api_test_string_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_string");
    cJSON_AddStringToObject(o, "_crc", "3955d673");
    cJSON_AddItemToObject(o, "str", vl_api_test_stringtype_t_tojson(&a->str));
    return o;
}
static inline cJSON *vl_api_test_string_reply_t_tojson (vl_api_test_string_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_string_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_string2_t_tojson (vl_api_test_string2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_string2");
    cJSON_AddStringToObject(o, "_crc", "64a8785b");
    vl_api_string_cJSON_AddToObject(o, "str", &a->str);
    return o;
}
static inline cJSON *vl_api_test_string2_reply_t_tojson (vl_api_test_string2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_string2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_vla_t_tojson (vl_api_test_vla_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla");
    cJSON_AddStringToObject(o, "_crc", "5d944dfc");
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "vla");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, cJSON_CreateNumber(a->vla[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_test_vla_reply_t_tojson (vl_api_test_vla_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_vla2_t_tojson (vl_api_test_vla2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla2");
    cJSON_AddStringToObject(o, "_crc", "471f6687");
    cJSON_AddNumberToObject(o, "count", a->count);
    {
    char *s = format_c_string(0, "0x%U", format_hex_bytes_no_wrap, &a->vla, a->count);
    cJSON_AddStringToObject(o, "vla", s);
    vec_free(s);
    }
    return o;
}
static inline cJSON *vl_api_test_vla2_reply_t_tojson (vl_api_test_vla2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_vla3_t_tojson (vl_api_test_vla3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla3");
    cJSON_AddStringToObject(o, "_crc", "bac4a968");
    cJSON_AddNumberToObject(o, "count", a->count);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "vla");
        for (i = 0; i < a->count; i++) {
            cJSON_AddItemToArray(array, vl_api_test_vlatype_t_tojson(&a->vla[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_test_vla3_reply_t_tojson (vl_api_test_vla3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla3_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_vla4_t_tojson (vl_api_test_vla4_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla4");
    cJSON_AddStringToObject(o, "_crc", "c061d9d1");
    cJSON_AddItemToObject(o, "data", vl_api_test_vlatype2_t_tojson(&a->data));
    return o;
}
static inline cJSON *vl_api_test_vla4_reply_t_tojson (vl_api_test_vla4_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla4_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_vla5_t_tojson (vl_api_test_vla5_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla5");
    cJSON_AddStringToObject(o, "_crc", "09b0e1f3");
    cJSON_AddItemToObject(o, "data", vl_api_test_vlatype3_t_tojson(&a->data));
    return o;
}
static inline cJSON *vl_api_test_vla5_reply_t_tojson (vl_api_test_vla5_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_vla5_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_addresses_t_tojson (vl_api_test_addresses_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_addresses");
    cJSON_AddStringToObject(o, "_crc", "2bef955c");
    cJSON_AddItemToObject(o, "a", vl_api_address_t_tojson(&a->a));
    return o;
}
static inline cJSON *vl_api_test_addresses_reply_t_tojson (vl_api_test_addresses_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_addresses_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_addresses2_t_tojson (vl_api_test_addresses2_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_addresses2");
    cJSON_AddStringToObject(o, "_crc", "ff01dd23");
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "a");
        for (i = 0; i < 2; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->a[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_test_addresses2_reply_t_tojson (vl_api_test_addresses2_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_addresses2_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_addresses3_t_tojson (vl_api_test_addresses3_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_addresses3");
    cJSON_AddStringToObject(o, "_crc", "7f3e48a1");
    cJSON_AddNumberToObject(o, "n", a->n);
    {
        int i;
        cJSON *array = cJSON_AddArrayToObject(o, "a");
        for (i = 0; i < a->n; i++) {
            cJSON_AddItemToArray(array, vl_api_address_t_tojson(&a->a[i]));
        }
    }
    return o;
}
static inline cJSON *vl_api_test_addresses3_reply_t_tojson (vl_api_test_addresses3_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_addresses3_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_empty_t_tojson (vl_api_test_empty_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_empty");
    cJSON_AddStringToObject(o, "_crc", "51077d14");
    return o;
}
static inline cJSON *vl_api_test_empty_reply_t_tojson (vl_api_test_empty_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_empty_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
static inline cJSON *vl_api_test_interface_t_tojson (vl_api_test_interface_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_interface");
    cJSON_AddStringToObject(o, "_crc", "00e34dc0");
    cJSON_AddNumberToObject(o, "sw_if_index", a->sw_if_index);
    return o;
}
static inline cJSON *vl_api_test_interface_reply_t_tojson (vl_api_test_interface_reply_t *a) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "_msgname", "test_interface_reply");
    cJSON_AddStringToObject(o, "_crc", "e8d4e804");
    cJSON_AddNumberToObject(o, "retval", a->retval);
    return o;
}
#endif
