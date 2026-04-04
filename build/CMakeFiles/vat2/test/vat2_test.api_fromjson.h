/* Imported API files */
#include <vnet/ip/ip_types.api_fromjson.h>
#include <vnet/interface_types.api_fromjson.h>
#ifndef included_vat2_test_api_fromjson_h
#define included_vat2_test_api_fromjson_h
#include <vppinfra/cJSON.h>

#include <vlibapi/jsonformat.h>

#pragma GCC diagnostic ignored "-Wunused-label"
static inline int vl_api_test_enumflags_t_fromjson (void **mp, int *len, cJSON *o, vl_api_test_enumflags_t *a) {
   int i;
   *a = 0;
   for (i = 0; i < cJSON_GetArraySize(o); i++) {
       cJSON *e = cJSON_GetArrayItem(o, i);
       char *p = cJSON_GetStringValue(e);
       if (!p) return -1;
       if (strcmp(p, "RED") == 0) *a |= 1;
       if (strcmp(p, "BLUE") == 0) *a |= 2;
       if (strcmp(p, "GREEN") == 0) *a |= 4;
    }
   return 0;
}
static inline int vl_api_test_stringtype_t_fromjson (void **mp, int *len, cJSON *o, vl_api_test_stringtype_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "str");
    if (!item) goto error;
    char *p = cJSON_GetStringValue(item);
    size_t plen = strlen(p);
    *mp = cJSON_realloc(*mp, *len + plen);
    if (*mp == 0) goto error;
    vl_api_c_string_to_api_string(p, (void *)*mp + *len - sizeof(vl_api_string_t));
    *len += plen;

    return 0;

  error:
    return -1;
}
static inline int vl_api_test_vlatype_t_fromjson (void **mp, int *len, cJSON *o, vl_api_test_vlatype_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    vl_api_u32_fromjson(item, &a->data);

    return 0;

  error:
    return -1;
}
static inline int vl_api_test_vlatype2_t_fromjson (void **mp, int *len, cJSON *o, vl_api_test_vlatype2_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "vla");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "vla");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        *mp = cJSON_realloc(*mp, *len + sizeof(u32) * size);
        u32 *d = (void *)*mp + *len;
        *len += sizeof(u32) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            vl_api_u32_fromjson(e, &d[i]);
        }
    }

    return 0;

  error:
    return -1;
}
static inline int vl_api_test_vlatype3_t_fromjson (void **mp, int *len, cJSON *o, vl_api_test_vlatype3_t *a) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));

    item = cJSON_GetObjectItem(o, "vla");
    if (!item) goto error;
    s = u8string_fromjson(o, "vla");
    if (!s) goto error;
    a->count = vec_len(s);
    *mp = cJSON_realloc(*mp, *len + vec_len(s));
    clib_memcpy((void *)*mp + *len, s, vec_len(s));
    *len += vec_len(s);
    vec_free(s);

    return 0;

  error:
    return -1;
}
static inline vl_api_test_prefix_t *vl_api_test_prefix_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_prefix_t);
    vl_api_test_prefix_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "pref");
    if (!item) goto error;
    if (vl_api_prefix_t_fromjson((void **)&a, &l, item, &a->pref) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_prefix_reply_t *vl_api_test_prefix_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_prefix_reply_t);
    vl_api_test_prefix_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_enum_t *vl_api_test_enum_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_enum_t);
    vl_api_test_enum_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "flags");
    if (!item) goto error;
    if (vl_api_test_enumflags_t_fromjson((void **)&a, &l, item, &a->flags) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_enum_reply_t *vl_api_test_enum_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_enum_reply_t);
    vl_api_test_enum_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_string_t *vl_api_test_string_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_string_t);
    vl_api_test_string_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "str");
    if (!item) goto error;
    if (vl_api_test_stringtype_t_fromjson((void **)&a, &l, item, &a->str) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_string_reply_t *vl_api_test_string_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_string_reply_t);
    vl_api_test_string_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_string2_t *vl_api_test_string2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_string2_t);
    vl_api_test_string2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "str");
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
static inline vl_api_test_string2_reply_t *vl_api_test_string2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_string2_reply_t);
    vl_api_test_string2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla_t *vl_api_test_vla_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla_t);
    vl_api_test_vla_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vla");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "vla");
        int size = cJSON_GetArraySize(array);
        a->count = size;
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
static inline vl_api_test_vla_reply_t *vl_api_test_vla_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla_reply_t);
    vl_api_test_vla_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla2_t *vl_api_test_vla2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla2_t);
    vl_api_test_vla2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vla");
    if (!item) goto error;
    s = u8string_fromjson(o, "vla");
    if (!s) goto error;
    a->count = vec_len(s);
    a = cJSON_realloc(a, l + vec_len(s));
    clib_memcpy((void *)a + l, s, vec_len(s));
    l += vec_len(s);
    vec_free(s);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla2_reply_t *vl_api_test_vla2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla2_reply_t);
    vl_api_test_vla2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla3_t *vl_api_test_vla3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla3_t);
    vl_api_test_vla3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "vla");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "vla");
        int size = cJSON_GetArraySize(array);
        a->count = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_test_vlatype_t) * size);
        vl_api_test_vlatype_t *d = (void *)a + l;
        l += sizeof(vl_api_test_vlatype_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_test_vlatype_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla3_reply_t *vl_api_test_vla3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla3_reply_t);
    vl_api_test_vla3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla4_t *vl_api_test_vla4_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla4_t);
    vl_api_test_vla4_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    if (vl_api_test_vlatype2_t_fromjson((void **)&a, &l, item, &a->data) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla4_reply_t *vl_api_test_vla4_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla4_reply_t);
    vl_api_test_vla4_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla5_t *vl_api_test_vla5_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla5_t);
    vl_api_test_vla5_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "data");
    if (!item) goto error;
    if (vl_api_test_vlatype3_t_fromjson((void **)&a, &l, item, &a->data) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_vla5_reply_t *vl_api_test_vla5_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_vla5_reply_t);
    vl_api_test_vla5_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_addresses_t *vl_api_test_addresses_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_addresses_t);
    vl_api_test_addresses_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "a");
    if (!item) goto error;
    if (vl_api_address_t_fromjson((void **)&a, &l, item, &a->a) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_addresses_reply_t *vl_api_test_addresses_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_addresses_reply_t);
    vl_api_test_addresses_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_addresses2_t *vl_api_test_addresses2_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_addresses2_t);
    vl_api_test_addresses2_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "a");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "a");
        int size = cJSON_GetArraySize(array);
        if (size != 2) goto error;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &a->a[i]) < 0) goto error;
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_addresses2_reply_t *vl_api_test_addresses2_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_addresses2_reply_t);
    vl_api_test_addresses2_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_addresses3_t *vl_api_test_addresses3_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_addresses3_t);
    vl_api_test_addresses3_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "a");
    if (!item) goto error;
    {
        int i;
        cJSON *array = cJSON_GetObjectItem(o, "a");
        int size = cJSON_GetArraySize(array);
        a->n = size;
        a = cJSON_realloc(a, l + sizeof(vl_api_address_t) * size);
        vl_api_address_t *d = (void *)a + l;
        l += sizeof(vl_api_address_t) * size;
        for (i = 0; i < size; i++) {
            cJSON *e = cJSON_GetArrayItem(array, i);
            if (vl_api_address_t_fromjson((void **)&a, len, e, &d[i]) < 0) goto error; 
        }
    }

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_addresses3_reply_t *vl_api_test_addresses3_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_addresses3_reply_t);
    vl_api_test_addresses3_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_empty_t *vl_api_test_empty_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_empty_t);
    vl_api_test_empty_t *a = cJSON_malloc(l);

    *len = l;
    return a;
}
static inline vl_api_test_empty_reply_t *vl_api_test_empty_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_empty_reply_t);
    vl_api_test_empty_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_interface_t *vl_api_test_interface_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_interface_t);
    vl_api_test_interface_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "sw_if_index");
    if (!item) goto error;
    if (vl_api_interface_index_t_fromjson((void **)&a, &l, item, &a->sw_if_index) < 0) goto error;

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
static inline vl_api_test_interface_reply_t *vl_api_test_interface_reply_t_fromjson (cJSON *o, int *len) {
    cJSON *item __attribute__ ((unused));
    u8 *s __attribute__ ((unused));
    int l = sizeof(vl_api_test_interface_reply_t);
    vl_api_test_interface_reply_t *a = cJSON_malloc(l);

    item = cJSON_GetObjectItem(o, "retval");
    if (!item) goto error;
    vl_api_i32_fromjson(item, &a->retval);

    *len = l;
    return a;

  error:
    cJSON_free(a);
    return 0;
}
#endif
