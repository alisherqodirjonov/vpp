#define vl_endianfun		/* define message structures */
#include "bpf_trace_filter.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "bpf_trace_filter.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "bpf_trace_filter.api.h"
#undef vl_printfun

#include "bpf_trace_filter.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("bpf_trace_filter_b682a79a", VL_MSG_BPF_TRACE_FILTER_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_bpf_trace_filter);
   vl_msg_api_add_msg_name_crc (am, "bpf_trace_filter_set_3171346e",
                                VL_API_BPF_TRACE_FILTER_SET + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bpf_trace_filter_set_reply_e8d4e804",
                                VL_API_BPF_TRACE_FILTER_SET_REPLY + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bpf_trace_filter_set_v2_5615acbf",
                                VL_API_BPF_TRACE_FILTER_SET_V2 + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "bpf_trace_filter_set_v2_reply_e8d4e804",
                                VL_API_BPF_TRACE_FILTER_SET_V2_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BPF_TRACE_FILTER_SET + msg_id_base,
   .name = "bpf_trace_filter_set",
   .handler = vl_api_bpf_trace_filter_set_t_handler,
   .endian = vl_api_bpf_trace_filter_set_t_endian,
   .format_fn = vl_api_bpf_trace_filter_set_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bpf_trace_filter_set_t_tojson,
   .fromjson = vl_api_bpf_trace_filter_set_t_fromjson,
   .calc_size = vl_api_bpf_trace_filter_set_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BPF_TRACE_FILTER_SET_REPLY + msg_id_base,
  .name = "bpf_trace_filter_set_reply",
  .handler = 0,
  .endian = vl_api_bpf_trace_filter_set_reply_t_endian,
  .format_fn = vl_api_bpf_trace_filter_set_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bpf_trace_filter_set_reply_t_tojson,
  .fromjson = vl_api_bpf_trace_filter_set_reply_t_fromjson,
  .calc_size = vl_api_bpf_trace_filter_set_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_BPF_TRACE_FILTER_SET_V2 + msg_id_base,
   .name = "bpf_trace_filter_set_v2",
   .handler = vl_api_bpf_trace_filter_set_v2_t_handler,
   .endian = vl_api_bpf_trace_filter_set_v2_t_endian,
   .format_fn = vl_api_bpf_trace_filter_set_v2_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_bpf_trace_filter_set_v2_t_tojson,
   .fromjson = vl_api_bpf_trace_filter_set_v2_t_fromjson,
   .calc_size = vl_api_bpf_trace_filter_set_v2_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_BPF_TRACE_FILTER_SET_V2_REPLY + msg_id_base,
  .name = "bpf_trace_filter_set_v2_reply",
  .handler = 0,
  .endian = vl_api_bpf_trace_filter_set_v2_reply_t_endian,
  .format_fn = vl_api_bpf_trace_filter_set_v2_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_bpf_trace_filter_set_v2_reply_t_tojson,
  .fromjson = vl_api_bpf_trace_filter_set_v2_reply_t_fromjson,
  .calc_size = vl_api_bpf_trace_filter_set_v2_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
