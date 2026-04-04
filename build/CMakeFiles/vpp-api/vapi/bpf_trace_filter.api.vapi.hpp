#ifndef __included_hpp_bpf_trace_filter_api_json
#define __included_hpp_bpf_trace_filter_api_json

#include <vapi/vapi.hpp>
#include <vapi/bpf_trace_filter.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_bpf_trace_filter_set>(vapi_msg_bpf_trace_filter_set *msg)
{
  vapi_msg_bpf_trace_filter_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bpf_trace_filter_set>(vapi_msg_bpf_trace_filter_set *msg)
{
  vapi_msg_bpf_trace_filter_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bpf_trace_filter_set>()
{
  return ::vapi_msg_id_bpf_trace_filter_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bpf_trace_filter_set>>()
{
  return ::vapi_msg_id_bpf_trace_filter_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bpf_trace_filter_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bpf_trace_filter_set>(vapi_msg_id_bpf_trace_filter_set);
}

template <> inline vapi_msg_bpf_trace_filter_set* vapi_alloc<vapi_msg_bpf_trace_filter_set, size_t>(Connection &con, size_t filter_buf_array_size)
{
  vapi_msg_bpf_trace_filter_set* result = vapi_alloc_bpf_trace_filter_set(con.vapi_ctx, filter_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bpf_trace_filter_set>;

template class Request<vapi_msg_bpf_trace_filter_set, vapi_msg_bpf_trace_filter_set_reply, size_t>;

using Bpf_trace_filter_set = Request<vapi_msg_bpf_trace_filter_set, vapi_msg_bpf_trace_filter_set_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_bpf_trace_filter_set_reply>(vapi_msg_bpf_trace_filter_set_reply *msg)
{
  vapi_msg_bpf_trace_filter_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bpf_trace_filter_set_reply>(vapi_msg_bpf_trace_filter_set_reply *msg)
{
  vapi_msg_bpf_trace_filter_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bpf_trace_filter_set_reply>()
{
  return ::vapi_msg_id_bpf_trace_filter_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bpf_trace_filter_set_reply>>()
{
  return ::vapi_msg_id_bpf_trace_filter_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bpf_trace_filter_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bpf_trace_filter_set_reply>(vapi_msg_id_bpf_trace_filter_set_reply);
}

template class Msg<vapi_msg_bpf_trace_filter_set_reply>;

using Bpf_trace_filter_set_reply = Msg<vapi_msg_bpf_trace_filter_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bpf_trace_filter_set_v2>(vapi_msg_bpf_trace_filter_set_v2 *msg)
{
  vapi_msg_bpf_trace_filter_set_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bpf_trace_filter_set_v2>(vapi_msg_bpf_trace_filter_set_v2 *msg)
{
  vapi_msg_bpf_trace_filter_set_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bpf_trace_filter_set_v2>()
{
  return ::vapi_msg_id_bpf_trace_filter_set_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bpf_trace_filter_set_v2>>()
{
  return ::vapi_msg_id_bpf_trace_filter_set_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bpf_trace_filter_set_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bpf_trace_filter_set_v2>(vapi_msg_id_bpf_trace_filter_set_v2);
}

template <> inline vapi_msg_bpf_trace_filter_set_v2* vapi_alloc<vapi_msg_bpf_trace_filter_set_v2, size_t>(Connection &con, size_t filter_buf_array_size)
{
  vapi_msg_bpf_trace_filter_set_v2* result = vapi_alloc_bpf_trace_filter_set_v2(con.vapi_ctx, filter_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bpf_trace_filter_set_v2>;

template class Request<vapi_msg_bpf_trace_filter_set_v2, vapi_msg_bpf_trace_filter_set_v2_reply, size_t>;

using Bpf_trace_filter_set_v2 = Request<vapi_msg_bpf_trace_filter_set_v2, vapi_msg_bpf_trace_filter_set_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_bpf_trace_filter_set_v2_reply>(vapi_msg_bpf_trace_filter_set_v2_reply *msg)
{
  vapi_msg_bpf_trace_filter_set_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bpf_trace_filter_set_v2_reply>(vapi_msg_bpf_trace_filter_set_v2_reply *msg)
{
  vapi_msg_bpf_trace_filter_set_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bpf_trace_filter_set_v2_reply>()
{
  return ::vapi_msg_id_bpf_trace_filter_set_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bpf_trace_filter_set_v2_reply>>()
{
  return ::vapi_msg_id_bpf_trace_filter_set_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bpf_trace_filter_set_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bpf_trace_filter_set_v2_reply>(vapi_msg_id_bpf_trace_filter_set_v2_reply);
}

template class Msg<vapi_msg_bpf_trace_filter_set_v2_reply>;

using Bpf_trace_filter_set_v2_reply = Msg<vapi_msg_bpf_trace_filter_set_v2_reply>;
}
#endif
