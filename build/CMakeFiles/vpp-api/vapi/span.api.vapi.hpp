#ifndef __included_hpp_span_api_json
#define __included_hpp_span_api_json

#include <vapi/vapi.hpp>
#include <vapi/span.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_span_enable_disable>(vapi_msg_sw_interface_span_enable_disable *msg)
{
  vapi_msg_sw_interface_span_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_span_enable_disable>(vapi_msg_sw_interface_span_enable_disable *msg)
{
  vapi_msg_sw_interface_span_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_span_enable_disable>()
{
  return ::vapi_msg_id_sw_interface_span_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_span_enable_disable>>()
{
  return ::vapi_msg_id_sw_interface_span_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_span_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_span_enable_disable>(vapi_msg_id_sw_interface_span_enable_disable);
}

template <> inline vapi_msg_sw_interface_span_enable_disable* vapi_alloc<vapi_msg_sw_interface_span_enable_disable>(Connection &con)
{
  vapi_msg_sw_interface_span_enable_disable* result = vapi_alloc_sw_interface_span_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_span_enable_disable>;

template class Request<vapi_msg_sw_interface_span_enable_disable, vapi_msg_sw_interface_span_enable_disable_reply>;

using Sw_interface_span_enable_disable = Request<vapi_msg_sw_interface_span_enable_disable, vapi_msg_sw_interface_span_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_span_enable_disable_reply>(vapi_msg_sw_interface_span_enable_disable_reply *msg)
{
  vapi_msg_sw_interface_span_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_span_enable_disable_reply>(vapi_msg_sw_interface_span_enable_disable_reply *msg)
{
  vapi_msg_sw_interface_span_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_span_enable_disable_reply>()
{
  return ::vapi_msg_id_sw_interface_span_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_span_enable_disable_reply>>()
{
  return ::vapi_msg_id_sw_interface_span_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_span_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_span_enable_disable_reply>(vapi_msg_id_sw_interface_span_enable_disable_reply);
}

template class Msg<vapi_msg_sw_interface_span_enable_disable_reply>;

using Sw_interface_span_enable_disable_reply = Msg<vapi_msg_sw_interface_span_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_span_dump>(vapi_msg_sw_interface_span_dump *msg)
{
  vapi_msg_sw_interface_span_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_span_dump>(vapi_msg_sw_interface_span_dump *msg)
{
  vapi_msg_sw_interface_span_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_span_dump>()
{
  return ::vapi_msg_id_sw_interface_span_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_span_dump>>()
{
  return ::vapi_msg_id_sw_interface_span_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_span_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_span_dump>(vapi_msg_id_sw_interface_span_dump);
}

template <> inline vapi_msg_sw_interface_span_dump* vapi_alloc<vapi_msg_sw_interface_span_dump>(Connection &con)
{
  vapi_msg_sw_interface_span_dump* result = vapi_alloc_sw_interface_span_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_span_dump>;

template class Dump<vapi_msg_sw_interface_span_dump, vapi_msg_sw_interface_span_details>;

using Sw_interface_span_dump = Dump<vapi_msg_sw_interface_span_dump, vapi_msg_sw_interface_span_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_span_details>(vapi_msg_sw_interface_span_details *msg)
{
  vapi_msg_sw_interface_span_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_span_details>(vapi_msg_sw_interface_span_details *msg)
{
  vapi_msg_sw_interface_span_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_span_details>()
{
  return ::vapi_msg_id_sw_interface_span_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_span_details>>()
{
  return ::vapi_msg_id_sw_interface_span_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_span_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_span_details>(vapi_msg_id_sw_interface_span_details);
}

template class Msg<vapi_msg_sw_interface_span_details>;

using Sw_interface_span_details = Msg<vapi_msg_sw_interface_span_details>;
}
#endif
