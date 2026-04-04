#ifndef __included_hpp_mss_clamp_api_json
#define __included_hpp_mss_clamp_api_json

#include <vapi/vapi.hpp>
#include <vapi/mss_clamp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_mss_clamp_enable_disable>(vapi_msg_mss_clamp_enable_disable *msg)
{
  vapi_msg_mss_clamp_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mss_clamp_enable_disable>(vapi_msg_mss_clamp_enable_disable *msg)
{
  vapi_msg_mss_clamp_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mss_clamp_enable_disable>()
{
  return ::vapi_msg_id_mss_clamp_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mss_clamp_enable_disable>>()
{
  return ::vapi_msg_id_mss_clamp_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mss_clamp_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mss_clamp_enable_disable>(vapi_msg_id_mss_clamp_enable_disable);
}

template <> inline vapi_msg_mss_clamp_enable_disable* vapi_alloc<vapi_msg_mss_clamp_enable_disable>(Connection &con)
{
  vapi_msg_mss_clamp_enable_disable* result = vapi_alloc_mss_clamp_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mss_clamp_enable_disable>;

template class Request<vapi_msg_mss_clamp_enable_disable, vapi_msg_mss_clamp_enable_disable_reply>;

using Mss_clamp_enable_disable = Request<vapi_msg_mss_clamp_enable_disable, vapi_msg_mss_clamp_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_mss_clamp_enable_disable_reply>(vapi_msg_mss_clamp_enable_disable_reply *msg)
{
  vapi_msg_mss_clamp_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mss_clamp_enable_disable_reply>(vapi_msg_mss_clamp_enable_disable_reply *msg)
{
  vapi_msg_mss_clamp_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mss_clamp_enable_disable_reply>()
{
  return ::vapi_msg_id_mss_clamp_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mss_clamp_enable_disable_reply>>()
{
  return ::vapi_msg_id_mss_clamp_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mss_clamp_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mss_clamp_enable_disable_reply>(vapi_msg_id_mss_clamp_enable_disable_reply);
}

template class Msg<vapi_msg_mss_clamp_enable_disable_reply>;

using Mss_clamp_enable_disable_reply = Msg<vapi_msg_mss_clamp_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mss_clamp_get>(vapi_msg_mss_clamp_get *msg)
{
  vapi_msg_mss_clamp_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mss_clamp_get>(vapi_msg_mss_clamp_get *msg)
{
  vapi_msg_mss_clamp_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mss_clamp_get>()
{
  return ::vapi_msg_id_mss_clamp_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mss_clamp_get>>()
{
  return ::vapi_msg_id_mss_clamp_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mss_clamp_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mss_clamp_get>(vapi_msg_id_mss_clamp_get);
}

template <> inline vapi_msg_mss_clamp_get* vapi_alloc<vapi_msg_mss_clamp_get>(Connection &con)
{
  vapi_msg_mss_clamp_get* result = vapi_alloc_mss_clamp_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mss_clamp_get>;

template class Stream<vapi_msg_mss_clamp_get, vapi_msg_mss_clamp_get_reply, vapi_msg_mss_clamp_details>;

using Mss_clamp_get = Stream<vapi_msg_mss_clamp_get, vapi_msg_mss_clamp_get_reply, vapi_msg_mss_clamp_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mss_clamp_get_reply>(vapi_msg_mss_clamp_get_reply *msg)
{
  vapi_msg_mss_clamp_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mss_clamp_get_reply>(vapi_msg_mss_clamp_get_reply *msg)
{
  vapi_msg_mss_clamp_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mss_clamp_get_reply>()
{
  return ::vapi_msg_id_mss_clamp_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mss_clamp_get_reply>>()
{
  return ::vapi_msg_id_mss_clamp_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mss_clamp_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mss_clamp_get_reply>(vapi_msg_id_mss_clamp_get_reply);
}

template class Msg<vapi_msg_mss_clamp_get_reply>;

using Mss_clamp_get_reply = Msg<vapi_msg_mss_clamp_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mss_clamp_details>(vapi_msg_mss_clamp_details *msg)
{
  vapi_msg_mss_clamp_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mss_clamp_details>(vapi_msg_mss_clamp_details *msg)
{
  vapi_msg_mss_clamp_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mss_clamp_details>()
{
  return ::vapi_msg_id_mss_clamp_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mss_clamp_details>>()
{
  return ::vapi_msg_id_mss_clamp_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mss_clamp_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mss_clamp_details>(vapi_msg_id_mss_clamp_details);
}

template class Msg<vapi_msg_mss_clamp_details>;

}
#endif
