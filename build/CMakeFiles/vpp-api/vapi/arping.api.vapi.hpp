#ifndef __included_hpp_arping_api_json
#define __included_hpp_arping_api_json

#include <vapi/vapi.hpp>
#include <vapi/arping.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_arping>(vapi_msg_arping *msg)
{
  vapi_msg_arping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_arping>(vapi_msg_arping *msg)
{
  vapi_msg_arping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_arping>()
{
  return ::vapi_msg_id_arping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_arping>>()
{
  return ::vapi_msg_id_arping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_arping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_arping>(vapi_msg_id_arping);
}

template <> inline vapi_msg_arping* vapi_alloc<vapi_msg_arping>(Connection &con)
{
  vapi_msg_arping* result = vapi_alloc_arping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_arping>;

template class Request<vapi_msg_arping, vapi_msg_arping_reply>;

using Arping = Request<vapi_msg_arping, vapi_msg_arping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_arping_reply>(vapi_msg_arping_reply *msg)
{
  vapi_msg_arping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_arping_reply>(vapi_msg_arping_reply *msg)
{
  vapi_msg_arping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_arping_reply>()
{
  return ::vapi_msg_id_arping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_arping_reply>>()
{
  return ::vapi_msg_id_arping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_arping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_arping_reply>(vapi_msg_id_arping_reply);
}

template class Msg<vapi_msg_arping_reply>;

using Arping_reply = Msg<vapi_msg_arping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_arping_acd>(vapi_msg_arping_acd *msg)
{
  vapi_msg_arping_acd_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_arping_acd>(vapi_msg_arping_acd *msg)
{
  vapi_msg_arping_acd_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_arping_acd>()
{
  return ::vapi_msg_id_arping_acd; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_arping_acd>>()
{
  return ::vapi_msg_id_arping_acd; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_arping_acd()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_arping_acd>(vapi_msg_id_arping_acd);
}

template <> inline vapi_msg_arping_acd* vapi_alloc<vapi_msg_arping_acd>(Connection &con)
{
  vapi_msg_arping_acd* result = vapi_alloc_arping_acd(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_arping_acd>;

template class Request<vapi_msg_arping_acd, vapi_msg_arping_acd_reply>;

using Arping_acd = Request<vapi_msg_arping_acd, vapi_msg_arping_acd_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_arping_acd_reply>(vapi_msg_arping_acd_reply *msg)
{
  vapi_msg_arping_acd_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_arping_acd_reply>(vapi_msg_arping_acd_reply *msg)
{
  vapi_msg_arping_acd_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_arping_acd_reply>()
{
  return ::vapi_msg_id_arping_acd_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_arping_acd_reply>>()
{
  return ::vapi_msg_id_arping_acd_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_arping_acd_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_arping_acd_reply>(vapi_msg_id_arping_acd_reply);
}

template class Msg<vapi_msg_arping_acd_reply>;

using Arping_acd_reply = Msg<vapi_msg_arping_acd_reply>;
}
#endif
