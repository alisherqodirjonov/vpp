#ifndef __included_hpp_http_static_api_json
#define __included_hpp_http_static_api_json

#include <vapi/vapi.hpp>
#include <vapi/http_static.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_http_static_enable_v4>(vapi_msg_http_static_enable_v4 *msg)
{
  vapi_msg_http_static_enable_v4_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_http_static_enable_v4>(vapi_msg_http_static_enable_v4 *msg)
{
  vapi_msg_http_static_enable_v4_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_http_static_enable_v4>()
{
  return ::vapi_msg_id_http_static_enable_v4; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_http_static_enable_v4>>()
{
  return ::vapi_msg_id_http_static_enable_v4; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_http_static_enable_v4()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_http_static_enable_v4>(vapi_msg_id_http_static_enable_v4);
}

template <> inline vapi_msg_http_static_enable_v4* vapi_alloc<vapi_msg_http_static_enable_v4>(Connection &con)
{
  vapi_msg_http_static_enable_v4* result = vapi_alloc_http_static_enable_v4(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_http_static_enable_v4>;

template class Request<vapi_msg_http_static_enable_v4, vapi_msg_http_static_enable_v4_reply>;

using Http_static_enable_v4 = Request<vapi_msg_http_static_enable_v4, vapi_msg_http_static_enable_v4_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_http_static_enable_v4_reply>(vapi_msg_http_static_enable_v4_reply *msg)
{
  vapi_msg_http_static_enable_v4_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_http_static_enable_v4_reply>(vapi_msg_http_static_enable_v4_reply *msg)
{
  vapi_msg_http_static_enable_v4_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_http_static_enable_v4_reply>()
{
  return ::vapi_msg_id_http_static_enable_v4_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_http_static_enable_v4_reply>>()
{
  return ::vapi_msg_id_http_static_enable_v4_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_http_static_enable_v4_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_http_static_enable_v4_reply>(vapi_msg_id_http_static_enable_v4_reply);
}

template class Msg<vapi_msg_http_static_enable_v4_reply>;

using Http_static_enable_v4_reply = Msg<vapi_msg_http_static_enable_v4_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_http_static_enable_v5>(vapi_msg_http_static_enable_v5 *msg)
{
  vapi_msg_http_static_enable_v5_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_http_static_enable_v5>(vapi_msg_http_static_enable_v5 *msg)
{
  vapi_msg_http_static_enable_v5_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_http_static_enable_v5>()
{
  return ::vapi_msg_id_http_static_enable_v5; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_http_static_enable_v5>>()
{
  return ::vapi_msg_id_http_static_enable_v5; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_http_static_enable_v5()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_http_static_enable_v5>(vapi_msg_id_http_static_enable_v5);
}

template <> inline vapi_msg_http_static_enable_v5* vapi_alloc<vapi_msg_http_static_enable_v5>(Connection &con)
{
  vapi_msg_http_static_enable_v5* result = vapi_alloc_http_static_enable_v5(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_http_static_enable_v5>;

template class Request<vapi_msg_http_static_enable_v5, vapi_msg_http_static_enable_v5_reply>;

using Http_static_enable_v5 = Request<vapi_msg_http_static_enable_v5, vapi_msg_http_static_enable_v5_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_http_static_enable_v5_reply>(vapi_msg_http_static_enable_v5_reply *msg)
{
  vapi_msg_http_static_enable_v5_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_http_static_enable_v5_reply>(vapi_msg_http_static_enable_v5_reply *msg)
{
  vapi_msg_http_static_enable_v5_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_http_static_enable_v5_reply>()
{
  return ::vapi_msg_id_http_static_enable_v5_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_http_static_enable_v5_reply>>()
{
  return ::vapi_msg_id_http_static_enable_v5_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_http_static_enable_v5_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_http_static_enable_v5_reply>(vapi_msg_id_http_static_enable_v5_reply);
}

template class Msg<vapi_msg_http_static_enable_v5_reply>;

using Http_static_enable_v5_reply = Msg<vapi_msg_http_static_enable_v5_reply>;
}
#endif
