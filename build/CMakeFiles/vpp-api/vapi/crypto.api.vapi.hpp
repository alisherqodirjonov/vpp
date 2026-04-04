#ifndef __included_hpp_crypto_api_json
#define __included_hpp_crypto_api_json

#include <vapi/vapi.hpp>
#include <vapi/crypto.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_crypto_set_async_dispatch>(vapi_msg_crypto_set_async_dispatch *msg)
{
  vapi_msg_crypto_set_async_dispatch_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_set_async_dispatch>(vapi_msg_crypto_set_async_dispatch *msg)
{
  vapi_msg_crypto_set_async_dispatch_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_set_async_dispatch>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_set_async_dispatch>>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_set_async_dispatch()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_set_async_dispatch>(vapi_msg_id_crypto_set_async_dispatch);
}

template <> inline vapi_msg_crypto_set_async_dispatch* vapi_alloc<vapi_msg_crypto_set_async_dispatch>(Connection &con)
{
  vapi_msg_crypto_set_async_dispatch* result = vapi_alloc_crypto_set_async_dispatch(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_crypto_set_async_dispatch>;

template class Request<vapi_msg_crypto_set_async_dispatch, vapi_msg_crypto_set_async_dispatch_reply>;

using Crypto_set_async_dispatch = Request<vapi_msg_crypto_set_async_dispatch, vapi_msg_crypto_set_async_dispatch_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_crypto_set_async_dispatch_reply>(vapi_msg_crypto_set_async_dispatch_reply *msg)
{
  vapi_msg_crypto_set_async_dispatch_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_set_async_dispatch_reply>(vapi_msg_crypto_set_async_dispatch_reply *msg)
{
  vapi_msg_crypto_set_async_dispatch_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_set_async_dispatch_reply>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_set_async_dispatch_reply>>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_set_async_dispatch_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_set_async_dispatch_reply>(vapi_msg_id_crypto_set_async_dispatch_reply);
}

template class Msg<vapi_msg_crypto_set_async_dispatch_reply>;

using Crypto_set_async_dispatch_reply = Msg<vapi_msg_crypto_set_async_dispatch_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_crypto_set_async_dispatch_v2>(vapi_msg_crypto_set_async_dispatch_v2 *msg)
{
  vapi_msg_crypto_set_async_dispatch_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_set_async_dispatch_v2>(vapi_msg_crypto_set_async_dispatch_v2 *msg)
{
  vapi_msg_crypto_set_async_dispatch_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_set_async_dispatch_v2>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_set_async_dispatch_v2>>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_set_async_dispatch_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_set_async_dispatch_v2>(vapi_msg_id_crypto_set_async_dispatch_v2);
}

template <> inline vapi_msg_crypto_set_async_dispatch_v2* vapi_alloc<vapi_msg_crypto_set_async_dispatch_v2>(Connection &con)
{
  vapi_msg_crypto_set_async_dispatch_v2* result = vapi_alloc_crypto_set_async_dispatch_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_crypto_set_async_dispatch_v2>;

template class Request<vapi_msg_crypto_set_async_dispatch_v2, vapi_msg_crypto_set_async_dispatch_v2_reply>;

using Crypto_set_async_dispatch_v2 = Request<vapi_msg_crypto_set_async_dispatch_v2, vapi_msg_crypto_set_async_dispatch_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_crypto_set_async_dispatch_v2_reply>(vapi_msg_crypto_set_async_dispatch_v2_reply *msg)
{
  vapi_msg_crypto_set_async_dispatch_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_set_async_dispatch_v2_reply>(vapi_msg_crypto_set_async_dispatch_v2_reply *msg)
{
  vapi_msg_crypto_set_async_dispatch_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_set_async_dispatch_v2_reply>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_set_async_dispatch_v2_reply>>()
{
  return ::vapi_msg_id_crypto_set_async_dispatch_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_set_async_dispatch_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_set_async_dispatch_v2_reply>(vapi_msg_id_crypto_set_async_dispatch_v2_reply);
}

template class Msg<vapi_msg_crypto_set_async_dispatch_v2_reply>;

using Crypto_set_async_dispatch_v2_reply = Msg<vapi_msg_crypto_set_async_dispatch_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_crypto_set_handler>(vapi_msg_crypto_set_handler *msg)
{
  vapi_msg_crypto_set_handler_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_set_handler>(vapi_msg_crypto_set_handler *msg)
{
  vapi_msg_crypto_set_handler_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_set_handler>()
{
  return ::vapi_msg_id_crypto_set_handler; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_set_handler>>()
{
  return ::vapi_msg_id_crypto_set_handler; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_set_handler()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_set_handler>(vapi_msg_id_crypto_set_handler);
}

template <> inline vapi_msg_crypto_set_handler* vapi_alloc<vapi_msg_crypto_set_handler>(Connection &con)
{
  vapi_msg_crypto_set_handler* result = vapi_alloc_crypto_set_handler(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_crypto_set_handler>;

template class Request<vapi_msg_crypto_set_handler, vapi_msg_crypto_set_handler_reply>;

using Crypto_set_handler = Request<vapi_msg_crypto_set_handler, vapi_msg_crypto_set_handler_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_crypto_set_handler_reply>(vapi_msg_crypto_set_handler_reply *msg)
{
  vapi_msg_crypto_set_handler_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_set_handler_reply>(vapi_msg_crypto_set_handler_reply *msg)
{
  vapi_msg_crypto_set_handler_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_set_handler_reply>()
{
  return ::vapi_msg_id_crypto_set_handler_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_set_handler_reply>>()
{
  return ::vapi_msg_id_crypto_set_handler_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_set_handler_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_set_handler_reply>(vapi_msg_id_crypto_set_handler_reply);
}

template class Msg<vapi_msg_crypto_set_handler_reply>;

using Crypto_set_handler_reply = Msg<vapi_msg_crypto_set_handler_reply>;
}
#endif
