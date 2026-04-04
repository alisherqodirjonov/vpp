#ifndef __included_hpp_tls_openssl_api_json
#define __included_hpp_tls_openssl_api_json

#include <vapi/vapi.hpp>
#include <vapi/tls_openssl.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_tls_openssl_set_engine>(vapi_msg_tls_openssl_set_engine *msg)
{
  vapi_msg_tls_openssl_set_engine_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tls_openssl_set_engine>(vapi_msg_tls_openssl_set_engine *msg)
{
  vapi_msg_tls_openssl_set_engine_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tls_openssl_set_engine>()
{
  return ::vapi_msg_id_tls_openssl_set_engine; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tls_openssl_set_engine>>()
{
  return ::vapi_msg_id_tls_openssl_set_engine; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tls_openssl_set_engine()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tls_openssl_set_engine>(vapi_msg_id_tls_openssl_set_engine);
}

template <> inline vapi_msg_tls_openssl_set_engine* vapi_alloc<vapi_msg_tls_openssl_set_engine>(Connection &con)
{
  vapi_msg_tls_openssl_set_engine* result = vapi_alloc_tls_openssl_set_engine(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_tls_openssl_set_engine>;

template class Request<vapi_msg_tls_openssl_set_engine, vapi_msg_tls_openssl_set_engine_reply>;

using Tls_openssl_set_engine = Request<vapi_msg_tls_openssl_set_engine, vapi_msg_tls_openssl_set_engine_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_tls_openssl_set_engine_reply>(vapi_msg_tls_openssl_set_engine_reply *msg)
{
  vapi_msg_tls_openssl_set_engine_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_tls_openssl_set_engine_reply>(vapi_msg_tls_openssl_set_engine_reply *msg)
{
  vapi_msg_tls_openssl_set_engine_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_tls_openssl_set_engine_reply>()
{
  return ::vapi_msg_id_tls_openssl_set_engine_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_tls_openssl_set_engine_reply>>()
{
  return ::vapi_msg_id_tls_openssl_set_engine_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_tls_openssl_set_engine_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_tls_openssl_set_engine_reply>(vapi_msg_id_tls_openssl_set_engine_reply);
}

template class Msg<vapi_msg_tls_openssl_set_engine_reply>;

using Tls_openssl_set_engine_reply = Msg<vapi_msg_tls_openssl_set_engine_reply>;
}
#endif
