#ifndef __included_hpp_crypto_sw_scheduler_api_json
#define __included_hpp_crypto_sw_scheduler_api_json

#include <vapi/vapi.hpp>
#include <vapi/crypto_sw_scheduler.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_crypto_sw_scheduler_set_worker>(vapi_msg_crypto_sw_scheduler_set_worker *msg)
{
  vapi_msg_crypto_sw_scheduler_set_worker_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_sw_scheduler_set_worker>(vapi_msg_crypto_sw_scheduler_set_worker *msg)
{
  vapi_msg_crypto_sw_scheduler_set_worker_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_sw_scheduler_set_worker>()
{
  return ::vapi_msg_id_crypto_sw_scheduler_set_worker; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_sw_scheduler_set_worker>>()
{
  return ::vapi_msg_id_crypto_sw_scheduler_set_worker; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_sw_scheduler_set_worker()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_sw_scheduler_set_worker>(vapi_msg_id_crypto_sw_scheduler_set_worker);
}

template <> inline vapi_msg_crypto_sw_scheduler_set_worker* vapi_alloc<vapi_msg_crypto_sw_scheduler_set_worker>(Connection &con)
{
  vapi_msg_crypto_sw_scheduler_set_worker* result = vapi_alloc_crypto_sw_scheduler_set_worker(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_crypto_sw_scheduler_set_worker>;

template class Request<vapi_msg_crypto_sw_scheduler_set_worker, vapi_msg_crypto_sw_scheduler_set_worker_reply>;

using Crypto_sw_scheduler_set_worker = Request<vapi_msg_crypto_sw_scheduler_set_worker, vapi_msg_crypto_sw_scheduler_set_worker_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_crypto_sw_scheduler_set_worker_reply>(vapi_msg_crypto_sw_scheduler_set_worker_reply *msg)
{
  vapi_msg_crypto_sw_scheduler_set_worker_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_crypto_sw_scheduler_set_worker_reply>(vapi_msg_crypto_sw_scheduler_set_worker_reply *msg)
{
  vapi_msg_crypto_sw_scheduler_set_worker_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_crypto_sw_scheduler_set_worker_reply>()
{
  return ::vapi_msg_id_crypto_sw_scheduler_set_worker_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_crypto_sw_scheduler_set_worker_reply>>()
{
  return ::vapi_msg_id_crypto_sw_scheduler_set_worker_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_crypto_sw_scheduler_set_worker_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_crypto_sw_scheduler_set_worker_reply>(vapi_msg_id_crypto_sw_scheduler_set_worker_reply);
}

template class Msg<vapi_msg_crypto_sw_scheduler_set_worker_reply>;

using Crypto_sw_scheduler_set_worker_reply = Msg<vapi_msg_crypto_sw_scheduler_set_worker_reply>;
}
#endif
