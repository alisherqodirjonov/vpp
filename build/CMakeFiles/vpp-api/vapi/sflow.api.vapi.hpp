#ifndef __included_hpp_sflow_api_json
#define __included_hpp_sflow_api_json

#include <vapi/vapi.hpp>
#include <vapi/sflow.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sflow_enable_disable>(vapi_msg_sflow_enable_disable *msg)
{
  vapi_msg_sflow_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_enable_disable>(vapi_msg_sflow_enable_disable *msg)
{
  vapi_msg_sflow_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_enable_disable>()
{
  return ::vapi_msg_id_sflow_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_enable_disable>>()
{
  return ::vapi_msg_id_sflow_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_enable_disable>(vapi_msg_id_sflow_enable_disable);
}

template <> inline vapi_msg_sflow_enable_disable* vapi_alloc<vapi_msg_sflow_enable_disable>(Connection &con)
{
  vapi_msg_sflow_enable_disable* result = vapi_alloc_sflow_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_enable_disable>;

template class Request<vapi_msg_sflow_enable_disable, vapi_msg_sflow_enable_disable_reply>;

using Sflow_enable_disable = Request<vapi_msg_sflow_enable_disable, vapi_msg_sflow_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_enable_disable_reply>(vapi_msg_sflow_enable_disable_reply *msg)
{
  vapi_msg_sflow_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_enable_disable_reply>(vapi_msg_sflow_enable_disable_reply *msg)
{
  vapi_msg_sflow_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_enable_disable_reply>()
{
  return ::vapi_msg_id_sflow_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_enable_disable_reply>>()
{
  return ::vapi_msg_id_sflow_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_enable_disable_reply>(vapi_msg_id_sflow_enable_disable_reply);
}

template class Msg<vapi_msg_sflow_enable_disable_reply>;

using Sflow_enable_disable_reply = Msg<vapi_msg_sflow_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_sampling_rate_get>(vapi_msg_sflow_sampling_rate_get *msg)
{
  vapi_msg_sflow_sampling_rate_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_sampling_rate_get>(vapi_msg_sflow_sampling_rate_get *msg)
{
  vapi_msg_sflow_sampling_rate_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_sampling_rate_get>()
{
  return ::vapi_msg_id_sflow_sampling_rate_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_sampling_rate_get>>()
{
  return ::vapi_msg_id_sflow_sampling_rate_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_sampling_rate_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_sampling_rate_get>(vapi_msg_id_sflow_sampling_rate_get);
}

template <> inline vapi_msg_sflow_sampling_rate_get* vapi_alloc<vapi_msg_sflow_sampling_rate_get>(Connection &con)
{
  vapi_msg_sflow_sampling_rate_get* result = vapi_alloc_sflow_sampling_rate_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_sampling_rate_get>;

template class Request<vapi_msg_sflow_sampling_rate_get, vapi_msg_sflow_sampling_rate_get_reply>;

using Sflow_sampling_rate_get = Request<vapi_msg_sflow_sampling_rate_get, vapi_msg_sflow_sampling_rate_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_sampling_rate_get_reply>(vapi_msg_sflow_sampling_rate_get_reply *msg)
{
  vapi_msg_sflow_sampling_rate_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_sampling_rate_get_reply>(vapi_msg_sflow_sampling_rate_get_reply *msg)
{
  vapi_msg_sflow_sampling_rate_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_sampling_rate_get_reply>()
{
  return ::vapi_msg_id_sflow_sampling_rate_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_sampling_rate_get_reply>>()
{
  return ::vapi_msg_id_sflow_sampling_rate_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_sampling_rate_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_sampling_rate_get_reply>(vapi_msg_id_sflow_sampling_rate_get_reply);
}

template class Msg<vapi_msg_sflow_sampling_rate_get_reply>;

using Sflow_sampling_rate_get_reply = Msg<vapi_msg_sflow_sampling_rate_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_sampling_rate_set>(vapi_msg_sflow_sampling_rate_set *msg)
{
  vapi_msg_sflow_sampling_rate_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_sampling_rate_set>(vapi_msg_sflow_sampling_rate_set *msg)
{
  vapi_msg_sflow_sampling_rate_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_sampling_rate_set>()
{
  return ::vapi_msg_id_sflow_sampling_rate_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_sampling_rate_set>>()
{
  return ::vapi_msg_id_sflow_sampling_rate_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_sampling_rate_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_sampling_rate_set>(vapi_msg_id_sflow_sampling_rate_set);
}

template <> inline vapi_msg_sflow_sampling_rate_set* vapi_alloc<vapi_msg_sflow_sampling_rate_set>(Connection &con)
{
  vapi_msg_sflow_sampling_rate_set* result = vapi_alloc_sflow_sampling_rate_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_sampling_rate_set>;

template class Request<vapi_msg_sflow_sampling_rate_set, vapi_msg_sflow_sampling_rate_set_reply>;

using Sflow_sampling_rate_set = Request<vapi_msg_sflow_sampling_rate_set, vapi_msg_sflow_sampling_rate_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_sampling_rate_set_reply>(vapi_msg_sflow_sampling_rate_set_reply *msg)
{
  vapi_msg_sflow_sampling_rate_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_sampling_rate_set_reply>(vapi_msg_sflow_sampling_rate_set_reply *msg)
{
  vapi_msg_sflow_sampling_rate_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_sampling_rate_set_reply>()
{
  return ::vapi_msg_id_sflow_sampling_rate_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_sampling_rate_set_reply>>()
{
  return ::vapi_msg_id_sflow_sampling_rate_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_sampling_rate_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_sampling_rate_set_reply>(vapi_msg_id_sflow_sampling_rate_set_reply);
}

template class Msg<vapi_msg_sflow_sampling_rate_set_reply>;

using Sflow_sampling_rate_set_reply = Msg<vapi_msg_sflow_sampling_rate_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_polling_interval_set>(vapi_msg_sflow_polling_interval_set *msg)
{
  vapi_msg_sflow_polling_interval_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_polling_interval_set>(vapi_msg_sflow_polling_interval_set *msg)
{
  vapi_msg_sflow_polling_interval_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_polling_interval_set>()
{
  return ::vapi_msg_id_sflow_polling_interval_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_polling_interval_set>>()
{
  return ::vapi_msg_id_sflow_polling_interval_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_polling_interval_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_polling_interval_set>(vapi_msg_id_sflow_polling_interval_set);
}

template <> inline vapi_msg_sflow_polling_interval_set* vapi_alloc<vapi_msg_sflow_polling_interval_set>(Connection &con)
{
  vapi_msg_sflow_polling_interval_set* result = vapi_alloc_sflow_polling_interval_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_polling_interval_set>;

template class Request<vapi_msg_sflow_polling_interval_set, vapi_msg_sflow_polling_interval_set_reply>;

using Sflow_polling_interval_set = Request<vapi_msg_sflow_polling_interval_set, vapi_msg_sflow_polling_interval_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_polling_interval_set_reply>(vapi_msg_sflow_polling_interval_set_reply *msg)
{
  vapi_msg_sflow_polling_interval_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_polling_interval_set_reply>(vapi_msg_sflow_polling_interval_set_reply *msg)
{
  vapi_msg_sflow_polling_interval_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_polling_interval_set_reply>()
{
  return ::vapi_msg_id_sflow_polling_interval_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_polling_interval_set_reply>>()
{
  return ::vapi_msg_id_sflow_polling_interval_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_polling_interval_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_polling_interval_set_reply>(vapi_msg_id_sflow_polling_interval_set_reply);
}

template class Msg<vapi_msg_sflow_polling_interval_set_reply>;

using Sflow_polling_interval_set_reply = Msg<vapi_msg_sflow_polling_interval_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_polling_interval_get>(vapi_msg_sflow_polling_interval_get *msg)
{
  vapi_msg_sflow_polling_interval_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_polling_interval_get>(vapi_msg_sflow_polling_interval_get *msg)
{
  vapi_msg_sflow_polling_interval_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_polling_interval_get>()
{
  return ::vapi_msg_id_sflow_polling_interval_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_polling_interval_get>>()
{
  return ::vapi_msg_id_sflow_polling_interval_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_polling_interval_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_polling_interval_get>(vapi_msg_id_sflow_polling_interval_get);
}

template <> inline vapi_msg_sflow_polling_interval_get* vapi_alloc<vapi_msg_sflow_polling_interval_get>(Connection &con)
{
  vapi_msg_sflow_polling_interval_get* result = vapi_alloc_sflow_polling_interval_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_polling_interval_get>;

template class Request<vapi_msg_sflow_polling_interval_get, vapi_msg_sflow_polling_interval_get_reply>;

using Sflow_polling_interval_get = Request<vapi_msg_sflow_polling_interval_get, vapi_msg_sflow_polling_interval_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_polling_interval_get_reply>(vapi_msg_sflow_polling_interval_get_reply *msg)
{
  vapi_msg_sflow_polling_interval_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_polling_interval_get_reply>(vapi_msg_sflow_polling_interval_get_reply *msg)
{
  vapi_msg_sflow_polling_interval_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_polling_interval_get_reply>()
{
  return ::vapi_msg_id_sflow_polling_interval_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_polling_interval_get_reply>>()
{
  return ::vapi_msg_id_sflow_polling_interval_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_polling_interval_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_polling_interval_get_reply>(vapi_msg_id_sflow_polling_interval_get_reply);
}

template class Msg<vapi_msg_sflow_polling_interval_get_reply>;

using Sflow_polling_interval_get_reply = Msg<vapi_msg_sflow_polling_interval_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_header_bytes_set>(vapi_msg_sflow_header_bytes_set *msg)
{
  vapi_msg_sflow_header_bytes_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_header_bytes_set>(vapi_msg_sflow_header_bytes_set *msg)
{
  vapi_msg_sflow_header_bytes_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_header_bytes_set>()
{
  return ::vapi_msg_id_sflow_header_bytes_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_header_bytes_set>>()
{
  return ::vapi_msg_id_sflow_header_bytes_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_header_bytes_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_header_bytes_set>(vapi_msg_id_sflow_header_bytes_set);
}

template <> inline vapi_msg_sflow_header_bytes_set* vapi_alloc<vapi_msg_sflow_header_bytes_set>(Connection &con)
{
  vapi_msg_sflow_header_bytes_set* result = vapi_alloc_sflow_header_bytes_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_header_bytes_set>;

template class Request<vapi_msg_sflow_header_bytes_set, vapi_msg_sflow_header_bytes_set_reply>;

using Sflow_header_bytes_set = Request<vapi_msg_sflow_header_bytes_set, vapi_msg_sflow_header_bytes_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_header_bytes_set_reply>(vapi_msg_sflow_header_bytes_set_reply *msg)
{
  vapi_msg_sflow_header_bytes_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_header_bytes_set_reply>(vapi_msg_sflow_header_bytes_set_reply *msg)
{
  vapi_msg_sflow_header_bytes_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_header_bytes_set_reply>()
{
  return ::vapi_msg_id_sflow_header_bytes_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_header_bytes_set_reply>>()
{
  return ::vapi_msg_id_sflow_header_bytes_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_header_bytes_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_header_bytes_set_reply>(vapi_msg_id_sflow_header_bytes_set_reply);
}

template class Msg<vapi_msg_sflow_header_bytes_set_reply>;

using Sflow_header_bytes_set_reply = Msg<vapi_msg_sflow_header_bytes_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_header_bytes_get>(vapi_msg_sflow_header_bytes_get *msg)
{
  vapi_msg_sflow_header_bytes_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_header_bytes_get>(vapi_msg_sflow_header_bytes_get *msg)
{
  vapi_msg_sflow_header_bytes_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_header_bytes_get>()
{
  return ::vapi_msg_id_sflow_header_bytes_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_header_bytes_get>>()
{
  return ::vapi_msg_id_sflow_header_bytes_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_header_bytes_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_header_bytes_get>(vapi_msg_id_sflow_header_bytes_get);
}

template <> inline vapi_msg_sflow_header_bytes_get* vapi_alloc<vapi_msg_sflow_header_bytes_get>(Connection &con)
{
  vapi_msg_sflow_header_bytes_get* result = vapi_alloc_sflow_header_bytes_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_header_bytes_get>;

template class Request<vapi_msg_sflow_header_bytes_get, vapi_msg_sflow_header_bytes_get_reply>;

using Sflow_header_bytes_get = Request<vapi_msg_sflow_header_bytes_get, vapi_msg_sflow_header_bytes_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_header_bytes_get_reply>(vapi_msg_sflow_header_bytes_get_reply *msg)
{
  vapi_msg_sflow_header_bytes_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_header_bytes_get_reply>(vapi_msg_sflow_header_bytes_get_reply *msg)
{
  vapi_msg_sflow_header_bytes_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_header_bytes_get_reply>()
{
  return ::vapi_msg_id_sflow_header_bytes_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_header_bytes_get_reply>>()
{
  return ::vapi_msg_id_sflow_header_bytes_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_header_bytes_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_header_bytes_get_reply>(vapi_msg_id_sflow_header_bytes_get_reply);
}

template class Msg<vapi_msg_sflow_header_bytes_get_reply>;

using Sflow_header_bytes_get_reply = Msg<vapi_msg_sflow_header_bytes_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_direction_set>(vapi_msg_sflow_direction_set *msg)
{
  vapi_msg_sflow_direction_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_direction_set>(vapi_msg_sflow_direction_set *msg)
{
  vapi_msg_sflow_direction_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_direction_set>()
{
  return ::vapi_msg_id_sflow_direction_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_direction_set>>()
{
  return ::vapi_msg_id_sflow_direction_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_direction_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_direction_set>(vapi_msg_id_sflow_direction_set);
}

template <> inline vapi_msg_sflow_direction_set* vapi_alloc<vapi_msg_sflow_direction_set>(Connection &con)
{
  vapi_msg_sflow_direction_set* result = vapi_alloc_sflow_direction_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_direction_set>;

template class Request<vapi_msg_sflow_direction_set, vapi_msg_sflow_direction_set_reply>;

using Sflow_direction_set = Request<vapi_msg_sflow_direction_set, vapi_msg_sflow_direction_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_direction_set_reply>(vapi_msg_sflow_direction_set_reply *msg)
{
  vapi_msg_sflow_direction_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_direction_set_reply>(vapi_msg_sflow_direction_set_reply *msg)
{
  vapi_msg_sflow_direction_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_direction_set_reply>()
{
  return ::vapi_msg_id_sflow_direction_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_direction_set_reply>>()
{
  return ::vapi_msg_id_sflow_direction_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_direction_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_direction_set_reply>(vapi_msg_id_sflow_direction_set_reply);
}

template class Msg<vapi_msg_sflow_direction_set_reply>;

using Sflow_direction_set_reply = Msg<vapi_msg_sflow_direction_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_direction_get>(vapi_msg_sflow_direction_get *msg)
{
  vapi_msg_sflow_direction_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_direction_get>(vapi_msg_sflow_direction_get *msg)
{
  vapi_msg_sflow_direction_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_direction_get>()
{
  return ::vapi_msg_id_sflow_direction_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_direction_get>>()
{
  return ::vapi_msg_id_sflow_direction_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_direction_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_direction_get>(vapi_msg_id_sflow_direction_get);
}

template <> inline vapi_msg_sflow_direction_get* vapi_alloc<vapi_msg_sflow_direction_get>(Connection &con)
{
  vapi_msg_sflow_direction_get* result = vapi_alloc_sflow_direction_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_direction_get>;

template class Request<vapi_msg_sflow_direction_get, vapi_msg_sflow_direction_get_reply>;

using Sflow_direction_get = Request<vapi_msg_sflow_direction_get, vapi_msg_sflow_direction_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_direction_get_reply>(vapi_msg_sflow_direction_get_reply *msg)
{
  vapi_msg_sflow_direction_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_direction_get_reply>(vapi_msg_sflow_direction_get_reply *msg)
{
  vapi_msg_sflow_direction_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_direction_get_reply>()
{
  return ::vapi_msg_id_sflow_direction_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_direction_get_reply>>()
{
  return ::vapi_msg_id_sflow_direction_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_direction_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_direction_get_reply>(vapi_msg_id_sflow_direction_get_reply);
}

template class Msg<vapi_msg_sflow_direction_get_reply>;

using Sflow_direction_get_reply = Msg<vapi_msg_sflow_direction_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_drop_monitoring_set>(vapi_msg_sflow_drop_monitoring_set *msg)
{
  vapi_msg_sflow_drop_monitoring_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_drop_monitoring_set>(vapi_msg_sflow_drop_monitoring_set *msg)
{
  vapi_msg_sflow_drop_monitoring_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_drop_monitoring_set>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_drop_monitoring_set>>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_drop_monitoring_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_drop_monitoring_set>(vapi_msg_id_sflow_drop_monitoring_set);
}

template <> inline vapi_msg_sflow_drop_monitoring_set* vapi_alloc<vapi_msg_sflow_drop_monitoring_set>(Connection &con)
{
  vapi_msg_sflow_drop_monitoring_set* result = vapi_alloc_sflow_drop_monitoring_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_drop_monitoring_set>;

template class Request<vapi_msg_sflow_drop_monitoring_set, vapi_msg_sflow_drop_monitoring_set_reply>;

using Sflow_drop_monitoring_set = Request<vapi_msg_sflow_drop_monitoring_set, vapi_msg_sflow_drop_monitoring_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_drop_monitoring_set_reply>(vapi_msg_sflow_drop_monitoring_set_reply *msg)
{
  vapi_msg_sflow_drop_monitoring_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_drop_monitoring_set_reply>(vapi_msg_sflow_drop_monitoring_set_reply *msg)
{
  vapi_msg_sflow_drop_monitoring_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_drop_monitoring_set_reply>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_drop_monitoring_set_reply>>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_drop_monitoring_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_drop_monitoring_set_reply>(vapi_msg_id_sflow_drop_monitoring_set_reply);
}

template class Msg<vapi_msg_sflow_drop_monitoring_set_reply>;

using Sflow_drop_monitoring_set_reply = Msg<vapi_msg_sflow_drop_monitoring_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_drop_monitoring_get>(vapi_msg_sflow_drop_monitoring_get *msg)
{
  vapi_msg_sflow_drop_monitoring_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_drop_monitoring_get>(vapi_msg_sflow_drop_monitoring_get *msg)
{
  vapi_msg_sflow_drop_monitoring_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_drop_monitoring_get>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_drop_monitoring_get>>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_drop_monitoring_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_drop_monitoring_get>(vapi_msg_id_sflow_drop_monitoring_get);
}

template <> inline vapi_msg_sflow_drop_monitoring_get* vapi_alloc<vapi_msg_sflow_drop_monitoring_get>(Connection &con)
{
  vapi_msg_sflow_drop_monitoring_get* result = vapi_alloc_sflow_drop_monitoring_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_drop_monitoring_get>;

template class Request<vapi_msg_sflow_drop_monitoring_get, vapi_msg_sflow_drop_monitoring_get_reply>;

using Sflow_drop_monitoring_get = Request<vapi_msg_sflow_drop_monitoring_get, vapi_msg_sflow_drop_monitoring_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_drop_monitoring_get_reply>(vapi_msg_sflow_drop_monitoring_get_reply *msg)
{
  vapi_msg_sflow_drop_monitoring_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_drop_monitoring_get_reply>(vapi_msg_sflow_drop_monitoring_get_reply *msg)
{
  vapi_msg_sflow_drop_monitoring_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_drop_monitoring_get_reply>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_drop_monitoring_get_reply>>()
{
  return ::vapi_msg_id_sflow_drop_monitoring_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_drop_monitoring_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_drop_monitoring_get_reply>(vapi_msg_id_sflow_drop_monitoring_get_reply);
}

template class Msg<vapi_msg_sflow_drop_monitoring_get_reply>;

using Sflow_drop_monitoring_get_reply = Msg<vapi_msg_sflow_drop_monitoring_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sflow_interface_dump>(vapi_msg_sflow_interface_dump *msg)
{
  vapi_msg_sflow_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_interface_dump>(vapi_msg_sflow_interface_dump *msg)
{
  vapi_msg_sflow_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_interface_dump>()
{
  return ::vapi_msg_id_sflow_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_interface_dump>>()
{
  return ::vapi_msg_id_sflow_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_interface_dump>(vapi_msg_id_sflow_interface_dump);
}

template <> inline vapi_msg_sflow_interface_dump* vapi_alloc<vapi_msg_sflow_interface_dump>(Connection &con)
{
  vapi_msg_sflow_interface_dump* result = vapi_alloc_sflow_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sflow_interface_dump>;

template class Dump<vapi_msg_sflow_interface_dump, vapi_msg_sflow_interface_details>;

using Sflow_interface_dump = Dump<vapi_msg_sflow_interface_dump, vapi_msg_sflow_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sflow_interface_details>(vapi_msg_sflow_interface_details *msg)
{
  vapi_msg_sflow_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sflow_interface_details>(vapi_msg_sflow_interface_details *msg)
{
  vapi_msg_sflow_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sflow_interface_details>()
{
  return ::vapi_msg_id_sflow_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sflow_interface_details>>()
{
  return ::vapi_msg_id_sflow_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sflow_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sflow_interface_details>(vapi_msg_id_sflow_interface_details);
}

template class Msg<vapi_msg_sflow_interface_details>;

using Sflow_interface_details = Msg<vapi_msg_sflow_interface_details>;
}
#endif
