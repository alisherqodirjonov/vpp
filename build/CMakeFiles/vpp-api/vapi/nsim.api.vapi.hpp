#ifndef __included_hpp_nsim_api_json
#define __included_hpp_nsim_api_json

#include <vapi/vapi.hpp>
#include <vapi/nsim.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_nsim_cross_connect_enable_disable>(vapi_msg_nsim_cross_connect_enable_disable *msg)
{
  vapi_msg_nsim_cross_connect_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_cross_connect_enable_disable>(vapi_msg_nsim_cross_connect_enable_disable *msg)
{
  vapi_msg_nsim_cross_connect_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_cross_connect_enable_disable>()
{
  return ::vapi_msg_id_nsim_cross_connect_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_cross_connect_enable_disable>>()
{
  return ::vapi_msg_id_nsim_cross_connect_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_cross_connect_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_cross_connect_enable_disable>(vapi_msg_id_nsim_cross_connect_enable_disable);
}

template <> inline vapi_msg_nsim_cross_connect_enable_disable* vapi_alloc<vapi_msg_nsim_cross_connect_enable_disable>(Connection &con)
{
  vapi_msg_nsim_cross_connect_enable_disable* result = vapi_alloc_nsim_cross_connect_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsim_cross_connect_enable_disable>;

template class Request<vapi_msg_nsim_cross_connect_enable_disable, vapi_msg_nsim_cross_connect_enable_disable_reply>;

using Nsim_cross_connect_enable_disable = Request<vapi_msg_nsim_cross_connect_enable_disable, vapi_msg_nsim_cross_connect_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nsim_cross_connect_enable_disable_reply>(vapi_msg_nsim_cross_connect_enable_disable_reply *msg)
{
  vapi_msg_nsim_cross_connect_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_cross_connect_enable_disable_reply>(vapi_msg_nsim_cross_connect_enable_disable_reply *msg)
{
  vapi_msg_nsim_cross_connect_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_cross_connect_enable_disable_reply>()
{
  return ::vapi_msg_id_nsim_cross_connect_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_cross_connect_enable_disable_reply>>()
{
  return ::vapi_msg_id_nsim_cross_connect_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_cross_connect_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_cross_connect_enable_disable_reply>(vapi_msg_id_nsim_cross_connect_enable_disable_reply);
}

template class Msg<vapi_msg_nsim_cross_connect_enable_disable_reply>;

using Nsim_cross_connect_enable_disable_reply = Msg<vapi_msg_nsim_cross_connect_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nsim_output_feature_enable_disable>(vapi_msg_nsim_output_feature_enable_disable *msg)
{
  vapi_msg_nsim_output_feature_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_output_feature_enable_disable>(vapi_msg_nsim_output_feature_enable_disable *msg)
{
  vapi_msg_nsim_output_feature_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_output_feature_enable_disable>()
{
  return ::vapi_msg_id_nsim_output_feature_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_output_feature_enable_disable>>()
{
  return ::vapi_msg_id_nsim_output_feature_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_output_feature_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_output_feature_enable_disable>(vapi_msg_id_nsim_output_feature_enable_disable);
}

template <> inline vapi_msg_nsim_output_feature_enable_disable* vapi_alloc<vapi_msg_nsim_output_feature_enable_disable>(Connection &con)
{
  vapi_msg_nsim_output_feature_enable_disable* result = vapi_alloc_nsim_output_feature_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsim_output_feature_enable_disable>;

template class Request<vapi_msg_nsim_output_feature_enable_disable, vapi_msg_nsim_output_feature_enable_disable_reply>;

using Nsim_output_feature_enable_disable = Request<vapi_msg_nsim_output_feature_enable_disable, vapi_msg_nsim_output_feature_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nsim_output_feature_enable_disable_reply>(vapi_msg_nsim_output_feature_enable_disable_reply *msg)
{
  vapi_msg_nsim_output_feature_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_output_feature_enable_disable_reply>(vapi_msg_nsim_output_feature_enable_disable_reply *msg)
{
  vapi_msg_nsim_output_feature_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_output_feature_enable_disable_reply>()
{
  return ::vapi_msg_id_nsim_output_feature_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_output_feature_enable_disable_reply>>()
{
  return ::vapi_msg_id_nsim_output_feature_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_output_feature_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_output_feature_enable_disable_reply>(vapi_msg_id_nsim_output_feature_enable_disable_reply);
}

template class Msg<vapi_msg_nsim_output_feature_enable_disable_reply>;

using Nsim_output_feature_enable_disable_reply = Msg<vapi_msg_nsim_output_feature_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nsim_configure>(vapi_msg_nsim_configure *msg)
{
  vapi_msg_nsim_configure_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_configure>(vapi_msg_nsim_configure *msg)
{
  vapi_msg_nsim_configure_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_configure>()
{
  return ::vapi_msg_id_nsim_configure; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_configure>>()
{
  return ::vapi_msg_id_nsim_configure; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_configure()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_configure>(vapi_msg_id_nsim_configure);
}

template <> inline vapi_msg_nsim_configure* vapi_alloc<vapi_msg_nsim_configure>(Connection &con)
{
  vapi_msg_nsim_configure* result = vapi_alloc_nsim_configure(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsim_configure>;

template class Request<vapi_msg_nsim_configure, vapi_msg_nsim_configure_reply>;

using Nsim_configure = Request<vapi_msg_nsim_configure, vapi_msg_nsim_configure_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nsim_configure_reply>(vapi_msg_nsim_configure_reply *msg)
{
  vapi_msg_nsim_configure_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_configure_reply>(vapi_msg_nsim_configure_reply *msg)
{
  vapi_msg_nsim_configure_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_configure_reply>()
{
  return ::vapi_msg_id_nsim_configure_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_configure_reply>>()
{
  return ::vapi_msg_id_nsim_configure_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_configure_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_configure_reply>(vapi_msg_id_nsim_configure_reply);
}

template class Msg<vapi_msg_nsim_configure_reply>;

using Nsim_configure_reply = Msg<vapi_msg_nsim_configure_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nsim_configure2>(vapi_msg_nsim_configure2 *msg)
{
  vapi_msg_nsim_configure2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_configure2>(vapi_msg_nsim_configure2 *msg)
{
  vapi_msg_nsim_configure2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_configure2>()
{
  return ::vapi_msg_id_nsim_configure2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_configure2>>()
{
  return ::vapi_msg_id_nsim_configure2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_configure2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_configure2>(vapi_msg_id_nsim_configure2);
}

template <> inline vapi_msg_nsim_configure2* vapi_alloc<vapi_msg_nsim_configure2>(Connection &con)
{
  vapi_msg_nsim_configure2* result = vapi_alloc_nsim_configure2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsim_configure2>;

template class Request<vapi_msg_nsim_configure2, vapi_msg_nsim_configure2_reply>;

using Nsim_configure2 = Request<vapi_msg_nsim_configure2, vapi_msg_nsim_configure2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nsim_configure2_reply>(vapi_msg_nsim_configure2_reply *msg)
{
  vapi_msg_nsim_configure2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsim_configure2_reply>(vapi_msg_nsim_configure2_reply *msg)
{
  vapi_msg_nsim_configure2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsim_configure2_reply>()
{
  return ::vapi_msg_id_nsim_configure2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsim_configure2_reply>>()
{
  return ::vapi_msg_id_nsim_configure2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsim_configure2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsim_configure2_reply>(vapi_msg_id_nsim_configure2_reply);
}

template class Msg<vapi_msg_nsim_configure2_reply>;

using Nsim_configure2_reply = Msg<vapi_msg_nsim_configure2_reply>;
}
#endif
