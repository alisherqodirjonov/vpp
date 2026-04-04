#ifndef __included_hpp_feature_api_json
#define __included_hpp_feature_api_json

#include <vapi/vapi.hpp>
#include <vapi/feature.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_feature_enable_disable>(vapi_msg_feature_enable_disable *msg)
{
  vapi_msg_feature_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_feature_enable_disable>(vapi_msg_feature_enable_disable *msg)
{
  vapi_msg_feature_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_feature_enable_disable>()
{
  return ::vapi_msg_id_feature_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_feature_enable_disable>>()
{
  return ::vapi_msg_id_feature_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_feature_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_feature_enable_disable>(vapi_msg_id_feature_enable_disable);
}

template <> inline vapi_msg_feature_enable_disable* vapi_alloc<vapi_msg_feature_enable_disable>(Connection &con)
{
  vapi_msg_feature_enable_disable* result = vapi_alloc_feature_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_feature_enable_disable>;

template class Request<vapi_msg_feature_enable_disable, vapi_msg_feature_enable_disable_reply>;

using Feature_enable_disable = Request<vapi_msg_feature_enable_disable, vapi_msg_feature_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_feature_enable_disable_reply>(vapi_msg_feature_enable_disable_reply *msg)
{
  vapi_msg_feature_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_feature_enable_disable_reply>(vapi_msg_feature_enable_disable_reply *msg)
{
  vapi_msg_feature_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_feature_enable_disable_reply>()
{
  return ::vapi_msg_id_feature_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_feature_enable_disable_reply>>()
{
  return ::vapi_msg_id_feature_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_feature_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_feature_enable_disable_reply>(vapi_msg_id_feature_enable_disable_reply);
}

template class Msg<vapi_msg_feature_enable_disable_reply>;

using Feature_enable_disable_reply = Msg<vapi_msg_feature_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_feature_is_enabled>(vapi_msg_feature_is_enabled *msg)
{
  vapi_msg_feature_is_enabled_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_feature_is_enabled>(vapi_msg_feature_is_enabled *msg)
{
  vapi_msg_feature_is_enabled_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_feature_is_enabled>()
{
  return ::vapi_msg_id_feature_is_enabled; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_feature_is_enabled>>()
{
  return ::vapi_msg_id_feature_is_enabled; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_feature_is_enabled()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_feature_is_enabled>(vapi_msg_id_feature_is_enabled);
}

template <> inline vapi_msg_feature_is_enabled* vapi_alloc<vapi_msg_feature_is_enabled>(Connection &con)
{
  vapi_msg_feature_is_enabled* result = vapi_alloc_feature_is_enabled(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_feature_is_enabled>;

template class Request<vapi_msg_feature_is_enabled, vapi_msg_feature_is_enabled_reply>;

using Feature_is_enabled = Request<vapi_msg_feature_is_enabled, vapi_msg_feature_is_enabled_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_feature_is_enabled_reply>(vapi_msg_feature_is_enabled_reply *msg)
{
  vapi_msg_feature_is_enabled_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_feature_is_enabled_reply>(vapi_msg_feature_is_enabled_reply *msg)
{
  vapi_msg_feature_is_enabled_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_feature_is_enabled_reply>()
{
  return ::vapi_msg_id_feature_is_enabled_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_feature_is_enabled_reply>>()
{
  return ::vapi_msg_id_feature_is_enabled_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_feature_is_enabled_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_feature_is_enabled_reply>(vapi_msg_id_feature_is_enabled_reply);
}

template class Msg<vapi_msg_feature_is_enabled_reply>;

using Feature_is_enabled_reply = Msg<vapi_msg_feature_is_enabled_reply>;
}
#endif
