#ifndef __included_hpp_auto_sdl_api_json
#define __included_hpp_auto_sdl_api_json

#include <vapi/vapi.hpp>
#include <vapi/auto_sdl.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_auto_sdl_config>(vapi_msg_auto_sdl_config *msg)
{
  vapi_msg_auto_sdl_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_auto_sdl_config>(vapi_msg_auto_sdl_config *msg)
{
  vapi_msg_auto_sdl_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_auto_sdl_config>()
{
  return ::vapi_msg_id_auto_sdl_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_auto_sdl_config>>()
{
  return ::vapi_msg_id_auto_sdl_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_auto_sdl_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_auto_sdl_config>(vapi_msg_id_auto_sdl_config);
}

template <> inline vapi_msg_auto_sdl_config* vapi_alloc<vapi_msg_auto_sdl_config>(Connection &con)
{
  vapi_msg_auto_sdl_config* result = vapi_alloc_auto_sdl_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_auto_sdl_config>;

template class Request<vapi_msg_auto_sdl_config, vapi_msg_auto_sdl_config_reply>;

using Auto_sdl_config = Request<vapi_msg_auto_sdl_config, vapi_msg_auto_sdl_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_auto_sdl_config_reply>(vapi_msg_auto_sdl_config_reply *msg)
{
  vapi_msg_auto_sdl_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_auto_sdl_config_reply>(vapi_msg_auto_sdl_config_reply *msg)
{
  vapi_msg_auto_sdl_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_auto_sdl_config_reply>()
{
  return ::vapi_msg_id_auto_sdl_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_auto_sdl_config_reply>>()
{
  return ::vapi_msg_id_auto_sdl_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_auto_sdl_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_auto_sdl_config_reply>(vapi_msg_id_auto_sdl_config_reply);
}

template class Msg<vapi_msg_auto_sdl_config_reply>;

using Auto_sdl_config_reply = Msg<vapi_msg_auto_sdl_config_reply>;
}
#endif
