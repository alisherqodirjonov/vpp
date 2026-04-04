#ifndef __included_hpp_trace_api_json
#define __included_hpp_trace_api_json

#include <vapi/vapi.hpp>
#include <vapi/trace.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_trace_profile_add>(vapi_msg_trace_profile_add *msg)
{
  vapi_msg_trace_profile_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_profile_add>(vapi_msg_trace_profile_add *msg)
{
  vapi_msg_trace_profile_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_profile_add>()
{
  return ::vapi_msg_id_trace_profile_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_profile_add>>()
{
  return ::vapi_msg_id_trace_profile_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_profile_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_profile_add>(vapi_msg_id_trace_profile_add);
}

template <> inline vapi_msg_trace_profile_add* vapi_alloc<vapi_msg_trace_profile_add>(Connection &con)
{
  vapi_msg_trace_profile_add* result = vapi_alloc_trace_profile_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_profile_add>;

template class Request<vapi_msg_trace_profile_add, vapi_msg_trace_profile_add_reply>;

using Trace_profile_add = Request<vapi_msg_trace_profile_add, vapi_msg_trace_profile_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_profile_add_reply>(vapi_msg_trace_profile_add_reply *msg)
{
  vapi_msg_trace_profile_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_profile_add_reply>(vapi_msg_trace_profile_add_reply *msg)
{
  vapi_msg_trace_profile_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_profile_add_reply>()
{
  return ::vapi_msg_id_trace_profile_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_profile_add_reply>>()
{
  return ::vapi_msg_id_trace_profile_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_profile_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_profile_add_reply>(vapi_msg_id_trace_profile_add_reply);
}

template class Msg<vapi_msg_trace_profile_add_reply>;

using Trace_profile_add_reply = Msg<vapi_msg_trace_profile_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_profile_del>(vapi_msg_trace_profile_del *msg)
{
  vapi_msg_trace_profile_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_profile_del>(vapi_msg_trace_profile_del *msg)
{
  vapi_msg_trace_profile_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_profile_del>()
{
  return ::vapi_msg_id_trace_profile_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_profile_del>>()
{
  return ::vapi_msg_id_trace_profile_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_profile_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_profile_del>(vapi_msg_id_trace_profile_del);
}

template <> inline vapi_msg_trace_profile_del* vapi_alloc<vapi_msg_trace_profile_del>(Connection &con)
{
  vapi_msg_trace_profile_del* result = vapi_alloc_trace_profile_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_profile_del>;

template class Request<vapi_msg_trace_profile_del, vapi_msg_trace_profile_del_reply>;

using Trace_profile_del = Request<vapi_msg_trace_profile_del, vapi_msg_trace_profile_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_profile_del_reply>(vapi_msg_trace_profile_del_reply *msg)
{
  vapi_msg_trace_profile_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_profile_del_reply>(vapi_msg_trace_profile_del_reply *msg)
{
  vapi_msg_trace_profile_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_profile_del_reply>()
{
  return ::vapi_msg_id_trace_profile_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_profile_del_reply>>()
{
  return ::vapi_msg_id_trace_profile_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_profile_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_profile_del_reply>(vapi_msg_id_trace_profile_del_reply);
}

template class Msg<vapi_msg_trace_profile_del_reply>;

using Trace_profile_del_reply = Msg<vapi_msg_trace_profile_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_trace_profile_show_config>(vapi_msg_trace_profile_show_config *msg)
{
  vapi_msg_trace_profile_show_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_profile_show_config>(vapi_msg_trace_profile_show_config *msg)
{
  vapi_msg_trace_profile_show_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_profile_show_config>()
{
  return ::vapi_msg_id_trace_profile_show_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_profile_show_config>>()
{
  return ::vapi_msg_id_trace_profile_show_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_profile_show_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_profile_show_config>(vapi_msg_id_trace_profile_show_config);
}

template <> inline vapi_msg_trace_profile_show_config* vapi_alloc<vapi_msg_trace_profile_show_config>(Connection &con)
{
  vapi_msg_trace_profile_show_config* result = vapi_alloc_trace_profile_show_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_trace_profile_show_config>;

template class Request<vapi_msg_trace_profile_show_config, vapi_msg_trace_profile_show_config_reply>;

using Trace_profile_show_config = Request<vapi_msg_trace_profile_show_config, vapi_msg_trace_profile_show_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_trace_profile_show_config_reply>(vapi_msg_trace_profile_show_config_reply *msg)
{
  vapi_msg_trace_profile_show_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_trace_profile_show_config_reply>(vapi_msg_trace_profile_show_config_reply *msg)
{
  vapi_msg_trace_profile_show_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_trace_profile_show_config_reply>()
{
  return ::vapi_msg_id_trace_profile_show_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_trace_profile_show_config_reply>>()
{
  return ::vapi_msg_id_trace_profile_show_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_trace_profile_show_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_trace_profile_show_config_reply>(vapi_msg_id_trace_profile_show_config_reply);
}

template class Msg<vapi_msg_trace_profile_show_config_reply>;

using Trace_profile_show_config_reply = Msg<vapi_msg_trace_profile_show_config_reply>;
}
#endif
