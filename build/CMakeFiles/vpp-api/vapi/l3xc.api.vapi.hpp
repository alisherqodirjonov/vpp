#ifndef __included_hpp_l3xc_api_json
#define __included_hpp_l3xc_api_json

#include <vapi/vapi.hpp>
#include <vapi/l3xc.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_l3xc_plugin_get_version>(vapi_msg_l3xc_plugin_get_version *msg)
{
  vapi_msg_l3xc_plugin_get_version_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_plugin_get_version>(vapi_msg_l3xc_plugin_get_version *msg)
{
  vapi_msg_l3xc_plugin_get_version_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_plugin_get_version>()
{
  return ::vapi_msg_id_l3xc_plugin_get_version; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_plugin_get_version>>()
{
  return ::vapi_msg_id_l3xc_plugin_get_version; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_plugin_get_version()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_plugin_get_version>(vapi_msg_id_l3xc_plugin_get_version);
}

template <> inline vapi_msg_l3xc_plugin_get_version* vapi_alloc<vapi_msg_l3xc_plugin_get_version>(Connection &con)
{
  vapi_msg_l3xc_plugin_get_version* result = vapi_alloc_l3xc_plugin_get_version(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l3xc_plugin_get_version>;

template class Request<vapi_msg_l3xc_plugin_get_version, vapi_msg_l3xc_plugin_get_version_reply>;

using L3xc_plugin_get_version = Request<vapi_msg_l3xc_plugin_get_version, vapi_msg_l3xc_plugin_get_version_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l3xc_plugin_get_version_reply>(vapi_msg_l3xc_plugin_get_version_reply *msg)
{
  vapi_msg_l3xc_plugin_get_version_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_plugin_get_version_reply>(vapi_msg_l3xc_plugin_get_version_reply *msg)
{
  vapi_msg_l3xc_plugin_get_version_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_plugin_get_version_reply>()
{
  return ::vapi_msg_id_l3xc_plugin_get_version_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_plugin_get_version_reply>>()
{
  return ::vapi_msg_id_l3xc_plugin_get_version_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_plugin_get_version_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_plugin_get_version_reply>(vapi_msg_id_l3xc_plugin_get_version_reply);
}

template class Msg<vapi_msg_l3xc_plugin_get_version_reply>;

using L3xc_plugin_get_version_reply = Msg<vapi_msg_l3xc_plugin_get_version_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l3xc_update>(vapi_msg_l3xc_update *msg)
{
  vapi_msg_l3xc_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_update>(vapi_msg_l3xc_update *msg)
{
  vapi_msg_l3xc_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_update>()
{
  return ::vapi_msg_id_l3xc_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_update>>()
{
  return ::vapi_msg_id_l3xc_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_update>(vapi_msg_id_l3xc_update);
}

template <> inline vapi_msg_l3xc_update* vapi_alloc<vapi_msg_l3xc_update, size_t>(Connection &con, size_t l3xc_paths_array_size)
{
  vapi_msg_l3xc_update* result = vapi_alloc_l3xc_update(con.vapi_ctx, l3xc_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l3xc_update>;

template class Request<vapi_msg_l3xc_update, vapi_msg_l3xc_update_reply, size_t>;

using L3xc_update = Request<vapi_msg_l3xc_update, vapi_msg_l3xc_update_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_l3xc_update_reply>(vapi_msg_l3xc_update_reply *msg)
{
  vapi_msg_l3xc_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_update_reply>(vapi_msg_l3xc_update_reply *msg)
{
  vapi_msg_l3xc_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_update_reply>()
{
  return ::vapi_msg_id_l3xc_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_update_reply>>()
{
  return ::vapi_msg_id_l3xc_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_update_reply>(vapi_msg_id_l3xc_update_reply);
}

template class Msg<vapi_msg_l3xc_update_reply>;

using L3xc_update_reply = Msg<vapi_msg_l3xc_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l3xc_del>(vapi_msg_l3xc_del *msg)
{
  vapi_msg_l3xc_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_del>(vapi_msg_l3xc_del *msg)
{
  vapi_msg_l3xc_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_del>()
{
  return ::vapi_msg_id_l3xc_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_del>>()
{
  return ::vapi_msg_id_l3xc_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_del>(vapi_msg_id_l3xc_del);
}

template <> inline vapi_msg_l3xc_del* vapi_alloc<vapi_msg_l3xc_del>(Connection &con)
{
  vapi_msg_l3xc_del* result = vapi_alloc_l3xc_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l3xc_del>;

template class Request<vapi_msg_l3xc_del, vapi_msg_l3xc_del_reply>;

using L3xc_del = Request<vapi_msg_l3xc_del, vapi_msg_l3xc_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l3xc_del_reply>(vapi_msg_l3xc_del_reply *msg)
{
  vapi_msg_l3xc_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_del_reply>(vapi_msg_l3xc_del_reply *msg)
{
  vapi_msg_l3xc_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_del_reply>()
{
  return ::vapi_msg_id_l3xc_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_del_reply>>()
{
  return ::vapi_msg_id_l3xc_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_del_reply>(vapi_msg_id_l3xc_del_reply);
}

template class Msg<vapi_msg_l3xc_del_reply>;

using L3xc_del_reply = Msg<vapi_msg_l3xc_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l3xc_dump>(vapi_msg_l3xc_dump *msg)
{
  vapi_msg_l3xc_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_dump>(vapi_msg_l3xc_dump *msg)
{
  vapi_msg_l3xc_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_dump>()
{
  return ::vapi_msg_id_l3xc_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_dump>>()
{
  return ::vapi_msg_id_l3xc_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_dump>(vapi_msg_id_l3xc_dump);
}

template <> inline vapi_msg_l3xc_dump* vapi_alloc<vapi_msg_l3xc_dump>(Connection &con)
{
  vapi_msg_l3xc_dump* result = vapi_alloc_l3xc_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l3xc_dump>;

template class Dump<vapi_msg_l3xc_dump, vapi_msg_l3xc_details>;

using L3xc_dump = Dump<vapi_msg_l3xc_dump, vapi_msg_l3xc_details>;

template <> inline void vapi_swap_to_be<vapi_msg_l3xc_details>(vapi_msg_l3xc_details *msg)
{
  vapi_msg_l3xc_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l3xc_details>(vapi_msg_l3xc_details *msg)
{
  vapi_msg_l3xc_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l3xc_details>()
{
  return ::vapi_msg_id_l3xc_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l3xc_details>>()
{
  return ::vapi_msg_id_l3xc_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l3xc_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l3xc_details>(vapi_msg_id_l3xc_details);
}

template class Msg<vapi_msg_l3xc_details>;

using L3xc_details = Msg<vapi_msg_l3xc_details>;
}
#endif
