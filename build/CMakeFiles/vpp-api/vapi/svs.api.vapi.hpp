#ifndef __included_hpp_svs_api_json
#define __included_hpp_svs_api_json

#include <vapi/vapi.hpp>
#include <vapi/svs.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_svs_plugin_get_version>(vapi_msg_svs_plugin_get_version *msg)
{
  vapi_msg_svs_plugin_get_version_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_plugin_get_version>(vapi_msg_svs_plugin_get_version *msg)
{
  vapi_msg_svs_plugin_get_version_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_plugin_get_version>()
{
  return ::vapi_msg_id_svs_plugin_get_version; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_plugin_get_version>>()
{
  return ::vapi_msg_id_svs_plugin_get_version; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_plugin_get_version()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_plugin_get_version>(vapi_msg_id_svs_plugin_get_version);
}

template <> inline vapi_msg_svs_plugin_get_version* vapi_alloc<vapi_msg_svs_plugin_get_version>(Connection &con)
{
  vapi_msg_svs_plugin_get_version* result = vapi_alloc_svs_plugin_get_version(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_svs_plugin_get_version>;

template class Request<vapi_msg_svs_plugin_get_version, vapi_msg_svs_plugin_get_version_reply>;

using Svs_plugin_get_version = Request<vapi_msg_svs_plugin_get_version, vapi_msg_svs_plugin_get_version_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_svs_plugin_get_version_reply>(vapi_msg_svs_plugin_get_version_reply *msg)
{
  vapi_msg_svs_plugin_get_version_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_plugin_get_version_reply>(vapi_msg_svs_plugin_get_version_reply *msg)
{
  vapi_msg_svs_plugin_get_version_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_plugin_get_version_reply>()
{
  return ::vapi_msg_id_svs_plugin_get_version_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_plugin_get_version_reply>>()
{
  return ::vapi_msg_id_svs_plugin_get_version_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_plugin_get_version_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_plugin_get_version_reply>(vapi_msg_id_svs_plugin_get_version_reply);
}

template class Msg<vapi_msg_svs_plugin_get_version_reply>;

using Svs_plugin_get_version_reply = Msg<vapi_msg_svs_plugin_get_version_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_svs_table_add_del>(vapi_msg_svs_table_add_del *msg)
{
  vapi_msg_svs_table_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_table_add_del>(vapi_msg_svs_table_add_del *msg)
{
  vapi_msg_svs_table_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_table_add_del>()
{
  return ::vapi_msg_id_svs_table_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_table_add_del>>()
{
  return ::vapi_msg_id_svs_table_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_table_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_table_add_del>(vapi_msg_id_svs_table_add_del);
}

template <> inline vapi_msg_svs_table_add_del* vapi_alloc<vapi_msg_svs_table_add_del>(Connection &con)
{
  vapi_msg_svs_table_add_del* result = vapi_alloc_svs_table_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_svs_table_add_del>;

template class Request<vapi_msg_svs_table_add_del, vapi_msg_svs_table_add_del_reply>;

using Svs_table_add_del = Request<vapi_msg_svs_table_add_del, vapi_msg_svs_table_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_svs_table_add_del_reply>(vapi_msg_svs_table_add_del_reply *msg)
{
  vapi_msg_svs_table_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_table_add_del_reply>(vapi_msg_svs_table_add_del_reply *msg)
{
  vapi_msg_svs_table_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_table_add_del_reply>()
{
  return ::vapi_msg_id_svs_table_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_table_add_del_reply>>()
{
  return ::vapi_msg_id_svs_table_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_table_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_table_add_del_reply>(vapi_msg_id_svs_table_add_del_reply);
}

template class Msg<vapi_msg_svs_table_add_del_reply>;

using Svs_table_add_del_reply = Msg<vapi_msg_svs_table_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_svs_route_add_del>(vapi_msg_svs_route_add_del *msg)
{
  vapi_msg_svs_route_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_route_add_del>(vapi_msg_svs_route_add_del *msg)
{
  vapi_msg_svs_route_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_route_add_del>()
{
  return ::vapi_msg_id_svs_route_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_route_add_del>>()
{
  return ::vapi_msg_id_svs_route_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_route_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_route_add_del>(vapi_msg_id_svs_route_add_del);
}

template <> inline vapi_msg_svs_route_add_del* vapi_alloc<vapi_msg_svs_route_add_del>(Connection &con)
{
  vapi_msg_svs_route_add_del* result = vapi_alloc_svs_route_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_svs_route_add_del>;

template class Request<vapi_msg_svs_route_add_del, vapi_msg_svs_route_add_del_reply>;

using Svs_route_add_del = Request<vapi_msg_svs_route_add_del, vapi_msg_svs_route_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_svs_route_add_del_reply>(vapi_msg_svs_route_add_del_reply *msg)
{
  vapi_msg_svs_route_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_route_add_del_reply>(vapi_msg_svs_route_add_del_reply *msg)
{
  vapi_msg_svs_route_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_route_add_del_reply>()
{
  return ::vapi_msg_id_svs_route_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_route_add_del_reply>>()
{
  return ::vapi_msg_id_svs_route_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_route_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_route_add_del_reply>(vapi_msg_id_svs_route_add_del_reply);
}

template class Msg<vapi_msg_svs_route_add_del_reply>;

using Svs_route_add_del_reply = Msg<vapi_msg_svs_route_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_svs_enable_disable>(vapi_msg_svs_enable_disable *msg)
{
  vapi_msg_svs_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_enable_disable>(vapi_msg_svs_enable_disable *msg)
{
  vapi_msg_svs_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_enable_disable>()
{
  return ::vapi_msg_id_svs_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_enable_disable>>()
{
  return ::vapi_msg_id_svs_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_enable_disable>(vapi_msg_id_svs_enable_disable);
}

template <> inline vapi_msg_svs_enable_disable* vapi_alloc<vapi_msg_svs_enable_disable>(Connection &con)
{
  vapi_msg_svs_enable_disable* result = vapi_alloc_svs_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_svs_enable_disable>;

template class Request<vapi_msg_svs_enable_disable, vapi_msg_svs_enable_disable_reply>;

using Svs_enable_disable = Request<vapi_msg_svs_enable_disable, vapi_msg_svs_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_svs_enable_disable_reply>(vapi_msg_svs_enable_disable_reply *msg)
{
  vapi_msg_svs_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_enable_disable_reply>(vapi_msg_svs_enable_disable_reply *msg)
{
  vapi_msg_svs_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_enable_disable_reply>()
{
  return ::vapi_msg_id_svs_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_enable_disable_reply>>()
{
  return ::vapi_msg_id_svs_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_enable_disable_reply>(vapi_msg_id_svs_enable_disable_reply);
}

template class Msg<vapi_msg_svs_enable_disable_reply>;

using Svs_enable_disable_reply = Msg<vapi_msg_svs_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_svs_dump>(vapi_msg_svs_dump *msg)
{
  vapi_msg_svs_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_dump>(vapi_msg_svs_dump *msg)
{
  vapi_msg_svs_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_dump>()
{
  return ::vapi_msg_id_svs_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_dump>>()
{
  return ::vapi_msg_id_svs_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_dump>(vapi_msg_id_svs_dump);
}

template <> inline vapi_msg_svs_dump* vapi_alloc<vapi_msg_svs_dump>(Connection &con)
{
  vapi_msg_svs_dump* result = vapi_alloc_svs_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_svs_dump>;

template class Dump<vapi_msg_svs_dump, vapi_msg_svs_details>;

using Svs_dump = Dump<vapi_msg_svs_dump, vapi_msg_svs_details>;

template <> inline void vapi_swap_to_be<vapi_msg_svs_details>(vapi_msg_svs_details *msg)
{
  vapi_msg_svs_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_svs_details>(vapi_msg_svs_details *msg)
{
  vapi_msg_svs_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_svs_details>()
{
  return ::vapi_msg_id_svs_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_svs_details>>()
{
  return ::vapi_msg_id_svs_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_svs_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_svs_details>(vapi_msg_id_svs_details);
}

template class Msg<vapi_msg_svs_details>;

using Svs_details = Msg<vapi_msg_svs_details>;
}
#endif
