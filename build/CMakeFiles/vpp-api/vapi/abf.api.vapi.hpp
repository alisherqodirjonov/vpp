#ifndef __included_hpp_abf_api_json
#define __included_hpp_abf_api_json

#include <vapi/vapi.hpp>
#include <vapi/abf.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_abf_plugin_get_version>(vapi_msg_abf_plugin_get_version *msg)
{
  vapi_msg_abf_plugin_get_version_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_plugin_get_version>(vapi_msg_abf_plugin_get_version *msg)
{
  vapi_msg_abf_plugin_get_version_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_plugin_get_version>()
{
  return ::vapi_msg_id_abf_plugin_get_version; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_plugin_get_version>>()
{
  return ::vapi_msg_id_abf_plugin_get_version; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_plugin_get_version()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_plugin_get_version>(vapi_msg_id_abf_plugin_get_version);
}

template <> inline vapi_msg_abf_plugin_get_version* vapi_alloc<vapi_msg_abf_plugin_get_version>(Connection &con)
{
  vapi_msg_abf_plugin_get_version* result = vapi_alloc_abf_plugin_get_version(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_abf_plugin_get_version>;

template class Request<vapi_msg_abf_plugin_get_version, vapi_msg_abf_plugin_get_version_reply>;

using Abf_plugin_get_version = Request<vapi_msg_abf_plugin_get_version, vapi_msg_abf_plugin_get_version_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_abf_plugin_get_version_reply>(vapi_msg_abf_plugin_get_version_reply *msg)
{
  vapi_msg_abf_plugin_get_version_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_plugin_get_version_reply>(vapi_msg_abf_plugin_get_version_reply *msg)
{
  vapi_msg_abf_plugin_get_version_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_plugin_get_version_reply>()
{
  return ::vapi_msg_id_abf_plugin_get_version_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_plugin_get_version_reply>>()
{
  return ::vapi_msg_id_abf_plugin_get_version_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_plugin_get_version_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_plugin_get_version_reply>(vapi_msg_id_abf_plugin_get_version_reply);
}

template class Msg<vapi_msg_abf_plugin_get_version_reply>;

using Abf_plugin_get_version_reply = Msg<vapi_msg_abf_plugin_get_version_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_abf_policy_add_del>(vapi_msg_abf_policy_add_del *msg)
{
  vapi_msg_abf_policy_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_policy_add_del>(vapi_msg_abf_policy_add_del *msg)
{
  vapi_msg_abf_policy_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_policy_add_del>()
{
  return ::vapi_msg_id_abf_policy_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_policy_add_del>>()
{
  return ::vapi_msg_id_abf_policy_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_policy_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_policy_add_del>(vapi_msg_id_abf_policy_add_del);
}

template <> inline vapi_msg_abf_policy_add_del* vapi_alloc<vapi_msg_abf_policy_add_del, size_t>(Connection &con, size_t policy_paths_array_size)
{
  vapi_msg_abf_policy_add_del* result = vapi_alloc_abf_policy_add_del(con.vapi_ctx, policy_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_abf_policy_add_del>;

template class Request<vapi_msg_abf_policy_add_del, vapi_msg_abf_policy_add_del_reply, size_t>;

using Abf_policy_add_del = Request<vapi_msg_abf_policy_add_del, vapi_msg_abf_policy_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_abf_policy_add_del_reply>(vapi_msg_abf_policy_add_del_reply *msg)
{
  vapi_msg_abf_policy_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_policy_add_del_reply>(vapi_msg_abf_policy_add_del_reply *msg)
{
  vapi_msg_abf_policy_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_policy_add_del_reply>()
{
  return ::vapi_msg_id_abf_policy_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_policy_add_del_reply>>()
{
  return ::vapi_msg_id_abf_policy_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_policy_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_policy_add_del_reply>(vapi_msg_id_abf_policy_add_del_reply);
}

template class Msg<vapi_msg_abf_policy_add_del_reply>;

using Abf_policy_add_del_reply = Msg<vapi_msg_abf_policy_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_abf_policy_details>(vapi_msg_abf_policy_details *msg)
{
  vapi_msg_abf_policy_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_policy_details>(vapi_msg_abf_policy_details *msg)
{
  vapi_msg_abf_policy_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_policy_details>()
{
  return ::vapi_msg_id_abf_policy_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_policy_details>>()
{
  return ::vapi_msg_id_abf_policy_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_policy_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_policy_details>(vapi_msg_id_abf_policy_details);
}

template class Msg<vapi_msg_abf_policy_details>;

using Abf_policy_details = Msg<vapi_msg_abf_policy_details>;
template <> inline void vapi_swap_to_be<vapi_msg_abf_policy_dump>(vapi_msg_abf_policy_dump *msg)
{
  vapi_msg_abf_policy_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_policy_dump>(vapi_msg_abf_policy_dump *msg)
{
  vapi_msg_abf_policy_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_policy_dump>()
{
  return ::vapi_msg_id_abf_policy_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_policy_dump>>()
{
  return ::vapi_msg_id_abf_policy_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_policy_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_policy_dump>(vapi_msg_id_abf_policy_dump);
}

template <> inline vapi_msg_abf_policy_dump* vapi_alloc<vapi_msg_abf_policy_dump>(Connection &con)
{
  vapi_msg_abf_policy_dump* result = vapi_alloc_abf_policy_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_abf_policy_dump>;

template class Dump<vapi_msg_abf_policy_dump, vapi_msg_abf_policy_details>;

using Abf_policy_dump = Dump<vapi_msg_abf_policy_dump, vapi_msg_abf_policy_details>;

template <> inline void vapi_swap_to_be<vapi_msg_abf_itf_attach_add_del>(vapi_msg_abf_itf_attach_add_del *msg)
{
  vapi_msg_abf_itf_attach_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_itf_attach_add_del>(vapi_msg_abf_itf_attach_add_del *msg)
{
  vapi_msg_abf_itf_attach_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_itf_attach_add_del>()
{
  return ::vapi_msg_id_abf_itf_attach_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_itf_attach_add_del>>()
{
  return ::vapi_msg_id_abf_itf_attach_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_itf_attach_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_itf_attach_add_del>(vapi_msg_id_abf_itf_attach_add_del);
}

template <> inline vapi_msg_abf_itf_attach_add_del* vapi_alloc<vapi_msg_abf_itf_attach_add_del>(Connection &con)
{
  vapi_msg_abf_itf_attach_add_del* result = vapi_alloc_abf_itf_attach_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_abf_itf_attach_add_del>;

template class Request<vapi_msg_abf_itf_attach_add_del, vapi_msg_abf_itf_attach_add_del_reply>;

using Abf_itf_attach_add_del = Request<vapi_msg_abf_itf_attach_add_del, vapi_msg_abf_itf_attach_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_abf_itf_attach_add_del_reply>(vapi_msg_abf_itf_attach_add_del_reply *msg)
{
  vapi_msg_abf_itf_attach_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_itf_attach_add_del_reply>(vapi_msg_abf_itf_attach_add_del_reply *msg)
{
  vapi_msg_abf_itf_attach_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_itf_attach_add_del_reply>()
{
  return ::vapi_msg_id_abf_itf_attach_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_itf_attach_add_del_reply>>()
{
  return ::vapi_msg_id_abf_itf_attach_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_itf_attach_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_itf_attach_add_del_reply>(vapi_msg_id_abf_itf_attach_add_del_reply);
}

template class Msg<vapi_msg_abf_itf_attach_add_del_reply>;

using Abf_itf_attach_add_del_reply = Msg<vapi_msg_abf_itf_attach_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_abf_itf_attach_details>(vapi_msg_abf_itf_attach_details *msg)
{
  vapi_msg_abf_itf_attach_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_itf_attach_details>(vapi_msg_abf_itf_attach_details *msg)
{
  vapi_msg_abf_itf_attach_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_itf_attach_details>()
{
  return ::vapi_msg_id_abf_itf_attach_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_itf_attach_details>>()
{
  return ::vapi_msg_id_abf_itf_attach_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_itf_attach_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_itf_attach_details>(vapi_msg_id_abf_itf_attach_details);
}

template class Msg<vapi_msg_abf_itf_attach_details>;

using Abf_itf_attach_details = Msg<vapi_msg_abf_itf_attach_details>;
template <> inline void vapi_swap_to_be<vapi_msg_abf_itf_attach_dump>(vapi_msg_abf_itf_attach_dump *msg)
{
  vapi_msg_abf_itf_attach_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_abf_itf_attach_dump>(vapi_msg_abf_itf_attach_dump *msg)
{
  vapi_msg_abf_itf_attach_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_abf_itf_attach_dump>()
{
  return ::vapi_msg_id_abf_itf_attach_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_abf_itf_attach_dump>>()
{
  return ::vapi_msg_id_abf_itf_attach_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_abf_itf_attach_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_abf_itf_attach_dump>(vapi_msg_id_abf_itf_attach_dump);
}

template <> inline vapi_msg_abf_itf_attach_dump* vapi_alloc<vapi_msg_abf_itf_attach_dump>(Connection &con)
{
  vapi_msg_abf_itf_attach_dump* result = vapi_alloc_abf_itf_attach_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_abf_itf_attach_dump>;

template class Dump<vapi_msg_abf_itf_attach_dump, vapi_msg_abf_itf_attach_details>;

using Abf_itf_attach_dump = Dump<vapi_msg_abf_itf_attach_dump, vapi_msg_abf_itf_attach_details>;

}
#endif
