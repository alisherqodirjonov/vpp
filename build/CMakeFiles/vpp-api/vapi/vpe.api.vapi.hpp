#ifndef __included_hpp_vpe_api_json
#define __included_hpp_vpe_api_json

#include <vapi/vapi.hpp>
#include <vapi/vpe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_show_version>(vapi_msg_show_version *msg)
{
  vapi_msg_show_version_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_version>(vapi_msg_show_version *msg)
{
  vapi_msg_show_version_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_version>()
{
  return ::vapi_msg_id_show_version; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_version>>()
{
  return ::vapi_msg_id_show_version; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_version()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_version>(vapi_msg_id_show_version);
}

template <> inline vapi_msg_show_version* vapi_alloc<vapi_msg_show_version>(Connection &con)
{
  vapi_msg_show_version* result = vapi_alloc_show_version(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_version>;

template class Request<vapi_msg_show_version, vapi_msg_show_version_reply>;

using Show_version = Request<vapi_msg_show_version, vapi_msg_show_version_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_version_reply>(vapi_msg_show_version_reply *msg)
{
  vapi_msg_show_version_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_version_reply>(vapi_msg_show_version_reply *msg)
{
  vapi_msg_show_version_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_version_reply>()
{
  return ::vapi_msg_id_show_version_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_version_reply>>()
{
  return ::vapi_msg_id_show_version_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_version_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_version_reply>(vapi_msg_id_show_version_reply);
}

template class Msg<vapi_msg_show_version_reply>;

using Show_version_reply = Msg<vapi_msg_show_version_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_show_vpe_system_time>(vapi_msg_show_vpe_system_time *msg)
{
  vapi_msg_show_vpe_system_time_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_vpe_system_time>(vapi_msg_show_vpe_system_time *msg)
{
  vapi_msg_show_vpe_system_time_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_vpe_system_time>()
{
  return ::vapi_msg_id_show_vpe_system_time; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_vpe_system_time>>()
{
  return ::vapi_msg_id_show_vpe_system_time; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_vpe_system_time()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_vpe_system_time>(vapi_msg_id_show_vpe_system_time);
}

template <> inline vapi_msg_show_vpe_system_time* vapi_alloc<vapi_msg_show_vpe_system_time>(Connection &con)
{
  vapi_msg_show_vpe_system_time* result = vapi_alloc_show_vpe_system_time(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_show_vpe_system_time>;

template class Request<vapi_msg_show_vpe_system_time, vapi_msg_show_vpe_system_time_reply>;

using Show_vpe_system_time = Request<vapi_msg_show_vpe_system_time, vapi_msg_show_vpe_system_time_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_show_vpe_system_time_reply>(vapi_msg_show_vpe_system_time_reply *msg)
{
  vapi_msg_show_vpe_system_time_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_show_vpe_system_time_reply>(vapi_msg_show_vpe_system_time_reply *msg)
{
  vapi_msg_show_vpe_system_time_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_show_vpe_system_time_reply>()
{
  return ::vapi_msg_id_show_vpe_system_time_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_show_vpe_system_time_reply>>()
{
  return ::vapi_msg_id_show_vpe_system_time_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_show_vpe_system_time_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_show_vpe_system_time_reply>(vapi_msg_id_show_vpe_system_time_reply);
}

template class Msg<vapi_msg_show_vpe_system_time_reply>;

using Show_vpe_system_time_reply = Msg<vapi_msg_show_vpe_system_time_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_log_dump>(vapi_msg_log_dump *msg)
{
  vapi_msg_log_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_log_dump>(vapi_msg_log_dump *msg)
{
  vapi_msg_log_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_log_dump>()
{
  return ::vapi_msg_id_log_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_log_dump>>()
{
  return ::vapi_msg_id_log_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_log_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_log_dump>(vapi_msg_id_log_dump);
}

template <> inline vapi_msg_log_dump* vapi_alloc<vapi_msg_log_dump>(Connection &con)
{
  vapi_msg_log_dump* result = vapi_alloc_log_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_log_dump>;

template class Dump<vapi_msg_log_dump, vapi_msg_log_details>;

using Log_dump = Dump<vapi_msg_log_dump, vapi_msg_log_details>;

template <> inline void vapi_swap_to_be<vapi_msg_log_details>(vapi_msg_log_details *msg)
{
  vapi_msg_log_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_log_details>(vapi_msg_log_details *msg)
{
  vapi_msg_log_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_log_details>()
{
  return ::vapi_msg_id_log_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_log_details>>()
{
  return ::vapi_msg_id_log_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_log_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_log_details>(vapi_msg_id_log_details);
}

template class Msg<vapi_msg_log_details>;

using Log_details = Msg<vapi_msg_log_details>;
}
#endif
