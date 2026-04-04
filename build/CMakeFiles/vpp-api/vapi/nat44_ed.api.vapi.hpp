#ifndef __included_hpp_nat44_ed_api_json
#define __included_hpp_nat44_ed_api_json

#include <vapi/vapi.hpp>
#include <vapi/nat44_ed.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_plugin_enable_disable>(vapi_msg_nat44_ed_plugin_enable_disable *msg)
{
  vapi_msg_nat44_ed_plugin_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_plugin_enable_disable>(vapi_msg_nat44_ed_plugin_enable_disable *msg)
{
  vapi_msg_nat44_ed_plugin_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_plugin_enable_disable>()
{
  return ::vapi_msg_id_nat44_ed_plugin_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_plugin_enable_disable>>()
{
  return ::vapi_msg_id_nat44_ed_plugin_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_plugin_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_plugin_enable_disable>(vapi_msg_id_nat44_ed_plugin_enable_disable);
}

template <> inline vapi_msg_nat44_ed_plugin_enable_disable* vapi_alloc<vapi_msg_nat44_ed_plugin_enable_disable>(Connection &con)
{
  vapi_msg_nat44_ed_plugin_enable_disable* result = vapi_alloc_nat44_ed_plugin_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_plugin_enable_disable>;

template class Request<vapi_msg_nat44_ed_plugin_enable_disable, vapi_msg_nat44_ed_plugin_enable_disable_reply>;

using Nat44_ed_plugin_enable_disable = Request<vapi_msg_nat44_ed_plugin_enable_disable, vapi_msg_nat44_ed_plugin_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_plugin_enable_disable_reply>(vapi_msg_nat44_ed_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat44_ed_plugin_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_plugin_enable_disable_reply>(vapi_msg_nat44_ed_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat44_ed_plugin_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_plugin_enable_disable_reply>()
{
  return ::vapi_msg_id_nat44_ed_plugin_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_plugin_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat44_ed_plugin_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_plugin_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_plugin_enable_disable_reply>(vapi_msg_id_nat44_ed_plugin_enable_disable_reply);
}

template class Msg<vapi_msg_nat44_ed_plugin_enable_disable_reply>;

using Nat44_ed_plugin_enable_disable_reply = Msg<vapi_msg_nat44_ed_plugin_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_forwarding_enable_disable>(vapi_msg_nat44_forwarding_enable_disable *msg)
{
  vapi_msg_nat44_forwarding_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_forwarding_enable_disable>(vapi_msg_nat44_forwarding_enable_disable *msg)
{
  vapi_msg_nat44_forwarding_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_forwarding_enable_disable>()
{
  return ::vapi_msg_id_nat44_forwarding_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_forwarding_enable_disable>>()
{
  return ::vapi_msg_id_nat44_forwarding_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_forwarding_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_forwarding_enable_disable>(vapi_msg_id_nat44_forwarding_enable_disable);
}

template <> inline vapi_msg_nat44_forwarding_enable_disable* vapi_alloc<vapi_msg_nat44_forwarding_enable_disable>(Connection &con)
{
  vapi_msg_nat44_forwarding_enable_disable* result = vapi_alloc_nat44_forwarding_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_forwarding_enable_disable>;

template class Request<vapi_msg_nat44_forwarding_enable_disable, vapi_msg_nat44_forwarding_enable_disable_reply>;

using Nat44_forwarding_enable_disable = Request<vapi_msg_nat44_forwarding_enable_disable, vapi_msg_nat44_forwarding_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_forwarding_enable_disable_reply>(vapi_msg_nat44_forwarding_enable_disable_reply *msg)
{
  vapi_msg_nat44_forwarding_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_forwarding_enable_disable_reply>(vapi_msg_nat44_forwarding_enable_disable_reply *msg)
{
  vapi_msg_nat44_forwarding_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_forwarding_enable_disable_reply>()
{
  return ::vapi_msg_id_nat44_forwarding_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_forwarding_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat44_forwarding_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_forwarding_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_forwarding_enable_disable_reply>(vapi_msg_id_nat44_forwarding_enable_disable_reply);
}

template class Msg<vapi_msg_nat44_forwarding_enable_disable_reply>;

using Nat44_forwarding_enable_disable_reply = Msg<vapi_msg_nat44_forwarding_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_ipfix_enable_disable>(vapi_msg_nat_ipfix_enable_disable *msg)
{
  vapi_msg_nat_ipfix_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_ipfix_enable_disable>(vapi_msg_nat_ipfix_enable_disable *msg)
{
  vapi_msg_nat_ipfix_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_ipfix_enable_disable>()
{
  return ::vapi_msg_id_nat_ipfix_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_ipfix_enable_disable>>()
{
  return ::vapi_msg_id_nat_ipfix_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_ipfix_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_ipfix_enable_disable>(vapi_msg_id_nat_ipfix_enable_disable);
}

template <> inline vapi_msg_nat_ipfix_enable_disable* vapi_alloc<vapi_msg_nat_ipfix_enable_disable>(Connection &con)
{
  vapi_msg_nat_ipfix_enable_disable* result = vapi_alloc_nat_ipfix_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_ipfix_enable_disable>;

template class Request<vapi_msg_nat_ipfix_enable_disable, vapi_msg_nat_ipfix_enable_disable_reply>;

using Nat_ipfix_enable_disable = Request<vapi_msg_nat_ipfix_enable_disable, vapi_msg_nat_ipfix_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_ipfix_enable_disable_reply>(vapi_msg_nat_ipfix_enable_disable_reply *msg)
{
  vapi_msg_nat_ipfix_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_ipfix_enable_disable_reply>(vapi_msg_nat_ipfix_enable_disable_reply *msg)
{
  vapi_msg_nat_ipfix_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_ipfix_enable_disable_reply>()
{
  return ::vapi_msg_id_nat_ipfix_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_ipfix_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat_ipfix_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_ipfix_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_ipfix_enable_disable_reply>(vapi_msg_id_nat_ipfix_enable_disable_reply);
}

template class Msg<vapi_msg_nat_ipfix_enable_disable_reply>;

using Nat_ipfix_enable_disable_reply = Msg<vapi_msg_nat_ipfix_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_set_timeouts>(vapi_msg_nat_set_timeouts *msg)
{
  vapi_msg_nat_set_timeouts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_set_timeouts>(vapi_msg_nat_set_timeouts *msg)
{
  vapi_msg_nat_set_timeouts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_set_timeouts>()
{
  return ::vapi_msg_id_nat_set_timeouts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_set_timeouts>>()
{
  return ::vapi_msg_id_nat_set_timeouts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_set_timeouts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_set_timeouts>(vapi_msg_id_nat_set_timeouts);
}

template <> inline vapi_msg_nat_set_timeouts* vapi_alloc<vapi_msg_nat_set_timeouts>(Connection &con)
{
  vapi_msg_nat_set_timeouts* result = vapi_alloc_nat_set_timeouts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_set_timeouts>;

template class Request<vapi_msg_nat_set_timeouts, vapi_msg_nat_set_timeouts_reply>;

using Nat_set_timeouts = Request<vapi_msg_nat_set_timeouts, vapi_msg_nat_set_timeouts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_set_timeouts_reply>(vapi_msg_nat_set_timeouts_reply *msg)
{
  vapi_msg_nat_set_timeouts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_set_timeouts_reply>(vapi_msg_nat_set_timeouts_reply *msg)
{
  vapi_msg_nat_set_timeouts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_set_timeouts_reply>()
{
  return ::vapi_msg_id_nat_set_timeouts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_set_timeouts_reply>>()
{
  return ::vapi_msg_id_nat_set_timeouts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_set_timeouts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_set_timeouts_reply>(vapi_msg_id_nat_set_timeouts_reply);
}

template class Msg<vapi_msg_nat_set_timeouts_reply>;

using Nat_set_timeouts_reply = Msg<vapi_msg_nat_set_timeouts_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_set_session_limit>(vapi_msg_nat44_set_session_limit *msg)
{
  vapi_msg_nat44_set_session_limit_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_set_session_limit>(vapi_msg_nat44_set_session_limit *msg)
{
  vapi_msg_nat44_set_session_limit_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_set_session_limit>()
{
  return ::vapi_msg_id_nat44_set_session_limit; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_set_session_limit>>()
{
  return ::vapi_msg_id_nat44_set_session_limit; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_set_session_limit()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_set_session_limit>(vapi_msg_id_nat44_set_session_limit);
}

template <> inline vapi_msg_nat44_set_session_limit* vapi_alloc<vapi_msg_nat44_set_session_limit>(Connection &con)
{
  vapi_msg_nat44_set_session_limit* result = vapi_alloc_nat44_set_session_limit(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_set_session_limit>;

template class Request<vapi_msg_nat44_set_session_limit, vapi_msg_nat44_set_session_limit_reply>;

using Nat44_set_session_limit = Request<vapi_msg_nat44_set_session_limit, vapi_msg_nat44_set_session_limit_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_set_session_limit_reply>(vapi_msg_nat44_set_session_limit_reply *msg)
{
  vapi_msg_nat44_set_session_limit_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_set_session_limit_reply>(vapi_msg_nat44_set_session_limit_reply *msg)
{
  vapi_msg_nat44_set_session_limit_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_set_session_limit_reply>()
{
  return ::vapi_msg_id_nat44_set_session_limit_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_set_session_limit_reply>>()
{
  return ::vapi_msg_id_nat44_set_session_limit_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_set_session_limit_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_set_session_limit_reply>(vapi_msg_id_nat44_set_session_limit_reply);
}

template class Msg<vapi_msg_nat44_set_session_limit_reply>;

using Nat44_set_session_limit_reply = Msg<vapi_msg_nat44_set_session_limit_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_show_running_config>(vapi_msg_nat44_show_running_config *msg)
{
  vapi_msg_nat44_show_running_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_show_running_config>(vapi_msg_nat44_show_running_config *msg)
{
  vapi_msg_nat44_show_running_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_show_running_config>()
{
  return ::vapi_msg_id_nat44_show_running_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_show_running_config>>()
{
  return ::vapi_msg_id_nat44_show_running_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_show_running_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_show_running_config>(vapi_msg_id_nat44_show_running_config);
}

template <> inline vapi_msg_nat44_show_running_config* vapi_alloc<vapi_msg_nat44_show_running_config>(Connection &con)
{
  vapi_msg_nat44_show_running_config* result = vapi_alloc_nat44_show_running_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_show_running_config>;

template class Request<vapi_msg_nat44_show_running_config, vapi_msg_nat44_show_running_config_reply>;

using Nat44_show_running_config = Request<vapi_msg_nat44_show_running_config, vapi_msg_nat44_show_running_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_show_running_config_reply>(vapi_msg_nat44_show_running_config_reply *msg)
{
  vapi_msg_nat44_show_running_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_show_running_config_reply>(vapi_msg_nat44_show_running_config_reply *msg)
{
  vapi_msg_nat44_show_running_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_show_running_config_reply>()
{
  return ::vapi_msg_id_nat44_show_running_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_show_running_config_reply>>()
{
  return ::vapi_msg_id_nat44_show_running_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_show_running_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_show_running_config_reply>(vapi_msg_id_nat44_show_running_config_reply);
}

template class Msg<vapi_msg_nat44_show_running_config_reply>;

using Nat44_show_running_config_reply = Msg<vapi_msg_nat44_show_running_config_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_set_workers>(vapi_msg_nat_set_workers *msg)
{
  vapi_msg_nat_set_workers_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_set_workers>(vapi_msg_nat_set_workers *msg)
{
  vapi_msg_nat_set_workers_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_set_workers>()
{
  return ::vapi_msg_id_nat_set_workers; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_set_workers>>()
{
  return ::vapi_msg_id_nat_set_workers; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_set_workers()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_set_workers>(vapi_msg_id_nat_set_workers);
}

template <> inline vapi_msg_nat_set_workers* vapi_alloc<vapi_msg_nat_set_workers>(Connection &con)
{
  vapi_msg_nat_set_workers* result = vapi_alloc_nat_set_workers(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_set_workers>;

template class Request<vapi_msg_nat_set_workers, vapi_msg_nat_set_workers_reply>;

using Nat_set_workers = Request<vapi_msg_nat_set_workers, vapi_msg_nat_set_workers_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_set_workers_reply>(vapi_msg_nat_set_workers_reply *msg)
{
  vapi_msg_nat_set_workers_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_set_workers_reply>(vapi_msg_nat_set_workers_reply *msg)
{
  vapi_msg_nat_set_workers_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_set_workers_reply>()
{
  return ::vapi_msg_id_nat_set_workers_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_set_workers_reply>>()
{
  return ::vapi_msg_id_nat_set_workers_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_set_workers_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_set_workers_reply>(vapi_msg_id_nat_set_workers_reply);
}

template class Msg<vapi_msg_nat_set_workers_reply>;

using Nat_set_workers_reply = Msg<vapi_msg_nat_set_workers_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_worker_dump>(vapi_msg_nat_worker_dump *msg)
{
  vapi_msg_nat_worker_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_worker_dump>(vapi_msg_nat_worker_dump *msg)
{
  vapi_msg_nat_worker_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_worker_dump>()
{
  return ::vapi_msg_id_nat_worker_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_worker_dump>>()
{
  return ::vapi_msg_id_nat_worker_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_worker_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_worker_dump>(vapi_msg_id_nat_worker_dump);
}

template <> inline vapi_msg_nat_worker_dump* vapi_alloc<vapi_msg_nat_worker_dump>(Connection &con)
{
  vapi_msg_nat_worker_dump* result = vapi_alloc_nat_worker_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_worker_dump>;

template class Dump<vapi_msg_nat_worker_dump, vapi_msg_nat_worker_details>;

using Nat_worker_dump = Dump<vapi_msg_nat_worker_dump, vapi_msg_nat_worker_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_worker_details>(vapi_msg_nat_worker_details *msg)
{
  vapi_msg_nat_worker_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_worker_details>(vapi_msg_nat_worker_details *msg)
{
  vapi_msg_nat_worker_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_worker_details>()
{
  return ::vapi_msg_id_nat_worker_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_worker_details>>()
{
  return ::vapi_msg_id_nat_worker_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_worker_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_worker_details>(vapi_msg_id_nat_worker_details);
}

template class Msg<vapi_msg_nat_worker_details>;

using Nat_worker_details = Msg<vapi_msg_nat_worker_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_add_del_vrf_table>(vapi_msg_nat44_ed_add_del_vrf_table *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_add_del_vrf_table>(vapi_msg_nat44_ed_add_del_vrf_table *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_add_del_vrf_table>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_add_del_vrf_table>>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_add_del_vrf_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_add_del_vrf_table>(vapi_msg_id_nat44_ed_add_del_vrf_table);
}

template <> inline vapi_msg_nat44_ed_add_del_vrf_table* vapi_alloc<vapi_msg_nat44_ed_add_del_vrf_table>(Connection &con)
{
  vapi_msg_nat44_ed_add_del_vrf_table* result = vapi_alloc_nat44_ed_add_del_vrf_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_add_del_vrf_table>;

template class Request<vapi_msg_nat44_ed_add_del_vrf_table, vapi_msg_nat44_ed_add_del_vrf_table_reply>;

using Nat44_ed_add_del_vrf_table = Request<vapi_msg_nat44_ed_add_del_vrf_table, vapi_msg_nat44_ed_add_del_vrf_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_add_del_vrf_table_reply>(vapi_msg_nat44_ed_add_del_vrf_table_reply *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_add_del_vrf_table_reply>(vapi_msg_nat44_ed_add_del_vrf_table_reply *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_add_del_vrf_table_reply>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_add_del_vrf_table_reply>>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_add_del_vrf_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_add_del_vrf_table_reply>(vapi_msg_id_nat44_ed_add_del_vrf_table_reply);
}

template class Msg<vapi_msg_nat44_ed_add_del_vrf_table_reply>;

using Nat44_ed_add_del_vrf_table_reply = Msg<vapi_msg_nat44_ed_add_del_vrf_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_add_del_vrf_route>(vapi_msg_nat44_ed_add_del_vrf_route *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_route_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_add_del_vrf_route>(vapi_msg_nat44_ed_add_del_vrf_route *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_route_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_add_del_vrf_route>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_route; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_add_del_vrf_route>>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_route; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_add_del_vrf_route()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_add_del_vrf_route>(vapi_msg_id_nat44_ed_add_del_vrf_route);
}

template <> inline vapi_msg_nat44_ed_add_del_vrf_route* vapi_alloc<vapi_msg_nat44_ed_add_del_vrf_route>(Connection &con)
{
  vapi_msg_nat44_ed_add_del_vrf_route* result = vapi_alloc_nat44_ed_add_del_vrf_route(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_add_del_vrf_route>;

template class Request<vapi_msg_nat44_ed_add_del_vrf_route, vapi_msg_nat44_ed_add_del_vrf_route_reply>;

using Nat44_ed_add_del_vrf_route = Request<vapi_msg_nat44_ed_add_del_vrf_route, vapi_msg_nat44_ed_add_del_vrf_route_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_add_del_vrf_route_reply>(vapi_msg_nat44_ed_add_del_vrf_route_reply *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_route_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_add_del_vrf_route_reply>(vapi_msg_nat44_ed_add_del_vrf_route_reply *msg)
{
  vapi_msg_nat44_ed_add_del_vrf_route_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_add_del_vrf_route_reply>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_route_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_add_del_vrf_route_reply>>()
{
  return ::vapi_msg_id_nat44_ed_add_del_vrf_route_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_add_del_vrf_route_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_add_del_vrf_route_reply>(vapi_msg_id_nat44_ed_add_del_vrf_route_reply);
}

template class Msg<vapi_msg_nat44_ed_add_del_vrf_route_reply>;

using Nat44_ed_add_del_vrf_route_reply = Msg<vapi_msg_nat44_ed_add_del_vrf_route_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_vrf_tables_dump>(vapi_msg_nat44_ed_vrf_tables_dump *msg)
{
  vapi_msg_nat44_ed_vrf_tables_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_vrf_tables_dump>(vapi_msg_nat44_ed_vrf_tables_dump *msg)
{
  vapi_msg_nat44_ed_vrf_tables_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_vrf_tables_dump>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_vrf_tables_dump>>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_vrf_tables_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_vrf_tables_dump>(vapi_msg_id_nat44_ed_vrf_tables_dump);
}

template <> inline vapi_msg_nat44_ed_vrf_tables_dump* vapi_alloc<vapi_msg_nat44_ed_vrf_tables_dump>(Connection &con)
{
  vapi_msg_nat44_ed_vrf_tables_dump* result = vapi_alloc_nat44_ed_vrf_tables_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_vrf_tables_dump>;

template class Dump<vapi_msg_nat44_ed_vrf_tables_dump, vapi_msg_nat44_ed_vrf_tables_details>;

using Nat44_ed_vrf_tables_dump = Dump<vapi_msg_nat44_ed_vrf_tables_dump, vapi_msg_nat44_ed_vrf_tables_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_vrf_tables_details>(vapi_msg_nat44_ed_vrf_tables_details *msg)
{
  vapi_msg_nat44_ed_vrf_tables_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_vrf_tables_details>(vapi_msg_nat44_ed_vrf_tables_details *msg)
{
  vapi_msg_nat44_ed_vrf_tables_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_vrf_tables_details>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_vrf_tables_details>>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_vrf_tables_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_vrf_tables_details>(vapi_msg_id_nat44_ed_vrf_tables_details);
}

template class Msg<vapi_msg_nat44_ed_vrf_tables_details>;

using Nat44_ed_vrf_tables_details = Msg<vapi_msg_nat44_ed_vrf_tables_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_vrf_tables_v2_dump>(vapi_msg_nat44_ed_vrf_tables_v2_dump *msg)
{
  vapi_msg_nat44_ed_vrf_tables_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_vrf_tables_v2_dump>(vapi_msg_nat44_ed_vrf_tables_v2_dump *msg)
{
  vapi_msg_nat44_ed_vrf_tables_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_vrf_tables_v2_dump>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_vrf_tables_v2_dump>>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_vrf_tables_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_vrf_tables_v2_dump>(vapi_msg_id_nat44_ed_vrf_tables_v2_dump);
}

template <> inline vapi_msg_nat44_ed_vrf_tables_v2_dump* vapi_alloc<vapi_msg_nat44_ed_vrf_tables_v2_dump>(Connection &con)
{
  vapi_msg_nat44_ed_vrf_tables_v2_dump* result = vapi_alloc_nat44_ed_vrf_tables_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_vrf_tables_v2_dump>;

template class Dump<vapi_msg_nat44_ed_vrf_tables_v2_dump, vapi_msg_nat44_ed_vrf_tables_v2_details>;

using Nat44_ed_vrf_tables_v2_dump = Dump<vapi_msg_nat44_ed_vrf_tables_v2_dump, vapi_msg_nat44_ed_vrf_tables_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_vrf_tables_v2_details>(vapi_msg_nat44_ed_vrf_tables_v2_details *msg)
{
  vapi_msg_nat44_ed_vrf_tables_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_vrf_tables_v2_details>(vapi_msg_nat44_ed_vrf_tables_v2_details *msg)
{
  vapi_msg_nat44_ed_vrf_tables_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_vrf_tables_v2_details>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_vrf_tables_v2_details>>()
{
  return ::vapi_msg_id_nat44_ed_vrf_tables_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_vrf_tables_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_vrf_tables_v2_details>(vapi_msg_id_nat44_ed_vrf_tables_v2_details);
}

template class Msg<vapi_msg_nat44_ed_vrf_tables_v2_details>;

using Nat44_ed_vrf_tables_v2_details = Msg<vapi_msg_nat44_ed_vrf_tables_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_set_mss_clamping>(vapi_msg_nat_set_mss_clamping *msg)
{
  vapi_msg_nat_set_mss_clamping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_set_mss_clamping>(vapi_msg_nat_set_mss_clamping *msg)
{
  vapi_msg_nat_set_mss_clamping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_set_mss_clamping>()
{
  return ::vapi_msg_id_nat_set_mss_clamping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_set_mss_clamping>>()
{
  return ::vapi_msg_id_nat_set_mss_clamping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_set_mss_clamping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_set_mss_clamping>(vapi_msg_id_nat_set_mss_clamping);
}

template <> inline vapi_msg_nat_set_mss_clamping* vapi_alloc<vapi_msg_nat_set_mss_clamping>(Connection &con)
{
  vapi_msg_nat_set_mss_clamping* result = vapi_alloc_nat_set_mss_clamping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_set_mss_clamping>;

template class Request<vapi_msg_nat_set_mss_clamping, vapi_msg_nat_set_mss_clamping_reply>;

using Nat_set_mss_clamping = Request<vapi_msg_nat_set_mss_clamping, vapi_msg_nat_set_mss_clamping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_set_mss_clamping_reply>(vapi_msg_nat_set_mss_clamping_reply *msg)
{
  vapi_msg_nat_set_mss_clamping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_set_mss_clamping_reply>(vapi_msg_nat_set_mss_clamping_reply *msg)
{
  vapi_msg_nat_set_mss_clamping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_set_mss_clamping_reply>()
{
  return ::vapi_msg_id_nat_set_mss_clamping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_set_mss_clamping_reply>>()
{
  return ::vapi_msg_id_nat_set_mss_clamping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_set_mss_clamping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_set_mss_clamping_reply>(vapi_msg_id_nat_set_mss_clamping_reply);
}

template class Msg<vapi_msg_nat_set_mss_clamping_reply>;

using Nat_set_mss_clamping_reply = Msg<vapi_msg_nat_set_mss_clamping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat_get_mss_clamping>(vapi_msg_nat_get_mss_clamping *msg)
{
  vapi_msg_nat_get_mss_clamping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_get_mss_clamping>(vapi_msg_nat_get_mss_clamping *msg)
{
  vapi_msg_nat_get_mss_clamping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_get_mss_clamping>()
{
  return ::vapi_msg_id_nat_get_mss_clamping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_get_mss_clamping>>()
{
  return ::vapi_msg_id_nat_get_mss_clamping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_get_mss_clamping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_get_mss_clamping>(vapi_msg_id_nat_get_mss_clamping);
}

template <> inline vapi_msg_nat_get_mss_clamping* vapi_alloc<vapi_msg_nat_get_mss_clamping>(Connection &con)
{
  vapi_msg_nat_get_mss_clamping* result = vapi_alloc_nat_get_mss_clamping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat_get_mss_clamping>;

template class Request<vapi_msg_nat_get_mss_clamping, vapi_msg_nat_get_mss_clamping_reply>;

using Nat_get_mss_clamping = Request<vapi_msg_nat_get_mss_clamping, vapi_msg_nat_get_mss_clamping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat_get_mss_clamping_reply>(vapi_msg_nat_get_mss_clamping_reply *msg)
{
  vapi_msg_nat_get_mss_clamping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat_get_mss_clamping_reply>(vapi_msg_nat_get_mss_clamping_reply *msg)
{
  vapi_msg_nat_get_mss_clamping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat_get_mss_clamping_reply>()
{
  return ::vapi_msg_id_nat_get_mss_clamping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat_get_mss_clamping_reply>>()
{
  return ::vapi_msg_id_nat_get_mss_clamping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat_get_mss_clamping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat_get_mss_clamping_reply>(vapi_msg_id_nat_get_mss_clamping_reply);
}

template class Msg<vapi_msg_nat_get_mss_clamping_reply>;

using Nat_get_mss_clamping_reply = Msg<vapi_msg_nat_get_mss_clamping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_set_fq_options>(vapi_msg_nat44_ed_set_fq_options *msg)
{
  vapi_msg_nat44_ed_set_fq_options_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_set_fq_options>(vapi_msg_nat44_ed_set_fq_options *msg)
{
  vapi_msg_nat44_ed_set_fq_options_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_set_fq_options>()
{
  return ::vapi_msg_id_nat44_ed_set_fq_options; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_set_fq_options>>()
{
  return ::vapi_msg_id_nat44_ed_set_fq_options; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_set_fq_options()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_set_fq_options>(vapi_msg_id_nat44_ed_set_fq_options);
}

template <> inline vapi_msg_nat44_ed_set_fq_options* vapi_alloc<vapi_msg_nat44_ed_set_fq_options>(Connection &con)
{
  vapi_msg_nat44_ed_set_fq_options* result = vapi_alloc_nat44_ed_set_fq_options(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_set_fq_options>;

template class Request<vapi_msg_nat44_ed_set_fq_options, vapi_msg_nat44_ed_set_fq_options_reply>;

using Nat44_ed_set_fq_options = Request<vapi_msg_nat44_ed_set_fq_options, vapi_msg_nat44_ed_set_fq_options_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_set_fq_options_reply>(vapi_msg_nat44_ed_set_fq_options_reply *msg)
{
  vapi_msg_nat44_ed_set_fq_options_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_set_fq_options_reply>(vapi_msg_nat44_ed_set_fq_options_reply *msg)
{
  vapi_msg_nat44_ed_set_fq_options_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_set_fq_options_reply>()
{
  return ::vapi_msg_id_nat44_ed_set_fq_options_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_set_fq_options_reply>>()
{
  return ::vapi_msg_id_nat44_ed_set_fq_options_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_set_fq_options_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_set_fq_options_reply>(vapi_msg_id_nat44_ed_set_fq_options_reply);
}

template class Msg<vapi_msg_nat44_ed_set_fq_options_reply>;

using Nat44_ed_set_fq_options_reply = Msg<vapi_msg_nat44_ed_set_fq_options_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_show_fq_options>(vapi_msg_nat44_ed_show_fq_options *msg)
{
  vapi_msg_nat44_ed_show_fq_options_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_show_fq_options>(vapi_msg_nat44_ed_show_fq_options *msg)
{
  vapi_msg_nat44_ed_show_fq_options_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_show_fq_options>()
{
  return ::vapi_msg_id_nat44_ed_show_fq_options; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_show_fq_options>>()
{
  return ::vapi_msg_id_nat44_ed_show_fq_options; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_show_fq_options()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_show_fq_options>(vapi_msg_id_nat44_ed_show_fq_options);
}

template <> inline vapi_msg_nat44_ed_show_fq_options* vapi_alloc<vapi_msg_nat44_ed_show_fq_options>(Connection &con)
{
  vapi_msg_nat44_ed_show_fq_options* result = vapi_alloc_nat44_ed_show_fq_options(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_show_fq_options>;

template class Request<vapi_msg_nat44_ed_show_fq_options, vapi_msg_nat44_ed_show_fq_options_reply>;

using Nat44_ed_show_fq_options = Request<vapi_msg_nat44_ed_show_fq_options, vapi_msg_nat44_ed_show_fq_options_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_show_fq_options_reply>(vapi_msg_nat44_ed_show_fq_options_reply *msg)
{
  vapi_msg_nat44_ed_show_fq_options_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_show_fq_options_reply>(vapi_msg_nat44_ed_show_fq_options_reply *msg)
{
  vapi_msg_nat44_ed_show_fq_options_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_show_fq_options_reply>()
{
  return ::vapi_msg_id_nat44_ed_show_fq_options_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_show_fq_options_reply>>()
{
  return ::vapi_msg_id_nat44_ed_show_fq_options_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_show_fq_options_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_show_fq_options_reply>(vapi_msg_id_nat44_ed_show_fq_options_reply);
}

template class Msg<vapi_msg_nat44_ed_show_fq_options_reply>;

using Nat44_ed_show_fq_options_reply = Msg<vapi_msg_nat44_ed_show_fq_options_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_interface_addr>(vapi_msg_nat44_add_del_interface_addr *msg)
{
  vapi_msg_nat44_add_del_interface_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_interface_addr>(vapi_msg_nat44_add_del_interface_addr *msg)
{
  vapi_msg_nat44_add_del_interface_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_interface_addr>()
{
  return ::vapi_msg_id_nat44_add_del_interface_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_interface_addr>>()
{
  return ::vapi_msg_id_nat44_add_del_interface_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_interface_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_interface_addr>(vapi_msg_id_nat44_add_del_interface_addr);
}

template <> inline vapi_msg_nat44_add_del_interface_addr* vapi_alloc<vapi_msg_nat44_add_del_interface_addr>(Connection &con)
{
  vapi_msg_nat44_add_del_interface_addr* result = vapi_alloc_nat44_add_del_interface_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_add_del_interface_addr>;

template class Request<vapi_msg_nat44_add_del_interface_addr, vapi_msg_nat44_add_del_interface_addr_reply>;

using Nat44_add_del_interface_addr = Request<vapi_msg_nat44_add_del_interface_addr, vapi_msg_nat44_add_del_interface_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_interface_addr_reply>(vapi_msg_nat44_add_del_interface_addr_reply *msg)
{
  vapi_msg_nat44_add_del_interface_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_interface_addr_reply>(vapi_msg_nat44_add_del_interface_addr_reply *msg)
{
  vapi_msg_nat44_add_del_interface_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_interface_addr_reply>()
{
  return ::vapi_msg_id_nat44_add_del_interface_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_interface_addr_reply>>()
{
  return ::vapi_msg_id_nat44_add_del_interface_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_interface_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_interface_addr_reply>(vapi_msg_id_nat44_add_del_interface_addr_reply);
}

template class Msg<vapi_msg_nat44_add_del_interface_addr_reply>;

using Nat44_add_del_interface_addr_reply = Msg<vapi_msg_nat44_add_del_interface_addr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_interface_addr_dump>(vapi_msg_nat44_interface_addr_dump *msg)
{
  vapi_msg_nat44_interface_addr_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_interface_addr_dump>(vapi_msg_nat44_interface_addr_dump *msg)
{
  vapi_msg_nat44_interface_addr_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_interface_addr_dump>()
{
  return ::vapi_msg_id_nat44_interface_addr_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_interface_addr_dump>>()
{
  return ::vapi_msg_id_nat44_interface_addr_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_interface_addr_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_interface_addr_dump>(vapi_msg_id_nat44_interface_addr_dump);
}

template <> inline vapi_msg_nat44_interface_addr_dump* vapi_alloc<vapi_msg_nat44_interface_addr_dump>(Connection &con)
{
  vapi_msg_nat44_interface_addr_dump* result = vapi_alloc_nat44_interface_addr_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_interface_addr_dump>;

template class Dump<vapi_msg_nat44_interface_addr_dump, vapi_msg_nat44_interface_addr_details>;

using Nat44_interface_addr_dump = Dump<vapi_msg_nat44_interface_addr_dump, vapi_msg_nat44_interface_addr_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_interface_addr_details>(vapi_msg_nat44_interface_addr_details *msg)
{
  vapi_msg_nat44_interface_addr_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_interface_addr_details>(vapi_msg_nat44_interface_addr_details *msg)
{
  vapi_msg_nat44_interface_addr_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_interface_addr_details>()
{
  return ::vapi_msg_id_nat44_interface_addr_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_interface_addr_details>>()
{
  return ::vapi_msg_id_nat44_interface_addr_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_interface_addr_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_interface_addr_details>(vapi_msg_id_nat44_interface_addr_details);
}

template class Msg<vapi_msg_nat44_interface_addr_details>;

using Nat44_interface_addr_details = Msg<vapi_msg_nat44_interface_addr_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_address_range>(vapi_msg_nat44_add_del_address_range *msg)
{
  vapi_msg_nat44_add_del_address_range_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_address_range>(vapi_msg_nat44_add_del_address_range *msg)
{
  vapi_msg_nat44_add_del_address_range_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_address_range>()
{
  return ::vapi_msg_id_nat44_add_del_address_range; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_address_range>>()
{
  return ::vapi_msg_id_nat44_add_del_address_range; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_address_range()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_address_range>(vapi_msg_id_nat44_add_del_address_range);
}

template <> inline vapi_msg_nat44_add_del_address_range* vapi_alloc<vapi_msg_nat44_add_del_address_range>(Connection &con)
{
  vapi_msg_nat44_add_del_address_range* result = vapi_alloc_nat44_add_del_address_range(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_add_del_address_range>;

template class Request<vapi_msg_nat44_add_del_address_range, vapi_msg_nat44_add_del_address_range_reply>;

using Nat44_add_del_address_range = Request<vapi_msg_nat44_add_del_address_range, vapi_msg_nat44_add_del_address_range_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_address_range_reply>(vapi_msg_nat44_add_del_address_range_reply *msg)
{
  vapi_msg_nat44_add_del_address_range_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_address_range_reply>(vapi_msg_nat44_add_del_address_range_reply *msg)
{
  vapi_msg_nat44_add_del_address_range_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_address_range_reply>()
{
  return ::vapi_msg_id_nat44_add_del_address_range_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_address_range_reply>>()
{
  return ::vapi_msg_id_nat44_add_del_address_range_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_address_range_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_address_range_reply>(vapi_msg_id_nat44_add_del_address_range_reply);
}

template class Msg<vapi_msg_nat44_add_del_address_range_reply>;

using Nat44_add_del_address_range_reply = Msg<vapi_msg_nat44_add_del_address_range_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_address_dump>(vapi_msg_nat44_address_dump *msg)
{
  vapi_msg_nat44_address_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_address_dump>(vapi_msg_nat44_address_dump *msg)
{
  vapi_msg_nat44_address_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_address_dump>()
{
  return ::vapi_msg_id_nat44_address_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_address_dump>>()
{
  return ::vapi_msg_id_nat44_address_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_address_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_address_dump>(vapi_msg_id_nat44_address_dump);
}

template <> inline vapi_msg_nat44_address_dump* vapi_alloc<vapi_msg_nat44_address_dump>(Connection &con)
{
  vapi_msg_nat44_address_dump* result = vapi_alloc_nat44_address_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_address_dump>;

template class Dump<vapi_msg_nat44_address_dump, vapi_msg_nat44_address_details>;

using Nat44_address_dump = Dump<vapi_msg_nat44_address_dump, vapi_msg_nat44_address_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_address_details>(vapi_msg_nat44_address_details *msg)
{
  vapi_msg_nat44_address_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_address_details>(vapi_msg_nat44_address_details *msg)
{
  vapi_msg_nat44_address_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_address_details>()
{
  return ::vapi_msg_id_nat44_address_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_address_details>>()
{
  return ::vapi_msg_id_nat44_address_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_address_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_address_details>(vapi_msg_id_nat44_address_details);
}

template class Msg<vapi_msg_nat44_address_details>;

using Nat44_address_details = Msg<vapi_msg_nat44_address_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_interface_add_del_feature>(vapi_msg_nat44_interface_add_del_feature *msg)
{
  vapi_msg_nat44_interface_add_del_feature_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_interface_add_del_feature>(vapi_msg_nat44_interface_add_del_feature *msg)
{
  vapi_msg_nat44_interface_add_del_feature_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_interface_add_del_feature>()
{
  return ::vapi_msg_id_nat44_interface_add_del_feature; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_interface_add_del_feature>>()
{
  return ::vapi_msg_id_nat44_interface_add_del_feature; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_interface_add_del_feature()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_interface_add_del_feature>(vapi_msg_id_nat44_interface_add_del_feature);
}

template <> inline vapi_msg_nat44_interface_add_del_feature* vapi_alloc<vapi_msg_nat44_interface_add_del_feature>(Connection &con)
{
  vapi_msg_nat44_interface_add_del_feature* result = vapi_alloc_nat44_interface_add_del_feature(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_interface_add_del_feature>;

template class Request<vapi_msg_nat44_interface_add_del_feature, vapi_msg_nat44_interface_add_del_feature_reply>;

using Nat44_interface_add_del_feature = Request<vapi_msg_nat44_interface_add_del_feature, vapi_msg_nat44_interface_add_del_feature_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_interface_add_del_feature_reply>(vapi_msg_nat44_interface_add_del_feature_reply *msg)
{
  vapi_msg_nat44_interface_add_del_feature_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_interface_add_del_feature_reply>(vapi_msg_nat44_interface_add_del_feature_reply *msg)
{
  vapi_msg_nat44_interface_add_del_feature_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_interface_add_del_feature_reply>()
{
  return ::vapi_msg_id_nat44_interface_add_del_feature_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_interface_add_del_feature_reply>>()
{
  return ::vapi_msg_id_nat44_interface_add_del_feature_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_interface_add_del_feature_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_interface_add_del_feature_reply>(vapi_msg_id_nat44_interface_add_del_feature_reply);
}

template class Msg<vapi_msg_nat44_interface_add_del_feature_reply>;

using Nat44_interface_add_del_feature_reply = Msg<vapi_msg_nat44_interface_add_del_feature_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_interface_dump>(vapi_msg_nat44_interface_dump *msg)
{
  vapi_msg_nat44_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_interface_dump>(vapi_msg_nat44_interface_dump *msg)
{
  vapi_msg_nat44_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_interface_dump>()
{
  return ::vapi_msg_id_nat44_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_interface_dump>>()
{
  return ::vapi_msg_id_nat44_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_interface_dump>(vapi_msg_id_nat44_interface_dump);
}

template <> inline vapi_msg_nat44_interface_dump* vapi_alloc<vapi_msg_nat44_interface_dump>(Connection &con)
{
  vapi_msg_nat44_interface_dump* result = vapi_alloc_nat44_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_interface_dump>;

template class Dump<vapi_msg_nat44_interface_dump, vapi_msg_nat44_interface_details>;

using Nat44_interface_dump = Dump<vapi_msg_nat44_interface_dump, vapi_msg_nat44_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_interface_details>(vapi_msg_nat44_interface_details *msg)
{
  vapi_msg_nat44_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_interface_details>(vapi_msg_nat44_interface_details *msg)
{
  vapi_msg_nat44_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_interface_details>()
{
  return ::vapi_msg_id_nat44_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_interface_details>>()
{
  return ::vapi_msg_id_nat44_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_interface_details>(vapi_msg_id_nat44_interface_details);
}

template class Msg<vapi_msg_nat44_interface_details>;

using Nat44_interface_details = Msg<vapi_msg_nat44_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_add_del_output_interface>(vapi_msg_nat44_ed_add_del_output_interface *msg)
{
  vapi_msg_nat44_ed_add_del_output_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_add_del_output_interface>(vapi_msg_nat44_ed_add_del_output_interface *msg)
{
  vapi_msg_nat44_ed_add_del_output_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_add_del_output_interface>()
{
  return ::vapi_msg_id_nat44_ed_add_del_output_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_add_del_output_interface>>()
{
  return ::vapi_msg_id_nat44_ed_add_del_output_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_add_del_output_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_add_del_output_interface>(vapi_msg_id_nat44_ed_add_del_output_interface);
}

template <> inline vapi_msg_nat44_ed_add_del_output_interface* vapi_alloc<vapi_msg_nat44_ed_add_del_output_interface>(Connection &con)
{
  vapi_msg_nat44_ed_add_del_output_interface* result = vapi_alloc_nat44_ed_add_del_output_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_add_del_output_interface>;

template class Request<vapi_msg_nat44_ed_add_del_output_interface, vapi_msg_nat44_ed_add_del_output_interface_reply>;

using Nat44_ed_add_del_output_interface = Request<vapi_msg_nat44_ed_add_del_output_interface, vapi_msg_nat44_ed_add_del_output_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_add_del_output_interface_reply>(vapi_msg_nat44_ed_add_del_output_interface_reply *msg)
{
  vapi_msg_nat44_ed_add_del_output_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_add_del_output_interface_reply>(vapi_msg_nat44_ed_add_del_output_interface_reply *msg)
{
  vapi_msg_nat44_ed_add_del_output_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_add_del_output_interface_reply>()
{
  return ::vapi_msg_id_nat44_ed_add_del_output_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_add_del_output_interface_reply>>()
{
  return ::vapi_msg_id_nat44_ed_add_del_output_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_add_del_output_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_add_del_output_interface_reply>(vapi_msg_id_nat44_ed_add_del_output_interface_reply);
}

template class Msg<vapi_msg_nat44_ed_add_del_output_interface_reply>;

using Nat44_ed_add_del_output_interface_reply = Msg<vapi_msg_nat44_ed_add_del_output_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_output_interface_get>(vapi_msg_nat44_ed_output_interface_get *msg)
{
  vapi_msg_nat44_ed_output_interface_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_output_interface_get>(vapi_msg_nat44_ed_output_interface_get *msg)
{
  vapi_msg_nat44_ed_output_interface_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_output_interface_get>()
{
  return ::vapi_msg_id_nat44_ed_output_interface_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_output_interface_get>>()
{
  return ::vapi_msg_id_nat44_ed_output_interface_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_output_interface_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_output_interface_get>(vapi_msg_id_nat44_ed_output_interface_get);
}

template <> inline vapi_msg_nat44_ed_output_interface_get* vapi_alloc<vapi_msg_nat44_ed_output_interface_get>(Connection &con)
{
  vapi_msg_nat44_ed_output_interface_get* result = vapi_alloc_nat44_ed_output_interface_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ed_output_interface_get>;

template class Stream<vapi_msg_nat44_ed_output_interface_get, vapi_msg_nat44_ed_output_interface_get_reply, vapi_msg_nat44_ed_output_interface_details>;

using Nat44_ed_output_interface_get = Stream<vapi_msg_nat44_ed_output_interface_get, vapi_msg_nat44_ed_output_interface_get_reply, vapi_msg_nat44_ed_output_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_output_interface_get_reply>(vapi_msg_nat44_ed_output_interface_get_reply *msg)
{
  vapi_msg_nat44_ed_output_interface_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_output_interface_get_reply>(vapi_msg_nat44_ed_output_interface_get_reply *msg)
{
  vapi_msg_nat44_ed_output_interface_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_output_interface_get_reply>()
{
  return ::vapi_msg_id_nat44_ed_output_interface_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_output_interface_get_reply>>()
{
  return ::vapi_msg_id_nat44_ed_output_interface_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_output_interface_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_output_interface_get_reply>(vapi_msg_id_nat44_ed_output_interface_get_reply);
}

template class Msg<vapi_msg_nat44_ed_output_interface_get_reply>;

using Nat44_ed_output_interface_get_reply = Msg<vapi_msg_nat44_ed_output_interface_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ed_output_interface_details>(vapi_msg_nat44_ed_output_interface_details *msg)
{
  vapi_msg_nat44_ed_output_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ed_output_interface_details>(vapi_msg_nat44_ed_output_interface_details *msg)
{
  vapi_msg_nat44_ed_output_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ed_output_interface_details>()
{
  return ::vapi_msg_id_nat44_ed_output_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ed_output_interface_details>>()
{
  return ::vapi_msg_id_nat44_ed_output_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ed_output_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ed_output_interface_details>(vapi_msg_id_nat44_ed_output_interface_details);
}

template class Msg<vapi_msg_nat44_ed_output_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_static_mapping>(vapi_msg_nat44_add_del_static_mapping *msg)
{
  vapi_msg_nat44_add_del_static_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_static_mapping>(vapi_msg_nat44_add_del_static_mapping *msg)
{
  vapi_msg_nat44_add_del_static_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_static_mapping>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_static_mapping>>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_static_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_static_mapping>(vapi_msg_id_nat44_add_del_static_mapping);
}

template <> inline vapi_msg_nat44_add_del_static_mapping* vapi_alloc<vapi_msg_nat44_add_del_static_mapping>(Connection &con)
{
  vapi_msg_nat44_add_del_static_mapping* result = vapi_alloc_nat44_add_del_static_mapping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_add_del_static_mapping>;

template class Request<vapi_msg_nat44_add_del_static_mapping, vapi_msg_nat44_add_del_static_mapping_reply>;

using Nat44_add_del_static_mapping = Request<vapi_msg_nat44_add_del_static_mapping, vapi_msg_nat44_add_del_static_mapping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_static_mapping_reply>(vapi_msg_nat44_add_del_static_mapping_reply *msg)
{
  vapi_msg_nat44_add_del_static_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_static_mapping_reply>(vapi_msg_nat44_add_del_static_mapping_reply *msg)
{
  vapi_msg_nat44_add_del_static_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_static_mapping_reply>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_static_mapping_reply>>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_static_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_static_mapping_reply>(vapi_msg_id_nat44_add_del_static_mapping_reply);
}

template class Msg<vapi_msg_nat44_add_del_static_mapping_reply>;

using Nat44_add_del_static_mapping_reply = Msg<vapi_msg_nat44_add_del_static_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_static_mapping_v2>(vapi_msg_nat44_add_del_static_mapping_v2 *msg)
{
  vapi_msg_nat44_add_del_static_mapping_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_static_mapping_v2>(vapi_msg_nat44_add_del_static_mapping_v2 *msg)
{
  vapi_msg_nat44_add_del_static_mapping_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_static_mapping_v2>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_static_mapping_v2>>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_static_mapping_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_static_mapping_v2>(vapi_msg_id_nat44_add_del_static_mapping_v2);
}

template <> inline vapi_msg_nat44_add_del_static_mapping_v2* vapi_alloc<vapi_msg_nat44_add_del_static_mapping_v2>(Connection &con)
{
  vapi_msg_nat44_add_del_static_mapping_v2* result = vapi_alloc_nat44_add_del_static_mapping_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_add_del_static_mapping_v2>;

template class Request<vapi_msg_nat44_add_del_static_mapping_v2, vapi_msg_nat44_add_del_static_mapping_v2_reply>;

using Nat44_add_del_static_mapping_v2 = Request<vapi_msg_nat44_add_del_static_mapping_v2, vapi_msg_nat44_add_del_static_mapping_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_static_mapping_v2_reply>(vapi_msg_nat44_add_del_static_mapping_v2_reply *msg)
{
  vapi_msg_nat44_add_del_static_mapping_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_static_mapping_v2_reply>(vapi_msg_nat44_add_del_static_mapping_v2_reply *msg)
{
  vapi_msg_nat44_add_del_static_mapping_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_static_mapping_v2_reply>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_static_mapping_v2_reply>>()
{
  return ::vapi_msg_id_nat44_add_del_static_mapping_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_static_mapping_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_static_mapping_v2_reply>(vapi_msg_id_nat44_add_del_static_mapping_v2_reply);
}

template class Msg<vapi_msg_nat44_add_del_static_mapping_v2_reply>;

using Nat44_add_del_static_mapping_v2_reply = Msg<vapi_msg_nat44_add_del_static_mapping_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_static_mapping_dump>(vapi_msg_nat44_static_mapping_dump *msg)
{
  vapi_msg_nat44_static_mapping_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_static_mapping_dump>(vapi_msg_nat44_static_mapping_dump *msg)
{
  vapi_msg_nat44_static_mapping_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_static_mapping_dump>()
{
  return ::vapi_msg_id_nat44_static_mapping_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_static_mapping_dump>>()
{
  return ::vapi_msg_id_nat44_static_mapping_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_static_mapping_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_static_mapping_dump>(vapi_msg_id_nat44_static_mapping_dump);
}

template <> inline vapi_msg_nat44_static_mapping_dump* vapi_alloc<vapi_msg_nat44_static_mapping_dump>(Connection &con)
{
  vapi_msg_nat44_static_mapping_dump* result = vapi_alloc_nat44_static_mapping_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_static_mapping_dump>;

template class Dump<vapi_msg_nat44_static_mapping_dump, vapi_msg_nat44_static_mapping_details>;

using Nat44_static_mapping_dump = Dump<vapi_msg_nat44_static_mapping_dump, vapi_msg_nat44_static_mapping_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_static_mapping_details>(vapi_msg_nat44_static_mapping_details *msg)
{
  vapi_msg_nat44_static_mapping_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_static_mapping_details>(vapi_msg_nat44_static_mapping_details *msg)
{
  vapi_msg_nat44_static_mapping_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_static_mapping_details>()
{
  return ::vapi_msg_id_nat44_static_mapping_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_static_mapping_details>>()
{
  return ::vapi_msg_id_nat44_static_mapping_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_static_mapping_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_static_mapping_details>(vapi_msg_id_nat44_static_mapping_details);
}

template class Msg<vapi_msg_nat44_static_mapping_details>;

using Nat44_static_mapping_details = Msg<vapi_msg_nat44_static_mapping_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_identity_mapping>(vapi_msg_nat44_add_del_identity_mapping *msg)
{
  vapi_msg_nat44_add_del_identity_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_identity_mapping>(vapi_msg_nat44_add_del_identity_mapping *msg)
{
  vapi_msg_nat44_add_del_identity_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_identity_mapping>()
{
  return ::vapi_msg_id_nat44_add_del_identity_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_identity_mapping>>()
{
  return ::vapi_msg_id_nat44_add_del_identity_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_identity_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_identity_mapping>(vapi_msg_id_nat44_add_del_identity_mapping);
}

template <> inline vapi_msg_nat44_add_del_identity_mapping* vapi_alloc<vapi_msg_nat44_add_del_identity_mapping>(Connection &con)
{
  vapi_msg_nat44_add_del_identity_mapping* result = vapi_alloc_nat44_add_del_identity_mapping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_add_del_identity_mapping>;

template class Request<vapi_msg_nat44_add_del_identity_mapping, vapi_msg_nat44_add_del_identity_mapping_reply>;

using Nat44_add_del_identity_mapping = Request<vapi_msg_nat44_add_del_identity_mapping, vapi_msg_nat44_add_del_identity_mapping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_identity_mapping_reply>(vapi_msg_nat44_add_del_identity_mapping_reply *msg)
{
  vapi_msg_nat44_add_del_identity_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_identity_mapping_reply>(vapi_msg_nat44_add_del_identity_mapping_reply *msg)
{
  vapi_msg_nat44_add_del_identity_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_identity_mapping_reply>()
{
  return ::vapi_msg_id_nat44_add_del_identity_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_identity_mapping_reply>>()
{
  return ::vapi_msg_id_nat44_add_del_identity_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_identity_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_identity_mapping_reply>(vapi_msg_id_nat44_add_del_identity_mapping_reply);
}

template class Msg<vapi_msg_nat44_add_del_identity_mapping_reply>;

using Nat44_add_del_identity_mapping_reply = Msg<vapi_msg_nat44_add_del_identity_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_identity_mapping_dump>(vapi_msg_nat44_identity_mapping_dump *msg)
{
  vapi_msg_nat44_identity_mapping_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_identity_mapping_dump>(vapi_msg_nat44_identity_mapping_dump *msg)
{
  vapi_msg_nat44_identity_mapping_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_identity_mapping_dump>()
{
  return ::vapi_msg_id_nat44_identity_mapping_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_identity_mapping_dump>>()
{
  return ::vapi_msg_id_nat44_identity_mapping_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_identity_mapping_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_identity_mapping_dump>(vapi_msg_id_nat44_identity_mapping_dump);
}

template <> inline vapi_msg_nat44_identity_mapping_dump* vapi_alloc<vapi_msg_nat44_identity_mapping_dump>(Connection &con)
{
  vapi_msg_nat44_identity_mapping_dump* result = vapi_alloc_nat44_identity_mapping_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_identity_mapping_dump>;

template class Dump<vapi_msg_nat44_identity_mapping_dump, vapi_msg_nat44_identity_mapping_details>;

using Nat44_identity_mapping_dump = Dump<vapi_msg_nat44_identity_mapping_dump, vapi_msg_nat44_identity_mapping_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_identity_mapping_details>(vapi_msg_nat44_identity_mapping_details *msg)
{
  vapi_msg_nat44_identity_mapping_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_identity_mapping_details>(vapi_msg_nat44_identity_mapping_details *msg)
{
  vapi_msg_nat44_identity_mapping_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_identity_mapping_details>()
{
  return ::vapi_msg_id_nat44_identity_mapping_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_identity_mapping_details>>()
{
  return ::vapi_msg_id_nat44_identity_mapping_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_identity_mapping_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_identity_mapping_details>(vapi_msg_id_nat44_identity_mapping_details);
}

template class Msg<vapi_msg_nat44_identity_mapping_details>;

using Nat44_identity_mapping_details = Msg<vapi_msg_nat44_identity_mapping_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_lb_static_mapping>(vapi_msg_nat44_add_del_lb_static_mapping *msg)
{
  vapi_msg_nat44_add_del_lb_static_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_lb_static_mapping>(vapi_msg_nat44_add_del_lb_static_mapping *msg)
{
  vapi_msg_nat44_add_del_lb_static_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_lb_static_mapping>()
{
  return ::vapi_msg_id_nat44_add_del_lb_static_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_lb_static_mapping>>()
{
  return ::vapi_msg_id_nat44_add_del_lb_static_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_lb_static_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_lb_static_mapping>(vapi_msg_id_nat44_add_del_lb_static_mapping);
}

template <> inline vapi_msg_nat44_add_del_lb_static_mapping* vapi_alloc<vapi_msg_nat44_add_del_lb_static_mapping, size_t>(Connection &con, size_t _locals_array_size)
{
  vapi_msg_nat44_add_del_lb_static_mapping* result = vapi_alloc_nat44_add_del_lb_static_mapping(con.vapi_ctx, _locals_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_add_del_lb_static_mapping>;

template class Request<vapi_msg_nat44_add_del_lb_static_mapping, vapi_msg_nat44_add_del_lb_static_mapping_reply, size_t>;

using Nat44_add_del_lb_static_mapping = Request<vapi_msg_nat44_add_del_lb_static_mapping, vapi_msg_nat44_add_del_lb_static_mapping_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_add_del_lb_static_mapping_reply>(vapi_msg_nat44_add_del_lb_static_mapping_reply *msg)
{
  vapi_msg_nat44_add_del_lb_static_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_add_del_lb_static_mapping_reply>(vapi_msg_nat44_add_del_lb_static_mapping_reply *msg)
{
  vapi_msg_nat44_add_del_lb_static_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_add_del_lb_static_mapping_reply>()
{
  return ::vapi_msg_id_nat44_add_del_lb_static_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_add_del_lb_static_mapping_reply>>()
{
  return ::vapi_msg_id_nat44_add_del_lb_static_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_add_del_lb_static_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_add_del_lb_static_mapping_reply>(vapi_msg_id_nat44_add_del_lb_static_mapping_reply);
}

template class Msg<vapi_msg_nat44_add_del_lb_static_mapping_reply>;

using Nat44_add_del_lb_static_mapping_reply = Msg<vapi_msg_nat44_add_del_lb_static_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_lb_static_mapping_add_del_local>(vapi_msg_nat44_lb_static_mapping_add_del_local *msg)
{
  vapi_msg_nat44_lb_static_mapping_add_del_local_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_lb_static_mapping_add_del_local>(vapi_msg_nat44_lb_static_mapping_add_del_local *msg)
{
  vapi_msg_nat44_lb_static_mapping_add_del_local_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_lb_static_mapping_add_del_local>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_add_del_local; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_lb_static_mapping_add_del_local>>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_add_del_local; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_lb_static_mapping_add_del_local()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_lb_static_mapping_add_del_local>(vapi_msg_id_nat44_lb_static_mapping_add_del_local);
}

template <> inline vapi_msg_nat44_lb_static_mapping_add_del_local* vapi_alloc<vapi_msg_nat44_lb_static_mapping_add_del_local>(Connection &con)
{
  vapi_msg_nat44_lb_static_mapping_add_del_local* result = vapi_alloc_nat44_lb_static_mapping_add_del_local(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_lb_static_mapping_add_del_local>;

template class Request<vapi_msg_nat44_lb_static_mapping_add_del_local, vapi_msg_nat44_lb_static_mapping_add_del_local_reply>;

using Nat44_lb_static_mapping_add_del_local = Request<vapi_msg_nat44_lb_static_mapping_add_del_local, vapi_msg_nat44_lb_static_mapping_add_del_local_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>(vapi_msg_nat44_lb_static_mapping_add_del_local_reply *msg)
{
  vapi_msg_nat44_lb_static_mapping_add_del_local_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>(vapi_msg_nat44_lb_static_mapping_add_del_local_reply *msg)
{
  vapi_msg_nat44_lb_static_mapping_add_del_local_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_add_del_local_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_add_del_local_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_lb_static_mapping_add_del_local_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>(vapi_msg_id_nat44_lb_static_mapping_add_del_local_reply);
}

template class Msg<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>;

using Nat44_lb_static_mapping_add_del_local_reply = Msg<vapi_msg_nat44_lb_static_mapping_add_del_local_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_lb_static_mapping_dump>(vapi_msg_nat44_lb_static_mapping_dump *msg)
{
  vapi_msg_nat44_lb_static_mapping_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_lb_static_mapping_dump>(vapi_msg_nat44_lb_static_mapping_dump *msg)
{
  vapi_msg_nat44_lb_static_mapping_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_lb_static_mapping_dump>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_lb_static_mapping_dump>>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_lb_static_mapping_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_lb_static_mapping_dump>(vapi_msg_id_nat44_lb_static_mapping_dump);
}

template <> inline vapi_msg_nat44_lb_static_mapping_dump* vapi_alloc<vapi_msg_nat44_lb_static_mapping_dump>(Connection &con)
{
  vapi_msg_nat44_lb_static_mapping_dump* result = vapi_alloc_nat44_lb_static_mapping_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_lb_static_mapping_dump>;

template class Dump<vapi_msg_nat44_lb_static_mapping_dump, vapi_msg_nat44_lb_static_mapping_details>;

using Nat44_lb_static_mapping_dump = Dump<vapi_msg_nat44_lb_static_mapping_dump, vapi_msg_nat44_lb_static_mapping_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_lb_static_mapping_details>(vapi_msg_nat44_lb_static_mapping_details *msg)
{
  vapi_msg_nat44_lb_static_mapping_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_lb_static_mapping_details>(vapi_msg_nat44_lb_static_mapping_details *msg)
{
  vapi_msg_nat44_lb_static_mapping_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_lb_static_mapping_details>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_lb_static_mapping_details>>()
{
  return ::vapi_msg_id_nat44_lb_static_mapping_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_lb_static_mapping_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_lb_static_mapping_details>(vapi_msg_id_nat44_lb_static_mapping_details);
}

template class Msg<vapi_msg_nat44_lb_static_mapping_details>;

using Nat44_lb_static_mapping_details = Msg<vapi_msg_nat44_lb_static_mapping_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_del_session>(vapi_msg_nat44_del_session *msg)
{
  vapi_msg_nat44_del_session_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_del_session>(vapi_msg_nat44_del_session *msg)
{
  vapi_msg_nat44_del_session_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_del_session>()
{
  return ::vapi_msg_id_nat44_del_session; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_del_session>>()
{
  return ::vapi_msg_id_nat44_del_session; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_del_session()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_del_session>(vapi_msg_id_nat44_del_session);
}

template <> inline vapi_msg_nat44_del_session* vapi_alloc<vapi_msg_nat44_del_session>(Connection &con)
{
  vapi_msg_nat44_del_session* result = vapi_alloc_nat44_del_session(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_del_session>;

template class Request<vapi_msg_nat44_del_session, vapi_msg_nat44_del_session_reply>;

using Nat44_del_session = Request<vapi_msg_nat44_del_session, vapi_msg_nat44_del_session_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_del_session_reply>(vapi_msg_nat44_del_session_reply *msg)
{
  vapi_msg_nat44_del_session_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_del_session_reply>(vapi_msg_nat44_del_session_reply *msg)
{
  vapi_msg_nat44_del_session_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_del_session_reply>()
{
  return ::vapi_msg_id_nat44_del_session_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_del_session_reply>>()
{
  return ::vapi_msg_id_nat44_del_session_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_del_session_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_del_session_reply>(vapi_msg_id_nat44_del_session_reply);
}

template class Msg<vapi_msg_nat44_del_session_reply>;

using Nat44_del_session_reply = Msg<vapi_msg_nat44_del_session_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_dump>(vapi_msg_nat44_user_dump *msg)
{
  vapi_msg_nat44_user_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_dump>(vapi_msg_nat44_user_dump *msg)
{
  vapi_msg_nat44_user_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_dump>()
{
  return ::vapi_msg_id_nat44_user_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_dump>>()
{
  return ::vapi_msg_id_nat44_user_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_dump>(vapi_msg_id_nat44_user_dump);
}

template <> inline vapi_msg_nat44_user_dump* vapi_alloc<vapi_msg_nat44_user_dump>(Connection &con)
{
  vapi_msg_nat44_user_dump* result = vapi_alloc_nat44_user_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_user_dump>;

template class Dump<vapi_msg_nat44_user_dump, vapi_msg_nat44_user_details>;

using Nat44_user_dump = Dump<vapi_msg_nat44_user_dump, vapi_msg_nat44_user_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_details>(vapi_msg_nat44_user_details *msg)
{
  vapi_msg_nat44_user_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_details>(vapi_msg_nat44_user_details *msg)
{
  vapi_msg_nat44_user_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_details>()
{
  return ::vapi_msg_id_nat44_user_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_details>>()
{
  return ::vapi_msg_id_nat44_user_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_details>(vapi_msg_id_nat44_user_details);
}

template class Msg<vapi_msg_nat44_user_details>;

using Nat44_user_details = Msg<vapi_msg_nat44_user_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_session_dump>(vapi_msg_nat44_user_session_dump *msg)
{
  vapi_msg_nat44_user_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_session_dump>(vapi_msg_nat44_user_session_dump *msg)
{
  vapi_msg_nat44_user_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_session_dump>()
{
  return ::vapi_msg_id_nat44_user_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_session_dump>>()
{
  return ::vapi_msg_id_nat44_user_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_session_dump>(vapi_msg_id_nat44_user_session_dump);
}

template <> inline vapi_msg_nat44_user_session_dump* vapi_alloc<vapi_msg_nat44_user_session_dump>(Connection &con)
{
  vapi_msg_nat44_user_session_dump* result = vapi_alloc_nat44_user_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_user_session_dump>;

template class Dump<vapi_msg_nat44_user_session_dump, vapi_msg_nat44_user_session_details>;

using Nat44_user_session_dump = Dump<vapi_msg_nat44_user_session_dump, vapi_msg_nat44_user_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_session_details>(vapi_msg_nat44_user_session_details *msg)
{
  vapi_msg_nat44_user_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_session_details>(vapi_msg_nat44_user_session_details *msg)
{
  vapi_msg_nat44_user_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_session_details>()
{
  return ::vapi_msg_id_nat44_user_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_session_details>>()
{
  return ::vapi_msg_id_nat44_user_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_session_details>(vapi_msg_id_nat44_user_session_details);
}

template class Msg<vapi_msg_nat44_user_session_details>;

using Nat44_user_session_details = Msg<vapi_msg_nat44_user_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_session_v2_dump>(vapi_msg_nat44_user_session_v2_dump *msg)
{
  vapi_msg_nat44_user_session_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_session_v2_dump>(vapi_msg_nat44_user_session_v2_dump *msg)
{
  vapi_msg_nat44_user_session_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_session_v2_dump>()
{
  return ::vapi_msg_id_nat44_user_session_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_session_v2_dump>>()
{
  return ::vapi_msg_id_nat44_user_session_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_session_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_session_v2_dump>(vapi_msg_id_nat44_user_session_v2_dump);
}

template <> inline vapi_msg_nat44_user_session_v2_dump* vapi_alloc<vapi_msg_nat44_user_session_v2_dump>(Connection &con)
{
  vapi_msg_nat44_user_session_v2_dump* result = vapi_alloc_nat44_user_session_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_user_session_v2_dump>;

template class Dump<vapi_msg_nat44_user_session_v2_dump, vapi_msg_nat44_user_session_v2_details>;

using Nat44_user_session_v2_dump = Dump<vapi_msg_nat44_user_session_v2_dump, vapi_msg_nat44_user_session_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_session_v2_details>(vapi_msg_nat44_user_session_v2_details *msg)
{
  vapi_msg_nat44_user_session_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_session_v2_details>(vapi_msg_nat44_user_session_v2_details *msg)
{
  vapi_msg_nat44_user_session_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_session_v2_details>()
{
  return ::vapi_msg_id_nat44_user_session_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_session_v2_details>>()
{
  return ::vapi_msg_id_nat44_user_session_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_session_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_session_v2_details>(vapi_msg_id_nat44_user_session_v2_details);
}

template class Msg<vapi_msg_nat44_user_session_v2_details>;

using Nat44_user_session_v2_details = Msg<vapi_msg_nat44_user_session_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_session_v3_details>(vapi_msg_nat44_user_session_v3_details *msg)
{
  vapi_msg_nat44_user_session_v3_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_session_v3_details>(vapi_msg_nat44_user_session_v3_details *msg)
{
  vapi_msg_nat44_user_session_v3_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_session_v3_details>()
{
  return ::vapi_msg_id_nat44_user_session_v3_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_session_v3_details>>()
{
  return ::vapi_msg_id_nat44_user_session_v3_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_session_v3_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_session_v3_details>(vapi_msg_id_nat44_user_session_v3_details);
}

template class Msg<vapi_msg_nat44_user_session_v3_details>;

using Nat44_user_session_v3_details = Msg<vapi_msg_nat44_user_session_v3_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_user_session_v3_dump>(vapi_msg_nat44_user_session_v3_dump *msg)
{
  vapi_msg_nat44_user_session_v3_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_user_session_v3_dump>(vapi_msg_nat44_user_session_v3_dump *msg)
{
  vapi_msg_nat44_user_session_v3_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_user_session_v3_dump>()
{
  return ::vapi_msg_id_nat44_user_session_v3_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_user_session_v3_dump>>()
{
  return ::vapi_msg_id_nat44_user_session_v3_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_user_session_v3_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_user_session_v3_dump>(vapi_msg_id_nat44_user_session_v3_dump);
}

template <> inline vapi_msg_nat44_user_session_v3_dump* vapi_alloc<vapi_msg_nat44_user_session_v3_dump>(Connection &con)
{
  vapi_msg_nat44_user_session_v3_dump* result = vapi_alloc_nat44_user_session_v3_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_user_session_v3_dump>;

template class Dump<vapi_msg_nat44_user_session_v3_dump, vapi_msg_nat44_user_session_v3_details>;

using Nat44_user_session_v3_dump = Dump<vapi_msg_nat44_user_session_v3_dump, vapi_msg_nat44_user_session_v3_details>;

}
#endif
