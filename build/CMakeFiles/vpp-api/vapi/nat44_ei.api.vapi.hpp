#ifndef __included_hpp_nat44_ei_api_json
#define __included_hpp_nat44_ei_api_json

#include <vapi/vapi.hpp>
#include <vapi/nat44_ei.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_plugin_enable_disable>(vapi_msg_nat44_ei_plugin_enable_disable *msg)
{
  vapi_msg_nat44_ei_plugin_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_plugin_enable_disable>(vapi_msg_nat44_ei_plugin_enable_disable *msg)
{
  vapi_msg_nat44_ei_plugin_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_plugin_enable_disable>()
{
  return ::vapi_msg_id_nat44_ei_plugin_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_plugin_enable_disable>>()
{
  return ::vapi_msg_id_nat44_ei_plugin_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_plugin_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_plugin_enable_disable>(vapi_msg_id_nat44_ei_plugin_enable_disable);
}

template <> inline vapi_msg_nat44_ei_plugin_enable_disable* vapi_alloc<vapi_msg_nat44_ei_plugin_enable_disable>(Connection &con)
{
  vapi_msg_nat44_ei_plugin_enable_disable* result = vapi_alloc_nat44_ei_plugin_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_plugin_enable_disable>;

template class Request<vapi_msg_nat44_ei_plugin_enable_disable, vapi_msg_nat44_ei_plugin_enable_disable_reply>;

using Nat44_ei_plugin_enable_disable = Request<vapi_msg_nat44_ei_plugin_enable_disable, vapi_msg_nat44_ei_plugin_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_plugin_enable_disable_reply>(vapi_msg_nat44_ei_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat44_ei_plugin_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_plugin_enable_disable_reply>(vapi_msg_nat44_ei_plugin_enable_disable_reply *msg)
{
  vapi_msg_nat44_ei_plugin_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_plugin_enable_disable_reply>()
{
  return ::vapi_msg_id_nat44_ei_plugin_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_plugin_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat44_ei_plugin_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_plugin_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_plugin_enable_disable_reply>(vapi_msg_id_nat44_ei_plugin_enable_disable_reply);
}

template class Msg<vapi_msg_nat44_ei_plugin_enable_disable_reply>;

using Nat44_ei_plugin_enable_disable_reply = Msg<vapi_msg_nat44_ei_plugin_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_show_running_config>(vapi_msg_nat44_ei_show_running_config *msg)
{
  vapi_msg_nat44_ei_show_running_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_show_running_config>(vapi_msg_nat44_ei_show_running_config *msg)
{
  vapi_msg_nat44_ei_show_running_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_show_running_config>()
{
  return ::vapi_msg_id_nat44_ei_show_running_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_show_running_config>>()
{
  return ::vapi_msg_id_nat44_ei_show_running_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_show_running_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_show_running_config>(vapi_msg_id_nat44_ei_show_running_config);
}

template <> inline vapi_msg_nat44_ei_show_running_config* vapi_alloc<vapi_msg_nat44_ei_show_running_config>(Connection &con)
{
  vapi_msg_nat44_ei_show_running_config* result = vapi_alloc_nat44_ei_show_running_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_show_running_config>;

template class Request<vapi_msg_nat44_ei_show_running_config, vapi_msg_nat44_ei_show_running_config_reply>;

using Nat44_ei_show_running_config = Request<vapi_msg_nat44_ei_show_running_config, vapi_msg_nat44_ei_show_running_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_show_running_config_reply>(vapi_msg_nat44_ei_show_running_config_reply *msg)
{
  vapi_msg_nat44_ei_show_running_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_show_running_config_reply>(vapi_msg_nat44_ei_show_running_config_reply *msg)
{
  vapi_msg_nat44_ei_show_running_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_show_running_config_reply>()
{
  return ::vapi_msg_id_nat44_ei_show_running_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_show_running_config_reply>>()
{
  return ::vapi_msg_id_nat44_ei_show_running_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_show_running_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_show_running_config_reply>(vapi_msg_id_nat44_ei_show_running_config_reply);
}

template class Msg<vapi_msg_nat44_ei_show_running_config_reply>;

using Nat44_ei_show_running_config_reply = Msg<vapi_msg_nat44_ei_show_running_config_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_log_level>(vapi_msg_nat44_ei_set_log_level *msg)
{
  vapi_msg_nat44_ei_set_log_level_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_log_level>(vapi_msg_nat44_ei_set_log_level *msg)
{
  vapi_msg_nat44_ei_set_log_level_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_log_level>()
{
  return ::vapi_msg_id_nat44_ei_set_log_level; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_log_level>>()
{
  return ::vapi_msg_id_nat44_ei_set_log_level; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_log_level()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_log_level>(vapi_msg_id_nat44_ei_set_log_level);
}

template <> inline vapi_msg_nat44_ei_set_log_level* vapi_alloc<vapi_msg_nat44_ei_set_log_level>(Connection &con)
{
  vapi_msg_nat44_ei_set_log_level* result = vapi_alloc_nat44_ei_set_log_level(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_set_log_level>;

template class Request<vapi_msg_nat44_ei_set_log_level, vapi_msg_nat44_ei_set_log_level_reply>;

using Nat44_ei_set_log_level = Request<vapi_msg_nat44_ei_set_log_level, vapi_msg_nat44_ei_set_log_level_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_log_level_reply>(vapi_msg_nat44_ei_set_log_level_reply *msg)
{
  vapi_msg_nat44_ei_set_log_level_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_log_level_reply>(vapi_msg_nat44_ei_set_log_level_reply *msg)
{
  vapi_msg_nat44_ei_set_log_level_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_log_level_reply>()
{
  return ::vapi_msg_id_nat44_ei_set_log_level_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_log_level_reply>>()
{
  return ::vapi_msg_id_nat44_ei_set_log_level_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_log_level_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_log_level_reply>(vapi_msg_id_nat44_ei_set_log_level_reply);
}

template class Msg<vapi_msg_nat44_ei_set_log_level_reply>;

using Nat44_ei_set_log_level_reply = Msg<vapi_msg_nat44_ei_set_log_level_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_workers>(vapi_msg_nat44_ei_set_workers *msg)
{
  vapi_msg_nat44_ei_set_workers_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_workers>(vapi_msg_nat44_ei_set_workers *msg)
{
  vapi_msg_nat44_ei_set_workers_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_workers>()
{
  return ::vapi_msg_id_nat44_ei_set_workers; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_workers>>()
{
  return ::vapi_msg_id_nat44_ei_set_workers; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_workers()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_workers>(vapi_msg_id_nat44_ei_set_workers);
}

template <> inline vapi_msg_nat44_ei_set_workers* vapi_alloc<vapi_msg_nat44_ei_set_workers>(Connection &con)
{
  vapi_msg_nat44_ei_set_workers* result = vapi_alloc_nat44_ei_set_workers(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_set_workers>;

template class Request<vapi_msg_nat44_ei_set_workers, vapi_msg_nat44_ei_set_workers_reply>;

using Nat44_ei_set_workers = Request<vapi_msg_nat44_ei_set_workers, vapi_msg_nat44_ei_set_workers_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_workers_reply>(vapi_msg_nat44_ei_set_workers_reply *msg)
{
  vapi_msg_nat44_ei_set_workers_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_workers_reply>(vapi_msg_nat44_ei_set_workers_reply *msg)
{
  vapi_msg_nat44_ei_set_workers_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_workers_reply>()
{
  return ::vapi_msg_id_nat44_ei_set_workers_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_workers_reply>>()
{
  return ::vapi_msg_id_nat44_ei_set_workers_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_workers_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_workers_reply>(vapi_msg_id_nat44_ei_set_workers_reply);
}

template class Msg<vapi_msg_nat44_ei_set_workers_reply>;

using Nat44_ei_set_workers_reply = Msg<vapi_msg_nat44_ei_set_workers_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_worker_dump>(vapi_msg_nat44_ei_worker_dump *msg)
{
  vapi_msg_nat44_ei_worker_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_worker_dump>(vapi_msg_nat44_ei_worker_dump *msg)
{
  vapi_msg_nat44_ei_worker_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_worker_dump>()
{
  return ::vapi_msg_id_nat44_ei_worker_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_worker_dump>>()
{
  return ::vapi_msg_id_nat44_ei_worker_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_worker_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_worker_dump>(vapi_msg_id_nat44_ei_worker_dump);
}

template <> inline vapi_msg_nat44_ei_worker_dump* vapi_alloc<vapi_msg_nat44_ei_worker_dump>(Connection &con)
{
  vapi_msg_nat44_ei_worker_dump* result = vapi_alloc_nat44_ei_worker_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_worker_dump>;

template class Dump<vapi_msg_nat44_ei_worker_dump, vapi_msg_nat44_ei_worker_details>;

using Nat44_ei_worker_dump = Dump<vapi_msg_nat44_ei_worker_dump, vapi_msg_nat44_ei_worker_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_worker_details>(vapi_msg_nat44_ei_worker_details *msg)
{
  vapi_msg_nat44_ei_worker_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_worker_details>(vapi_msg_nat44_ei_worker_details *msg)
{
  vapi_msg_nat44_ei_worker_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_worker_details>()
{
  return ::vapi_msg_id_nat44_ei_worker_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_worker_details>>()
{
  return ::vapi_msg_id_nat44_ei_worker_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_worker_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_worker_details>(vapi_msg_id_nat44_ei_worker_details);
}

template class Msg<vapi_msg_nat44_ei_worker_details>;

using Nat44_ei_worker_details = Msg<vapi_msg_nat44_ei_worker_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ipfix_enable_disable>(vapi_msg_nat44_ei_ipfix_enable_disable *msg)
{
  vapi_msg_nat44_ei_ipfix_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ipfix_enable_disable>(vapi_msg_nat44_ei_ipfix_enable_disable *msg)
{
  vapi_msg_nat44_ei_ipfix_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ipfix_enable_disable>()
{
  return ::vapi_msg_id_nat44_ei_ipfix_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ipfix_enable_disable>>()
{
  return ::vapi_msg_id_nat44_ei_ipfix_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ipfix_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ipfix_enable_disable>(vapi_msg_id_nat44_ei_ipfix_enable_disable);
}

template <> inline vapi_msg_nat44_ei_ipfix_enable_disable* vapi_alloc<vapi_msg_nat44_ei_ipfix_enable_disable>(Connection &con)
{
  vapi_msg_nat44_ei_ipfix_enable_disable* result = vapi_alloc_nat44_ei_ipfix_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ipfix_enable_disable>;

template class Request<vapi_msg_nat44_ei_ipfix_enable_disable, vapi_msg_nat44_ei_ipfix_enable_disable_reply>;

using Nat44_ei_ipfix_enable_disable = Request<vapi_msg_nat44_ei_ipfix_enable_disable, vapi_msg_nat44_ei_ipfix_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ipfix_enable_disable_reply>(vapi_msg_nat44_ei_ipfix_enable_disable_reply *msg)
{
  vapi_msg_nat44_ei_ipfix_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ipfix_enable_disable_reply>(vapi_msg_nat44_ei_ipfix_enable_disable_reply *msg)
{
  vapi_msg_nat44_ei_ipfix_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ipfix_enable_disable_reply>()
{
  return ::vapi_msg_id_nat44_ei_ipfix_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ipfix_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ipfix_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ipfix_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ipfix_enable_disable_reply>(vapi_msg_id_nat44_ei_ipfix_enable_disable_reply);
}

template class Msg<vapi_msg_nat44_ei_ipfix_enable_disable_reply>;

using Nat44_ei_ipfix_enable_disable_reply = Msg<vapi_msg_nat44_ei_ipfix_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_timeouts>(vapi_msg_nat44_ei_set_timeouts *msg)
{
  vapi_msg_nat44_ei_set_timeouts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_timeouts>(vapi_msg_nat44_ei_set_timeouts *msg)
{
  vapi_msg_nat44_ei_set_timeouts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_timeouts>()
{
  return ::vapi_msg_id_nat44_ei_set_timeouts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_timeouts>>()
{
  return ::vapi_msg_id_nat44_ei_set_timeouts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_timeouts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_timeouts>(vapi_msg_id_nat44_ei_set_timeouts);
}

template <> inline vapi_msg_nat44_ei_set_timeouts* vapi_alloc<vapi_msg_nat44_ei_set_timeouts>(Connection &con)
{
  vapi_msg_nat44_ei_set_timeouts* result = vapi_alloc_nat44_ei_set_timeouts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_set_timeouts>;

template class Request<vapi_msg_nat44_ei_set_timeouts, vapi_msg_nat44_ei_set_timeouts_reply>;

using Nat44_ei_set_timeouts = Request<vapi_msg_nat44_ei_set_timeouts, vapi_msg_nat44_ei_set_timeouts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_timeouts_reply>(vapi_msg_nat44_ei_set_timeouts_reply *msg)
{
  vapi_msg_nat44_ei_set_timeouts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_timeouts_reply>(vapi_msg_nat44_ei_set_timeouts_reply *msg)
{
  vapi_msg_nat44_ei_set_timeouts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_timeouts_reply>()
{
  return ::vapi_msg_id_nat44_ei_set_timeouts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_timeouts_reply>>()
{
  return ::vapi_msg_id_nat44_ei_set_timeouts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_timeouts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_timeouts_reply>(vapi_msg_id_nat44_ei_set_timeouts_reply);
}

template class Msg<vapi_msg_nat44_ei_set_timeouts_reply>;

using Nat44_ei_set_timeouts_reply = Msg<vapi_msg_nat44_ei_set_timeouts_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg)
{
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg *msg)
{
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>()
{
  return ::vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>>()
{
  return ::vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_addr_and_port_alloc_alg()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>(vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg);
}

template <> inline vapi_msg_nat44_ei_set_addr_and_port_alloc_alg* vapi_alloc<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>(Connection &con)
{
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg* result = vapi_alloc_nat44_ei_set_addr_and_port_alloc_alg(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg>;

template class Request<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg, vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>;

using Nat44_ei_set_addr_and_port_alloc_alg = Request<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg, vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply *msg)
{
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>(vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply *msg)
{
  vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>()
{
  return ::vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>>()
{
  return ::vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_addr_and_port_alloc_alg_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>(vapi_msg_id_nat44_ei_set_addr_and_port_alloc_alg_reply);
}

template class Msg<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>;

using Nat44_ei_set_addr_and_port_alloc_alg_reply = Msg<vapi_msg_nat44_ei_set_addr_and_port_alloc_alg_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg)
{
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg *msg)
{
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>()
{
  return ::vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>>()
{
  return ::vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_get_addr_and_port_alloc_alg()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>(vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg);
}

template <> inline vapi_msg_nat44_ei_get_addr_and_port_alloc_alg* vapi_alloc<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>(Connection &con)
{
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg* result = vapi_alloc_nat44_ei_get_addr_and_port_alloc_alg(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg>;

template class Request<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg, vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>;

using Nat44_ei_get_addr_and_port_alloc_alg = Request<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg, vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply *msg)
{
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>(vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply *msg)
{
  vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>()
{
  return ::vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>>()
{
  return ::vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_get_addr_and_port_alloc_alg_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>(vapi_msg_id_nat44_ei_get_addr_and_port_alloc_alg_reply);
}

template class Msg<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>;

using Nat44_ei_get_addr_and_port_alloc_alg_reply = Msg<vapi_msg_nat44_ei_get_addr_and_port_alloc_alg_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_mss_clamping>(vapi_msg_nat44_ei_set_mss_clamping *msg)
{
  vapi_msg_nat44_ei_set_mss_clamping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_mss_clamping>(vapi_msg_nat44_ei_set_mss_clamping *msg)
{
  vapi_msg_nat44_ei_set_mss_clamping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_mss_clamping>()
{
  return ::vapi_msg_id_nat44_ei_set_mss_clamping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_mss_clamping>>()
{
  return ::vapi_msg_id_nat44_ei_set_mss_clamping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_mss_clamping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_mss_clamping>(vapi_msg_id_nat44_ei_set_mss_clamping);
}

template <> inline vapi_msg_nat44_ei_set_mss_clamping* vapi_alloc<vapi_msg_nat44_ei_set_mss_clamping>(Connection &con)
{
  vapi_msg_nat44_ei_set_mss_clamping* result = vapi_alloc_nat44_ei_set_mss_clamping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_set_mss_clamping>;

template class Request<vapi_msg_nat44_ei_set_mss_clamping, vapi_msg_nat44_ei_set_mss_clamping_reply>;

using Nat44_ei_set_mss_clamping = Request<vapi_msg_nat44_ei_set_mss_clamping, vapi_msg_nat44_ei_set_mss_clamping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_mss_clamping_reply>(vapi_msg_nat44_ei_set_mss_clamping_reply *msg)
{
  vapi_msg_nat44_ei_set_mss_clamping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_mss_clamping_reply>(vapi_msg_nat44_ei_set_mss_clamping_reply *msg)
{
  vapi_msg_nat44_ei_set_mss_clamping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_mss_clamping_reply>()
{
  return ::vapi_msg_id_nat44_ei_set_mss_clamping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_mss_clamping_reply>>()
{
  return ::vapi_msg_id_nat44_ei_set_mss_clamping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_mss_clamping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_mss_clamping_reply>(vapi_msg_id_nat44_ei_set_mss_clamping_reply);
}

template class Msg<vapi_msg_nat44_ei_set_mss_clamping_reply>;

using Nat44_ei_set_mss_clamping_reply = Msg<vapi_msg_nat44_ei_set_mss_clamping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_get_mss_clamping>(vapi_msg_nat44_ei_get_mss_clamping *msg)
{
  vapi_msg_nat44_ei_get_mss_clamping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_get_mss_clamping>(vapi_msg_nat44_ei_get_mss_clamping *msg)
{
  vapi_msg_nat44_ei_get_mss_clamping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_get_mss_clamping>()
{
  return ::vapi_msg_id_nat44_ei_get_mss_clamping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_get_mss_clamping>>()
{
  return ::vapi_msg_id_nat44_ei_get_mss_clamping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_get_mss_clamping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_get_mss_clamping>(vapi_msg_id_nat44_ei_get_mss_clamping);
}

template <> inline vapi_msg_nat44_ei_get_mss_clamping* vapi_alloc<vapi_msg_nat44_ei_get_mss_clamping>(Connection &con)
{
  vapi_msg_nat44_ei_get_mss_clamping* result = vapi_alloc_nat44_ei_get_mss_clamping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_get_mss_clamping>;

template class Request<vapi_msg_nat44_ei_get_mss_clamping, vapi_msg_nat44_ei_get_mss_clamping_reply>;

using Nat44_ei_get_mss_clamping = Request<vapi_msg_nat44_ei_get_mss_clamping, vapi_msg_nat44_ei_get_mss_clamping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_get_mss_clamping_reply>(vapi_msg_nat44_ei_get_mss_clamping_reply *msg)
{
  vapi_msg_nat44_ei_get_mss_clamping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_get_mss_clamping_reply>(vapi_msg_nat44_ei_get_mss_clamping_reply *msg)
{
  vapi_msg_nat44_ei_get_mss_clamping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_get_mss_clamping_reply>()
{
  return ::vapi_msg_id_nat44_ei_get_mss_clamping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_get_mss_clamping_reply>>()
{
  return ::vapi_msg_id_nat44_ei_get_mss_clamping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_get_mss_clamping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_get_mss_clamping_reply>(vapi_msg_id_nat44_ei_get_mss_clamping_reply);
}

template class Msg<vapi_msg_nat44_ei_get_mss_clamping_reply>;

using Nat44_ei_get_mss_clamping_reply = Msg<vapi_msg_nat44_ei_get_mss_clamping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_set_listener>(vapi_msg_nat44_ei_ha_set_listener *msg)
{
  vapi_msg_nat44_ei_ha_set_listener_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_set_listener>(vapi_msg_nat44_ei_ha_set_listener *msg)
{
  vapi_msg_nat44_ei_ha_set_listener_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_set_listener>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_listener; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_set_listener>>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_listener; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_set_listener()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_set_listener>(vapi_msg_id_nat44_ei_ha_set_listener);
}

template <> inline vapi_msg_nat44_ei_ha_set_listener* vapi_alloc<vapi_msg_nat44_ei_ha_set_listener>(Connection &con)
{
  vapi_msg_nat44_ei_ha_set_listener* result = vapi_alloc_nat44_ei_ha_set_listener(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ha_set_listener>;

template class Request<vapi_msg_nat44_ei_ha_set_listener, vapi_msg_nat44_ei_ha_set_listener_reply>;

using Nat44_ei_ha_set_listener = Request<vapi_msg_nat44_ei_ha_set_listener, vapi_msg_nat44_ei_ha_set_listener_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_set_listener_reply>(vapi_msg_nat44_ei_ha_set_listener_reply *msg)
{
  vapi_msg_nat44_ei_ha_set_listener_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_set_listener_reply>(vapi_msg_nat44_ei_ha_set_listener_reply *msg)
{
  vapi_msg_nat44_ei_ha_set_listener_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_set_listener_reply>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_listener_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_set_listener_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_listener_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_set_listener_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_set_listener_reply>(vapi_msg_id_nat44_ei_ha_set_listener_reply);
}

template class Msg<vapi_msg_nat44_ei_ha_set_listener_reply>;

using Nat44_ei_ha_set_listener_reply = Msg<vapi_msg_nat44_ei_ha_set_listener_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_set_failover>(vapi_msg_nat44_ei_ha_set_failover *msg)
{
  vapi_msg_nat44_ei_ha_set_failover_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_set_failover>(vapi_msg_nat44_ei_ha_set_failover *msg)
{
  vapi_msg_nat44_ei_ha_set_failover_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_set_failover>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_failover; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_set_failover>>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_failover; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_set_failover()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_set_failover>(vapi_msg_id_nat44_ei_ha_set_failover);
}

template <> inline vapi_msg_nat44_ei_ha_set_failover* vapi_alloc<vapi_msg_nat44_ei_ha_set_failover>(Connection &con)
{
  vapi_msg_nat44_ei_ha_set_failover* result = vapi_alloc_nat44_ei_ha_set_failover(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ha_set_failover>;

template class Request<vapi_msg_nat44_ei_ha_set_failover, vapi_msg_nat44_ei_ha_set_failover_reply>;

using Nat44_ei_ha_set_failover = Request<vapi_msg_nat44_ei_ha_set_failover, vapi_msg_nat44_ei_ha_set_failover_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_set_failover_reply>(vapi_msg_nat44_ei_ha_set_failover_reply *msg)
{
  vapi_msg_nat44_ei_ha_set_failover_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_set_failover_reply>(vapi_msg_nat44_ei_ha_set_failover_reply *msg)
{
  vapi_msg_nat44_ei_ha_set_failover_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_set_failover_reply>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_failover_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_set_failover_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ha_set_failover_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_set_failover_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_set_failover_reply>(vapi_msg_id_nat44_ei_ha_set_failover_reply);
}

template class Msg<vapi_msg_nat44_ei_ha_set_failover_reply>;

using Nat44_ei_ha_set_failover_reply = Msg<vapi_msg_nat44_ei_ha_set_failover_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_get_listener>(vapi_msg_nat44_ei_ha_get_listener *msg)
{
  vapi_msg_nat44_ei_ha_get_listener_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_get_listener>(vapi_msg_nat44_ei_ha_get_listener *msg)
{
  vapi_msg_nat44_ei_ha_get_listener_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_get_listener>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_listener; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_get_listener>>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_listener; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_get_listener()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_get_listener>(vapi_msg_id_nat44_ei_ha_get_listener);
}

template <> inline vapi_msg_nat44_ei_ha_get_listener* vapi_alloc<vapi_msg_nat44_ei_ha_get_listener>(Connection &con)
{
  vapi_msg_nat44_ei_ha_get_listener* result = vapi_alloc_nat44_ei_ha_get_listener(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ha_get_listener>;

template class Request<vapi_msg_nat44_ei_ha_get_listener, vapi_msg_nat44_ei_ha_get_listener_reply>;

using Nat44_ei_ha_get_listener = Request<vapi_msg_nat44_ei_ha_get_listener, vapi_msg_nat44_ei_ha_get_listener_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_get_listener_reply>(vapi_msg_nat44_ei_ha_get_listener_reply *msg)
{
  vapi_msg_nat44_ei_ha_get_listener_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_get_listener_reply>(vapi_msg_nat44_ei_ha_get_listener_reply *msg)
{
  vapi_msg_nat44_ei_ha_get_listener_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_get_listener_reply>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_listener_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_get_listener_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_listener_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_get_listener_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_get_listener_reply>(vapi_msg_id_nat44_ei_ha_get_listener_reply);
}

template class Msg<vapi_msg_nat44_ei_ha_get_listener_reply>;

using Nat44_ei_ha_get_listener_reply = Msg<vapi_msg_nat44_ei_ha_get_listener_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_get_failover>(vapi_msg_nat44_ei_ha_get_failover *msg)
{
  vapi_msg_nat44_ei_ha_get_failover_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_get_failover>(vapi_msg_nat44_ei_ha_get_failover *msg)
{
  vapi_msg_nat44_ei_ha_get_failover_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_get_failover>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_failover; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_get_failover>>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_failover; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_get_failover()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_get_failover>(vapi_msg_id_nat44_ei_ha_get_failover);
}

template <> inline vapi_msg_nat44_ei_ha_get_failover* vapi_alloc<vapi_msg_nat44_ei_ha_get_failover>(Connection &con)
{
  vapi_msg_nat44_ei_ha_get_failover* result = vapi_alloc_nat44_ei_ha_get_failover(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ha_get_failover>;

template class Request<vapi_msg_nat44_ei_ha_get_failover, vapi_msg_nat44_ei_ha_get_failover_reply>;

using Nat44_ei_ha_get_failover = Request<vapi_msg_nat44_ei_ha_get_failover, vapi_msg_nat44_ei_ha_get_failover_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_get_failover_reply>(vapi_msg_nat44_ei_ha_get_failover_reply *msg)
{
  vapi_msg_nat44_ei_ha_get_failover_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_get_failover_reply>(vapi_msg_nat44_ei_ha_get_failover_reply *msg)
{
  vapi_msg_nat44_ei_ha_get_failover_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_get_failover_reply>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_failover_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_get_failover_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ha_get_failover_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_get_failover_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_get_failover_reply>(vapi_msg_id_nat44_ei_ha_get_failover_reply);
}

template class Msg<vapi_msg_nat44_ei_ha_get_failover_reply>;

using Nat44_ei_ha_get_failover_reply = Msg<vapi_msg_nat44_ei_ha_get_failover_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_flush>(vapi_msg_nat44_ei_ha_flush *msg)
{
  vapi_msg_nat44_ei_ha_flush_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_flush>(vapi_msg_nat44_ei_ha_flush *msg)
{
  vapi_msg_nat44_ei_ha_flush_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_flush>()
{
  return ::vapi_msg_id_nat44_ei_ha_flush; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_flush>>()
{
  return ::vapi_msg_id_nat44_ei_ha_flush; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_flush()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_flush>(vapi_msg_id_nat44_ei_ha_flush);
}

template <> inline vapi_msg_nat44_ei_ha_flush* vapi_alloc<vapi_msg_nat44_ei_ha_flush>(Connection &con)
{
  vapi_msg_nat44_ei_ha_flush* result = vapi_alloc_nat44_ei_ha_flush(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ha_flush>;

template class Request<vapi_msg_nat44_ei_ha_flush, vapi_msg_nat44_ei_ha_flush_reply>;

using Nat44_ei_ha_flush = Request<vapi_msg_nat44_ei_ha_flush, vapi_msg_nat44_ei_ha_flush_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_flush_reply>(vapi_msg_nat44_ei_ha_flush_reply *msg)
{
  vapi_msg_nat44_ei_ha_flush_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_flush_reply>(vapi_msg_nat44_ei_ha_flush_reply *msg)
{
  vapi_msg_nat44_ei_ha_flush_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_flush_reply>()
{
  return ::vapi_msg_id_nat44_ei_ha_flush_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_flush_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ha_flush_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_flush_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_flush_reply>(vapi_msg_id_nat44_ei_ha_flush_reply);
}

template class Msg<vapi_msg_nat44_ei_ha_flush_reply>;

using Nat44_ei_ha_flush_reply = Msg<vapi_msg_nat44_ei_ha_flush_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_resync>(vapi_msg_nat44_ei_ha_resync *msg)
{
  vapi_msg_nat44_ei_ha_resync_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_resync>(vapi_msg_nat44_ei_ha_resync *msg)
{
  vapi_msg_nat44_ei_ha_resync_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_resync>()
{
  return ::vapi_msg_id_nat44_ei_ha_resync; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_resync>>()
{
  return ::vapi_msg_id_nat44_ei_ha_resync; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_resync()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_resync>(vapi_msg_id_nat44_ei_ha_resync);
}

template <> inline vapi_msg_nat44_ei_ha_resync* vapi_alloc<vapi_msg_nat44_ei_ha_resync>(Connection &con)
{
  vapi_msg_nat44_ei_ha_resync* result = vapi_alloc_nat44_ei_ha_resync(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_ha_resync>;

template class Request<vapi_msg_nat44_ei_ha_resync, vapi_msg_nat44_ei_ha_resync_reply>;

using Nat44_ei_ha_resync = Request<vapi_msg_nat44_ei_ha_resync, vapi_msg_nat44_ei_ha_resync_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_resync_reply>(vapi_msg_nat44_ei_ha_resync_reply *msg)
{
  vapi_msg_nat44_ei_ha_resync_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_resync_reply>(vapi_msg_nat44_ei_ha_resync_reply *msg)
{
  vapi_msg_nat44_ei_ha_resync_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_resync_reply>()
{
  return ::vapi_msg_id_nat44_ei_ha_resync_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_resync_reply>>()
{
  return ::vapi_msg_id_nat44_ei_ha_resync_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_resync_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_resync_reply>(vapi_msg_id_nat44_ei_ha_resync_reply);
}

template class Msg<vapi_msg_nat44_ei_ha_resync_reply>;

using Nat44_ei_ha_resync_reply = Msg<vapi_msg_nat44_ei_ha_resync_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_ha_resync_completed_event>(vapi_msg_nat44_ei_ha_resync_completed_event *msg)
{
  vapi_msg_nat44_ei_ha_resync_completed_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_ha_resync_completed_event>(vapi_msg_nat44_ei_ha_resync_completed_event *msg)
{
  vapi_msg_nat44_ei_ha_resync_completed_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_ha_resync_completed_event>()
{
  return ::vapi_msg_id_nat44_ei_ha_resync_completed_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_ha_resync_completed_event>>()
{
  return ::vapi_msg_id_nat44_ei_ha_resync_completed_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_ha_resync_completed_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_ha_resync_completed_event>(vapi_msg_id_nat44_ei_ha_resync_completed_event);
}

template class Msg<vapi_msg_nat44_ei_ha_resync_completed_event>;

using Nat44_ei_ha_resync_completed_event = Msg<vapi_msg_nat44_ei_ha_resync_completed_event>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_del_user>(vapi_msg_nat44_ei_del_user *msg)
{
  vapi_msg_nat44_ei_del_user_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_del_user>(vapi_msg_nat44_ei_del_user *msg)
{
  vapi_msg_nat44_ei_del_user_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_del_user>()
{
  return ::vapi_msg_id_nat44_ei_del_user; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_del_user>>()
{
  return ::vapi_msg_id_nat44_ei_del_user; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_del_user()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_del_user>(vapi_msg_id_nat44_ei_del_user);
}

template <> inline vapi_msg_nat44_ei_del_user* vapi_alloc<vapi_msg_nat44_ei_del_user>(Connection &con)
{
  vapi_msg_nat44_ei_del_user* result = vapi_alloc_nat44_ei_del_user(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_del_user>;

template class Request<vapi_msg_nat44_ei_del_user, vapi_msg_nat44_ei_del_user_reply>;

using Nat44_ei_del_user = Request<vapi_msg_nat44_ei_del_user, vapi_msg_nat44_ei_del_user_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_del_user_reply>(vapi_msg_nat44_ei_del_user_reply *msg)
{
  vapi_msg_nat44_ei_del_user_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_del_user_reply>(vapi_msg_nat44_ei_del_user_reply *msg)
{
  vapi_msg_nat44_ei_del_user_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_del_user_reply>()
{
  return ::vapi_msg_id_nat44_ei_del_user_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_del_user_reply>>()
{
  return ::vapi_msg_id_nat44_ei_del_user_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_del_user_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_del_user_reply>(vapi_msg_id_nat44_ei_del_user_reply);
}

template class Msg<vapi_msg_nat44_ei_del_user_reply>;

using Nat44_ei_del_user_reply = Msg<vapi_msg_nat44_ei_del_user_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_address_range>(vapi_msg_nat44_ei_add_del_address_range *msg)
{
  vapi_msg_nat44_ei_add_del_address_range_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_address_range>(vapi_msg_nat44_ei_add_del_address_range *msg)
{
  vapi_msg_nat44_ei_add_del_address_range_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_address_range>()
{
  return ::vapi_msg_id_nat44_ei_add_del_address_range; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_address_range>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_address_range; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_address_range()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_address_range>(vapi_msg_id_nat44_ei_add_del_address_range);
}

template <> inline vapi_msg_nat44_ei_add_del_address_range* vapi_alloc<vapi_msg_nat44_ei_add_del_address_range>(Connection &con)
{
  vapi_msg_nat44_ei_add_del_address_range* result = vapi_alloc_nat44_ei_add_del_address_range(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_add_del_address_range>;

template class Request<vapi_msg_nat44_ei_add_del_address_range, vapi_msg_nat44_ei_add_del_address_range_reply>;

using Nat44_ei_add_del_address_range = Request<vapi_msg_nat44_ei_add_del_address_range, vapi_msg_nat44_ei_add_del_address_range_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_address_range_reply>(vapi_msg_nat44_ei_add_del_address_range_reply *msg)
{
  vapi_msg_nat44_ei_add_del_address_range_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_address_range_reply>(vapi_msg_nat44_ei_add_del_address_range_reply *msg)
{
  vapi_msg_nat44_ei_add_del_address_range_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_address_range_reply>()
{
  return ::vapi_msg_id_nat44_ei_add_del_address_range_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_address_range_reply>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_address_range_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_address_range_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_address_range_reply>(vapi_msg_id_nat44_ei_add_del_address_range_reply);
}

template class Msg<vapi_msg_nat44_ei_add_del_address_range_reply>;

using Nat44_ei_add_del_address_range_reply = Msg<vapi_msg_nat44_ei_add_del_address_range_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_address_dump>(vapi_msg_nat44_ei_address_dump *msg)
{
  vapi_msg_nat44_ei_address_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_address_dump>(vapi_msg_nat44_ei_address_dump *msg)
{
  vapi_msg_nat44_ei_address_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_address_dump>()
{
  return ::vapi_msg_id_nat44_ei_address_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_address_dump>>()
{
  return ::vapi_msg_id_nat44_ei_address_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_address_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_address_dump>(vapi_msg_id_nat44_ei_address_dump);
}

template <> inline vapi_msg_nat44_ei_address_dump* vapi_alloc<vapi_msg_nat44_ei_address_dump>(Connection &con)
{
  vapi_msg_nat44_ei_address_dump* result = vapi_alloc_nat44_ei_address_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_address_dump>;

template class Dump<vapi_msg_nat44_ei_address_dump, vapi_msg_nat44_ei_address_details>;

using Nat44_ei_address_dump = Dump<vapi_msg_nat44_ei_address_dump, vapi_msg_nat44_ei_address_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_address_details>(vapi_msg_nat44_ei_address_details *msg)
{
  vapi_msg_nat44_ei_address_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_address_details>(vapi_msg_nat44_ei_address_details *msg)
{
  vapi_msg_nat44_ei_address_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_address_details>()
{
  return ::vapi_msg_id_nat44_ei_address_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_address_details>>()
{
  return ::vapi_msg_id_nat44_ei_address_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_address_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_address_details>(vapi_msg_id_nat44_ei_address_details);
}

template class Msg<vapi_msg_nat44_ei_address_details>;

using Nat44_ei_address_details = Msg<vapi_msg_nat44_ei_address_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_add_del_feature>(vapi_msg_nat44_ei_interface_add_del_feature *msg)
{
  vapi_msg_nat44_ei_interface_add_del_feature_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_add_del_feature>(vapi_msg_nat44_ei_interface_add_del_feature *msg)
{
  vapi_msg_nat44_ei_interface_add_del_feature_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_add_del_feature>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_feature; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_add_del_feature>>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_feature; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_add_del_feature()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_add_del_feature>(vapi_msg_id_nat44_ei_interface_add_del_feature);
}

template <> inline vapi_msg_nat44_ei_interface_add_del_feature* vapi_alloc<vapi_msg_nat44_ei_interface_add_del_feature>(Connection &con)
{
  vapi_msg_nat44_ei_interface_add_del_feature* result = vapi_alloc_nat44_ei_interface_add_del_feature(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_interface_add_del_feature>;

template class Request<vapi_msg_nat44_ei_interface_add_del_feature, vapi_msg_nat44_ei_interface_add_del_feature_reply>;

using Nat44_ei_interface_add_del_feature = Request<vapi_msg_nat44_ei_interface_add_del_feature, vapi_msg_nat44_ei_interface_add_del_feature_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_add_del_feature_reply>(vapi_msg_nat44_ei_interface_add_del_feature_reply *msg)
{
  vapi_msg_nat44_ei_interface_add_del_feature_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_add_del_feature_reply>(vapi_msg_nat44_ei_interface_add_del_feature_reply *msg)
{
  vapi_msg_nat44_ei_interface_add_del_feature_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_add_del_feature_reply>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_feature_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_add_del_feature_reply>>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_feature_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_add_del_feature_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_add_del_feature_reply>(vapi_msg_id_nat44_ei_interface_add_del_feature_reply);
}

template class Msg<vapi_msg_nat44_ei_interface_add_del_feature_reply>;

using Nat44_ei_interface_add_del_feature_reply = Msg<vapi_msg_nat44_ei_interface_add_del_feature_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_dump>(vapi_msg_nat44_ei_interface_dump *msg)
{
  vapi_msg_nat44_ei_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_dump>(vapi_msg_nat44_ei_interface_dump *msg)
{
  vapi_msg_nat44_ei_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_dump>()
{
  return ::vapi_msg_id_nat44_ei_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_dump>>()
{
  return ::vapi_msg_id_nat44_ei_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_dump>(vapi_msg_id_nat44_ei_interface_dump);
}

template <> inline vapi_msg_nat44_ei_interface_dump* vapi_alloc<vapi_msg_nat44_ei_interface_dump>(Connection &con)
{
  vapi_msg_nat44_ei_interface_dump* result = vapi_alloc_nat44_ei_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_interface_dump>;

template class Dump<vapi_msg_nat44_ei_interface_dump, vapi_msg_nat44_ei_interface_details>;

using Nat44_ei_interface_dump = Dump<vapi_msg_nat44_ei_interface_dump, vapi_msg_nat44_ei_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_details>(vapi_msg_nat44_ei_interface_details *msg)
{
  vapi_msg_nat44_ei_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_details>(vapi_msg_nat44_ei_interface_details *msg)
{
  vapi_msg_nat44_ei_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_details>()
{
  return ::vapi_msg_id_nat44_ei_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_details>>()
{
  return ::vapi_msg_id_nat44_ei_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_details>(vapi_msg_id_nat44_ei_interface_details);
}

template class Msg<vapi_msg_nat44_ei_interface_details>;

using Nat44_ei_interface_details = Msg<vapi_msg_nat44_ei_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_add_del_output_feature>(vapi_msg_nat44_ei_interface_add_del_output_feature *msg)
{
  vapi_msg_nat44_ei_interface_add_del_output_feature_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_add_del_output_feature>(vapi_msg_nat44_ei_interface_add_del_output_feature *msg)
{
  vapi_msg_nat44_ei_interface_add_del_output_feature_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_add_del_output_feature>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_output_feature; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_add_del_output_feature>>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_output_feature; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_add_del_output_feature()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_add_del_output_feature>(vapi_msg_id_nat44_ei_interface_add_del_output_feature);
}

template <> inline vapi_msg_nat44_ei_interface_add_del_output_feature* vapi_alloc<vapi_msg_nat44_ei_interface_add_del_output_feature>(Connection &con)
{
  vapi_msg_nat44_ei_interface_add_del_output_feature* result = vapi_alloc_nat44_ei_interface_add_del_output_feature(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_interface_add_del_output_feature>;

template class Request<vapi_msg_nat44_ei_interface_add_del_output_feature, vapi_msg_nat44_ei_interface_add_del_output_feature_reply>;

using Nat44_ei_interface_add_del_output_feature = Request<vapi_msg_nat44_ei_interface_add_del_output_feature, vapi_msg_nat44_ei_interface_add_del_output_feature_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>(vapi_msg_nat44_ei_interface_add_del_output_feature_reply *msg)
{
  vapi_msg_nat44_ei_interface_add_del_output_feature_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>(vapi_msg_nat44_ei_interface_add_del_output_feature_reply *msg)
{
  vapi_msg_nat44_ei_interface_add_del_output_feature_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>>()
{
  return ::vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_add_del_output_feature_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>(vapi_msg_id_nat44_ei_interface_add_del_output_feature_reply);
}

template class Msg<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>;

using Nat44_ei_interface_add_del_output_feature_reply = Msg<vapi_msg_nat44_ei_interface_add_del_output_feature_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_output_feature_dump>(vapi_msg_nat44_ei_interface_output_feature_dump *msg)
{
  vapi_msg_nat44_ei_interface_output_feature_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_output_feature_dump>(vapi_msg_nat44_ei_interface_output_feature_dump *msg)
{
  vapi_msg_nat44_ei_interface_output_feature_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_output_feature_dump>()
{
  return ::vapi_msg_id_nat44_ei_interface_output_feature_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_output_feature_dump>>()
{
  return ::vapi_msg_id_nat44_ei_interface_output_feature_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_output_feature_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_output_feature_dump>(vapi_msg_id_nat44_ei_interface_output_feature_dump);
}

template <> inline vapi_msg_nat44_ei_interface_output_feature_dump* vapi_alloc<vapi_msg_nat44_ei_interface_output_feature_dump>(Connection &con)
{
  vapi_msg_nat44_ei_interface_output_feature_dump* result = vapi_alloc_nat44_ei_interface_output_feature_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_interface_output_feature_dump>;

template class Dump<vapi_msg_nat44_ei_interface_output_feature_dump, vapi_msg_nat44_ei_interface_output_feature_details>;

using Nat44_ei_interface_output_feature_dump = Dump<vapi_msg_nat44_ei_interface_output_feature_dump, vapi_msg_nat44_ei_interface_output_feature_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_output_feature_details>(vapi_msg_nat44_ei_interface_output_feature_details *msg)
{
  vapi_msg_nat44_ei_interface_output_feature_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_output_feature_details>(vapi_msg_nat44_ei_interface_output_feature_details *msg)
{
  vapi_msg_nat44_ei_interface_output_feature_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_output_feature_details>()
{
  return ::vapi_msg_id_nat44_ei_interface_output_feature_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_output_feature_details>>()
{
  return ::vapi_msg_id_nat44_ei_interface_output_feature_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_output_feature_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_output_feature_details>(vapi_msg_id_nat44_ei_interface_output_feature_details);
}

template class Msg<vapi_msg_nat44_ei_interface_output_feature_details>;

using Nat44_ei_interface_output_feature_details = Msg<vapi_msg_nat44_ei_interface_output_feature_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_output_interface>(vapi_msg_nat44_ei_add_del_output_interface *msg)
{
  vapi_msg_nat44_ei_add_del_output_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_output_interface>(vapi_msg_nat44_ei_add_del_output_interface *msg)
{
  vapi_msg_nat44_ei_add_del_output_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_output_interface>()
{
  return ::vapi_msg_id_nat44_ei_add_del_output_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_output_interface>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_output_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_output_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_output_interface>(vapi_msg_id_nat44_ei_add_del_output_interface);
}

template <> inline vapi_msg_nat44_ei_add_del_output_interface* vapi_alloc<vapi_msg_nat44_ei_add_del_output_interface>(Connection &con)
{
  vapi_msg_nat44_ei_add_del_output_interface* result = vapi_alloc_nat44_ei_add_del_output_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_add_del_output_interface>;

template class Request<vapi_msg_nat44_ei_add_del_output_interface, vapi_msg_nat44_ei_add_del_output_interface_reply>;

using Nat44_ei_add_del_output_interface = Request<vapi_msg_nat44_ei_add_del_output_interface, vapi_msg_nat44_ei_add_del_output_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_output_interface_reply>(vapi_msg_nat44_ei_add_del_output_interface_reply *msg)
{
  vapi_msg_nat44_ei_add_del_output_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_output_interface_reply>(vapi_msg_nat44_ei_add_del_output_interface_reply *msg)
{
  vapi_msg_nat44_ei_add_del_output_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_output_interface_reply>()
{
  return ::vapi_msg_id_nat44_ei_add_del_output_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_output_interface_reply>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_output_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_output_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_output_interface_reply>(vapi_msg_id_nat44_ei_add_del_output_interface_reply);
}

template class Msg<vapi_msg_nat44_ei_add_del_output_interface_reply>;

using Nat44_ei_add_del_output_interface_reply = Msg<vapi_msg_nat44_ei_add_del_output_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_output_interface_get>(vapi_msg_nat44_ei_output_interface_get *msg)
{
  vapi_msg_nat44_ei_output_interface_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_output_interface_get>(vapi_msg_nat44_ei_output_interface_get *msg)
{
  vapi_msg_nat44_ei_output_interface_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_output_interface_get>()
{
  return ::vapi_msg_id_nat44_ei_output_interface_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_output_interface_get>>()
{
  return ::vapi_msg_id_nat44_ei_output_interface_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_output_interface_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_output_interface_get>(vapi_msg_id_nat44_ei_output_interface_get);
}

template <> inline vapi_msg_nat44_ei_output_interface_get* vapi_alloc<vapi_msg_nat44_ei_output_interface_get>(Connection &con)
{
  vapi_msg_nat44_ei_output_interface_get* result = vapi_alloc_nat44_ei_output_interface_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_output_interface_get>;

template class Stream<vapi_msg_nat44_ei_output_interface_get, vapi_msg_nat44_ei_output_interface_get_reply, vapi_msg_nat44_ei_output_interface_details>;

using Nat44_ei_output_interface_get = Stream<vapi_msg_nat44_ei_output_interface_get, vapi_msg_nat44_ei_output_interface_get_reply, vapi_msg_nat44_ei_output_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_output_interface_get_reply>(vapi_msg_nat44_ei_output_interface_get_reply *msg)
{
  vapi_msg_nat44_ei_output_interface_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_output_interface_get_reply>(vapi_msg_nat44_ei_output_interface_get_reply *msg)
{
  vapi_msg_nat44_ei_output_interface_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_output_interface_get_reply>()
{
  return ::vapi_msg_id_nat44_ei_output_interface_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_output_interface_get_reply>>()
{
  return ::vapi_msg_id_nat44_ei_output_interface_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_output_interface_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_output_interface_get_reply>(vapi_msg_id_nat44_ei_output_interface_get_reply);
}

template class Msg<vapi_msg_nat44_ei_output_interface_get_reply>;

using Nat44_ei_output_interface_get_reply = Msg<vapi_msg_nat44_ei_output_interface_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_output_interface_details>(vapi_msg_nat44_ei_output_interface_details *msg)
{
  vapi_msg_nat44_ei_output_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_output_interface_details>(vapi_msg_nat44_ei_output_interface_details *msg)
{
  vapi_msg_nat44_ei_output_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_output_interface_details>()
{
  return ::vapi_msg_id_nat44_ei_output_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_output_interface_details>>()
{
  return ::vapi_msg_id_nat44_ei_output_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_output_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_output_interface_details>(vapi_msg_id_nat44_ei_output_interface_details);
}

template class Msg<vapi_msg_nat44_ei_output_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_static_mapping>(vapi_msg_nat44_ei_add_del_static_mapping *msg)
{
  vapi_msg_nat44_ei_add_del_static_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_static_mapping>(vapi_msg_nat44_ei_add_del_static_mapping *msg)
{
  vapi_msg_nat44_ei_add_del_static_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_static_mapping>()
{
  return ::vapi_msg_id_nat44_ei_add_del_static_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_static_mapping>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_static_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_static_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_static_mapping>(vapi_msg_id_nat44_ei_add_del_static_mapping);
}

template <> inline vapi_msg_nat44_ei_add_del_static_mapping* vapi_alloc<vapi_msg_nat44_ei_add_del_static_mapping>(Connection &con)
{
  vapi_msg_nat44_ei_add_del_static_mapping* result = vapi_alloc_nat44_ei_add_del_static_mapping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_add_del_static_mapping>;

template class Request<vapi_msg_nat44_ei_add_del_static_mapping, vapi_msg_nat44_ei_add_del_static_mapping_reply>;

using Nat44_ei_add_del_static_mapping = Request<vapi_msg_nat44_ei_add_del_static_mapping, vapi_msg_nat44_ei_add_del_static_mapping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_static_mapping_reply>(vapi_msg_nat44_ei_add_del_static_mapping_reply *msg)
{
  vapi_msg_nat44_ei_add_del_static_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_static_mapping_reply>(vapi_msg_nat44_ei_add_del_static_mapping_reply *msg)
{
  vapi_msg_nat44_ei_add_del_static_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_static_mapping_reply>()
{
  return ::vapi_msg_id_nat44_ei_add_del_static_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_static_mapping_reply>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_static_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_static_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_static_mapping_reply>(vapi_msg_id_nat44_ei_add_del_static_mapping_reply);
}

template class Msg<vapi_msg_nat44_ei_add_del_static_mapping_reply>;

using Nat44_ei_add_del_static_mapping_reply = Msg<vapi_msg_nat44_ei_add_del_static_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_static_mapping_dump>(vapi_msg_nat44_ei_static_mapping_dump *msg)
{
  vapi_msg_nat44_ei_static_mapping_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_static_mapping_dump>(vapi_msg_nat44_ei_static_mapping_dump *msg)
{
  vapi_msg_nat44_ei_static_mapping_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_static_mapping_dump>()
{
  return ::vapi_msg_id_nat44_ei_static_mapping_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_static_mapping_dump>>()
{
  return ::vapi_msg_id_nat44_ei_static_mapping_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_static_mapping_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_static_mapping_dump>(vapi_msg_id_nat44_ei_static_mapping_dump);
}

template <> inline vapi_msg_nat44_ei_static_mapping_dump* vapi_alloc<vapi_msg_nat44_ei_static_mapping_dump>(Connection &con)
{
  vapi_msg_nat44_ei_static_mapping_dump* result = vapi_alloc_nat44_ei_static_mapping_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_static_mapping_dump>;

template class Dump<vapi_msg_nat44_ei_static_mapping_dump, vapi_msg_nat44_ei_static_mapping_details>;

using Nat44_ei_static_mapping_dump = Dump<vapi_msg_nat44_ei_static_mapping_dump, vapi_msg_nat44_ei_static_mapping_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_static_mapping_details>(vapi_msg_nat44_ei_static_mapping_details *msg)
{
  vapi_msg_nat44_ei_static_mapping_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_static_mapping_details>(vapi_msg_nat44_ei_static_mapping_details *msg)
{
  vapi_msg_nat44_ei_static_mapping_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_static_mapping_details>()
{
  return ::vapi_msg_id_nat44_ei_static_mapping_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_static_mapping_details>>()
{
  return ::vapi_msg_id_nat44_ei_static_mapping_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_static_mapping_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_static_mapping_details>(vapi_msg_id_nat44_ei_static_mapping_details);
}

template class Msg<vapi_msg_nat44_ei_static_mapping_details>;

using Nat44_ei_static_mapping_details = Msg<vapi_msg_nat44_ei_static_mapping_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_identity_mapping>(vapi_msg_nat44_ei_add_del_identity_mapping *msg)
{
  vapi_msg_nat44_ei_add_del_identity_mapping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_identity_mapping>(vapi_msg_nat44_ei_add_del_identity_mapping *msg)
{
  vapi_msg_nat44_ei_add_del_identity_mapping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_identity_mapping>()
{
  return ::vapi_msg_id_nat44_ei_add_del_identity_mapping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_identity_mapping>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_identity_mapping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_identity_mapping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_identity_mapping>(vapi_msg_id_nat44_ei_add_del_identity_mapping);
}

template <> inline vapi_msg_nat44_ei_add_del_identity_mapping* vapi_alloc<vapi_msg_nat44_ei_add_del_identity_mapping>(Connection &con)
{
  vapi_msg_nat44_ei_add_del_identity_mapping* result = vapi_alloc_nat44_ei_add_del_identity_mapping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_add_del_identity_mapping>;

template class Request<vapi_msg_nat44_ei_add_del_identity_mapping, vapi_msg_nat44_ei_add_del_identity_mapping_reply>;

using Nat44_ei_add_del_identity_mapping = Request<vapi_msg_nat44_ei_add_del_identity_mapping, vapi_msg_nat44_ei_add_del_identity_mapping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_identity_mapping_reply>(vapi_msg_nat44_ei_add_del_identity_mapping_reply *msg)
{
  vapi_msg_nat44_ei_add_del_identity_mapping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_identity_mapping_reply>(vapi_msg_nat44_ei_add_del_identity_mapping_reply *msg)
{
  vapi_msg_nat44_ei_add_del_identity_mapping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_identity_mapping_reply>()
{
  return ::vapi_msg_id_nat44_ei_add_del_identity_mapping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_identity_mapping_reply>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_identity_mapping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_identity_mapping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_identity_mapping_reply>(vapi_msg_id_nat44_ei_add_del_identity_mapping_reply);
}

template class Msg<vapi_msg_nat44_ei_add_del_identity_mapping_reply>;

using Nat44_ei_add_del_identity_mapping_reply = Msg<vapi_msg_nat44_ei_add_del_identity_mapping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_identity_mapping_dump>(vapi_msg_nat44_ei_identity_mapping_dump *msg)
{
  vapi_msg_nat44_ei_identity_mapping_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_identity_mapping_dump>(vapi_msg_nat44_ei_identity_mapping_dump *msg)
{
  vapi_msg_nat44_ei_identity_mapping_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_identity_mapping_dump>()
{
  return ::vapi_msg_id_nat44_ei_identity_mapping_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_identity_mapping_dump>>()
{
  return ::vapi_msg_id_nat44_ei_identity_mapping_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_identity_mapping_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_identity_mapping_dump>(vapi_msg_id_nat44_ei_identity_mapping_dump);
}

template <> inline vapi_msg_nat44_ei_identity_mapping_dump* vapi_alloc<vapi_msg_nat44_ei_identity_mapping_dump>(Connection &con)
{
  vapi_msg_nat44_ei_identity_mapping_dump* result = vapi_alloc_nat44_ei_identity_mapping_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_identity_mapping_dump>;

template class Dump<vapi_msg_nat44_ei_identity_mapping_dump, vapi_msg_nat44_ei_identity_mapping_details>;

using Nat44_ei_identity_mapping_dump = Dump<vapi_msg_nat44_ei_identity_mapping_dump, vapi_msg_nat44_ei_identity_mapping_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_identity_mapping_details>(vapi_msg_nat44_ei_identity_mapping_details *msg)
{
  vapi_msg_nat44_ei_identity_mapping_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_identity_mapping_details>(vapi_msg_nat44_ei_identity_mapping_details *msg)
{
  vapi_msg_nat44_ei_identity_mapping_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_identity_mapping_details>()
{
  return ::vapi_msg_id_nat44_ei_identity_mapping_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_identity_mapping_details>>()
{
  return ::vapi_msg_id_nat44_ei_identity_mapping_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_identity_mapping_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_identity_mapping_details>(vapi_msg_id_nat44_ei_identity_mapping_details);
}

template class Msg<vapi_msg_nat44_ei_identity_mapping_details>;

using Nat44_ei_identity_mapping_details = Msg<vapi_msg_nat44_ei_identity_mapping_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_interface_addr>(vapi_msg_nat44_ei_add_del_interface_addr *msg)
{
  vapi_msg_nat44_ei_add_del_interface_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_interface_addr>(vapi_msg_nat44_ei_add_del_interface_addr *msg)
{
  vapi_msg_nat44_ei_add_del_interface_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_interface_addr>()
{
  return ::vapi_msg_id_nat44_ei_add_del_interface_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_interface_addr>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_interface_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_interface_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_interface_addr>(vapi_msg_id_nat44_ei_add_del_interface_addr);
}

template <> inline vapi_msg_nat44_ei_add_del_interface_addr* vapi_alloc<vapi_msg_nat44_ei_add_del_interface_addr>(Connection &con)
{
  vapi_msg_nat44_ei_add_del_interface_addr* result = vapi_alloc_nat44_ei_add_del_interface_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_add_del_interface_addr>;

template class Request<vapi_msg_nat44_ei_add_del_interface_addr, vapi_msg_nat44_ei_add_del_interface_addr_reply>;

using Nat44_ei_add_del_interface_addr = Request<vapi_msg_nat44_ei_add_del_interface_addr, vapi_msg_nat44_ei_add_del_interface_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_add_del_interface_addr_reply>(vapi_msg_nat44_ei_add_del_interface_addr_reply *msg)
{
  vapi_msg_nat44_ei_add_del_interface_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_add_del_interface_addr_reply>(vapi_msg_nat44_ei_add_del_interface_addr_reply *msg)
{
  vapi_msg_nat44_ei_add_del_interface_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_add_del_interface_addr_reply>()
{
  return ::vapi_msg_id_nat44_ei_add_del_interface_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_add_del_interface_addr_reply>>()
{
  return ::vapi_msg_id_nat44_ei_add_del_interface_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_add_del_interface_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_add_del_interface_addr_reply>(vapi_msg_id_nat44_ei_add_del_interface_addr_reply);
}

template class Msg<vapi_msg_nat44_ei_add_del_interface_addr_reply>;

using Nat44_ei_add_del_interface_addr_reply = Msg<vapi_msg_nat44_ei_add_del_interface_addr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_addr_dump>(vapi_msg_nat44_ei_interface_addr_dump *msg)
{
  vapi_msg_nat44_ei_interface_addr_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_addr_dump>(vapi_msg_nat44_ei_interface_addr_dump *msg)
{
  vapi_msg_nat44_ei_interface_addr_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_addr_dump>()
{
  return ::vapi_msg_id_nat44_ei_interface_addr_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_addr_dump>>()
{
  return ::vapi_msg_id_nat44_ei_interface_addr_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_addr_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_addr_dump>(vapi_msg_id_nat44_ei_interface_addr_dump);
}

template <> inline vapi_msg_nat44_ei_interface_addr_dump* vapi_alloc<vapi_msg_nat44_ei_interface_addr_dump>(Connection &con)
{
  vapi_msg_nat44_ei_interface_addr_dump* result = vapi_alloc_nat44_ei_interface_addr_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_interface_addr_dump>;

template class Dump<vapi_msg_nat44_ei_interface_addr_dump, vapi_msg_nat44_ei_interface_addr_details>;

using Nat44_ei_interface_addr_dump = Dump<vapi_msg_nat44_ei_interface_addr_dump, vapi_msg_nat44_ei_interface_addr_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_interface_addr_details>(vapi_msg_nat44_ei_interface_addr_details *msg)
{
  vapi_msg_nat44_ei_interface_addr_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_interface_addr_details>(vapi_msg_nat44_ei_interface_addr_details *msg)
{
  vapi_msg_nat44_ei_interface_addr_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_interface_addr_details>()
{
  return ::vapi_msg_id_nat44_ei_interface_addr_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_interface_addr_details>>()
{
  return ::vapi_msg_id_nat44_ei_interface_addr_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_interface_addr_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_interface_addr_details>(vapi_msg_id_nat44_ei_interface_addr_details);
}

template class Msg<vapi_msg_nat44_ei_interface_addr_details>;

using Nat44_ei_interface_addr_details = Msg<vapi_msg_nat44_ei_interface_addr_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_user_dump>(vapi_msg_nat44_ei_user_dump *msg)
{
  vapi_msg_nat44_ei_user_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_user_dump>(vapi_msg_nat44_ei_user_dump *msg)
{
  vapi_msg_nat44_ei_user_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_user_dump>()
{
  return ::vapi_msg_id_nat44_ei_user_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_user_dump>>()
{
  return ::vapi_msg_id_nat44_ei_user_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_user_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_user_dump>(vapi_msg_id_nat44_ei_user_dump);
}

template <> inline vapi_msg_nat44_ei_user_dump* vapi_alloc<vapi_msg_nat44_ei_user_dump>(Connection &con)
{
  vapi_msg_nat44_ei_user_dump* result = vapi_alloc_nat44_ei_user_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_user_dump>;

template class Dump<vapi_msg_nat44_ei_user_dump, vapi_msg_nat44_ei_user_details>;

using Nat44_ei_user_dump = Dump<vapi_msg_nat44_ei_user_dump, vapi_msg_nat44_ei_user_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_user_details>(vapi_msg_nat44_ei_user_details *msg)
{
  vapi_msg_nat44_ei_user_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_user_details>(vapi_msg_nat44_ei_user_details *msg)
{
  vapi_msg_nat44_ei_user_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_user_details>()
{
  return ::vapi_msg_id_nat44_ei_user_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_user_details>>()
{
  return ::vapi_msg_id_nat44_ei_user_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_user_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_user_details>(vapi_msg_id_nat44_ei_user_details);
}

template class Msg<vapi_msg_nat44_ei_user_details>;

using Nat44_ei_user_details = Msg<vapi_msg_nat44_ei_user_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_user_session_dump>(vapi_msg_nat44_ei_user_session_dump *msg)
{
  vapi_msg_nat44_ei_user_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_user_session_dump>(vapi_msg_nat44_ei_user_session_dump *msg)
{
  vapi_msg_nat44_ei_user_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_user_session_dump>()
{
  return ::vapi_msg_id_nat44_ei_user_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_user_session_dump>>()
{
  return ::vapi_msg_id_nat44_ei_user_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_user_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_user_session_dump>(vapi_msg_id_nat44_ei_user_session_dump);
}

template <> inline vapi_msg_nat44_ei_user_session_dump* vapi_alloc<vapi_msg_nat44_ei_user_session_dump>(Connection &con)
{
  vapi_msg_nat44_ei_user_session_dump* result = vapi_alloc_nat44_ei_user_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_user_session_dump>;

template class Dump<vapi_msg_nat44_ei_user_session_dump, vapi_msg_nat44_ei_user_session_details>;

using Nat44_ei_user_session_dump = Dump<vapi_msg_nat44_ei_user_session_dump, vapi_msg_nat44_ei_user_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_user_session_details>(vapi_msg_nat44_ei_user_session_details *msg)
{
  vapi_msg_nat44_ei_user_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_user_session_details>(vapi_msg_nat44_ei_user_session_details *msg)
{
  vapi_msg_nat44_ei_user_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_user_session_details>()
{
  return ::vapi_msg_id_nat44_ei_user_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_user_session_details>>()
{
  return ::vapi_msg_id_nat44_ei_user_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_user_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_user_session_details>(vapi_msg_id_nat44_ei_user_session_details);
}

template class Msg<vapi_msg_nat44_ei_user_session_details>;

using Nat44_ei_user_session_details = Msg<vapi_msg_nat44_ei_user_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_user_session_v2_dump>(vapi_msg_nat44_ei_user_session_v2_dump *msg)
{
  vapi_msg_nat44_ei_user_session_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_user_session_v2_dump>(vapi_msg_nat44_ei_user_session_v2_dump *msg)
{
  vapi_msg_nat44_ei_user_session_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_user_session_v2_dump>()
{
  return ::vapi_msg_id_nat44_ei_user_session_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_user_session_v2_dump>>()
{
  return ::vapi_msg_id_nat44_ei_user_session_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_user_session_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_user_session_v2_dump>(vapi_msg_id_nat44_ei_user_session_v2_dump);
}

template <> inline vapi_msg_nat44_ei_user_session_v2_dump* vapi_alloc<vapi_msg_nat44_ei_user_session_v2_dump>(Connection &con)
{
  vapi_msg_nat44_ei_user_session_v2_dump* result = vapi_alloc_nat44_ei_user_session_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_user_session_v2_dump>;

template class Dump<vapi_msg_nat44_ei_user_session_v2_dump, vapi_msg_nat44_ei_user_session_v2_details>;

using Nat44_ei_user_session_v2_dump = Dump<vapi_msg_nat44_ei_user_session_v2_dump, vapi_msg_nat44_ei_user_session_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_user_session_v2_details>(vapi_msg_nat44_ei_user_session_v2_details *msg)
{
  vapi_msg_nat44_ei_user_session_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_user_session_v2_details>(vapi_msg_nat44_ei_user_session_v2_details *msg)
{
  vapi_msg_nat44_ei_user_session_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_user_session_v2_details>()
{
  return ::vapi_msg_id_nat44_ei_user_session_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_user_session_v2_details>>()
{
  return ::vapi_msg_id_nat44_ei_user_session_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_user_session_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_user_session_v2_details>(vapi_msg_id_nat44_ei_user_session_v2_details);
}

template class Msg<vapi_msg_nat44_ei_user_session_v2_details>;

using Nat44_ei_user_session_v2_details = Msg<vapi_msg_nat44_ei_user_session_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_del_session>(vapi_msg_nat44_ei_del_session *msg)
{
  vapi_msg_nat44_ei_del_session_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_del_session>(vapi_msg_nat44_ei_del_session *msg)
{
  vapi_msg_nat44_ei_del_session_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_del_session>()
{
  return ::vapi_msg_id_nat44_ei_del_session; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_del_session>>()
{
  return ::vapi_msg_id_nat44_ei_del_session; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_del_session()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_del_session>(vapi_msg_id_nat44_ei_del_session);
}

template <> inline vapi_msg_nat44_ei_del_session* vapi_alloc<vapi_msg_nat44_ei_del_session>(Connection &con)
{
  vapi_msg_nat44_ei_del_session* result = vapi_alloc_nat44_ei_del_session(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_del_session>;

template class Request<vapi_msg_nat44_ei_del_session, vapi_msg_nat44_ei_del_session_reply>;

using Nat44_ei_del_session = Request<vapi_msg_nat44_ei_del_session, vapi_msg_nat44_ei_del_session_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_del_session_reply>(vapi_msg_nat44_ei_del_session_reply *msg)
{
  vapi_msg_nat44_ei_del_session_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_del_session_reply>(vapi_msg_nat44_ei_del_session_reply *msg)
{
  vapi_msg_nat44_ei_del_session_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_del_session_reply>()
{
  return ::vapi_msg_id_nat44_ei_del_session_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_del_session_reply>>()
{
  return ::vapi_msg_id_nat44_ei_del_session_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_del_session_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_del_session_reply>(vapi_msg_id_nat44_ei_del_session_reply);
}

template class Msg<vapi_msg_nat44_ei_del_session_reply>;

using Nat44_ei_del_session_reply = Msg<vapi_msg_nat44_ei_del_session_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_forwarding_enable_disable>(vapi_msg_nat44_ei_forwarding_enable_disable *msg)
{
  vapi_msg_nat44_ei_forwarding_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_forwarding_enable_disable>(vapi_msg_nat44_ei_forwarding_enable_disable *msg)
{
  vapi_msg_nat44_ei_forwarding_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_forwarding_enable_disable>()
{
  return ::vapi_msg_id_nat44_ei_forwarding_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_forwarding_enable_disable>>()
{
  return ::vapi_msg_id_nat44_ei_forwarding_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_forwarding_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_forwarding_enable_disable>(vapi_msg_id_nat44_ei_forwarding_enable_disable);
}

template <> inline vapi_msg_nat44_ei_forwarding_enable_disable* vapi_alloc<vapi_msg_nat44_ei_forwarding_enable_disable>(Connection &con)
{
  vapi_msg_nat44_ei_forwarding_enable_disable* result = vapi_alloc_nat44_ei_forwarding_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_forwarding_enable_disable>;

template class Request<vapi_msg_nat44_ei_forwarding_enable_disable, vapi_msg_nat44_ei_forwarding_enable_disable_reply>;

using Nat44_ei_forwarding_enable_disable = Request<vapi_msg_nat44_ei_forwarding_enable_disable, vapi_msg_nat44_ei_forwarding_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_forwarding_enable_disable_reply>(vapi_msg_nat44_ei_forwarding_enable_disable_reply *msg)
{
  vapi_msg_nat44_ei_forwarding_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_forwarding_enable_disable_reply>(vapi_msg_nat44_ei_forwarding_enable_disable_reply *msg)
{
  vapi_msg_nat44_ei_forwarding_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_forwarding_enable_disable_reply>()
{
  return ::vapi_msg_id_nat44_ei_forwarding_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_forwarding_enable_disable_reply>>()
{
  return ::vapi_msg_id_nat44_ei_forwarding_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_forwarding_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_forwarding_enable_disable_reply>(vapi_msg_id_nat44_ei_forwarding_enable_disable_reply);
}

template class Msg<vapi_msg_nat44_ei_forwarding_enable_disable_reply>;

using Nat44_ei_forwarding_enable_disable_reply = Msg<vapi_msg_nat44_ei_forwarding_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_fq_options>(vapi_msg_nat44_ei_set_fq_options *msg)
{
  vapi_msg_nat44_ei_set_fq_options_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_fq_options>(vapi_msg_nat44_ei_set_fq_options *msg)
{
  vapi_msg_nat44_ei_set_fq_options_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_fq_options>()
{
  return ::vapi_msg_id_nat44_ei_set_fq_options; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_fq_options>>()
{
  return ::vapi_msg_id_nat44_ei_set_fq_options; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_fq_options()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_fq_options>(vapi_msg_id_nat44_ei_set_fq_options);
}

template <> inline vapi_msg_nat44_ei_set_fq_options* vapi_alloc<vapi_msg_nat44_ei_set_fq_options>(Connection &con)
{
  vapi_msg_nat44_ei_set_fq_options* result = vapi_alloc_nat44_ei_set_fq_options(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_set_fq_options>;

template class Request<vapi_msg_nat44_ei_set_fq_options, vapi_msg_nat44_ei_set_fq_options_reply>;

using Nat44_ei_set_fq_options = Request<vapi_msg_nat44_ei_set_fq_options, vapi_msg_nat44_ei_set_fq_options_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_set_fq_options_reply>(vapi_msg_nat44_ei_set_fq_options_reply *msg)
{
  vapi_msg_nat44_ei_set_fq_options_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_set_fq_options_reply>(vapi_msg_nat44_ei_set_fq_options_reply *msg)
{
  vapi_msg_nat44_ei_set_fq_options_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_set_fq_options_reply>()
{
  return ::vapi_msg_id_nat44_ei_set_fq_options_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_set_fq_options_reply>>()
{
  return ::vapi_msg_id_nat44_ei_set_fq_options_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_set_fq_options_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_set_fq_options_reply>(vapi_msg_id_nat44_ei_set_fq_options_reply);
}

template class Msg<vapi_msg_nat44_ei_set_fq_options_reply>;

using Nat44_ei_set_fq_options_reply = Msg<vapi_msg_nat44_ei_set_fq_options_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_show_fq_options>(vapi_msg_nat44_ei_show_fq_options *msg)
{
  vapi_msg_nat44_ei_show_fq_options_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_show_fq_options>(vapi_msg_nat44_ei_show_fq_options *msg)
{
  vapi_msg_nat44_ei_show_fq_options_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_show_fq_options>()
{
  return ::vapi_msg_id_nat44_ei_show_fq_options; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_show_fq_options>>()
{
  return ::vapi_msg_id_nat44_ei_show_fq_options; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_show_fq_options()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_show_fq_options>(vapi_msg_id_nat44_ei_show_fq_options);
}

template <> inline vapi_msg_nat44_ei_show_fq_options* vapi_alloc<vapi_msg_nat44_ei_show_fq_options>(Connection &con)
{
  vapi_msg_nat44_ei_show_fq_options* result = vapi_alloc_nat44_ei_show_fq_options(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nat44_ei_show_fq_options>;

template class Request<vapi_msg_nat44_ei_show_fq_options, vapi_msg_nat44_ei_show_fq_options_reply>;

using Nat44_ei_show_fq_options = Request<vapi_msg_nat44_ei_show_fq_options, vapi_msg_nat44_ei_show_fq_options_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nat44_ei_show_fq_options_reply>(vapi_msg_nat44_ei_show_fq_options_reply *msg)
{
  vapi_msg_nat44_ei_show_fq_options_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nat44_ei_show_fq_options_reply>(vapi_msg_nat44_ei_show_fq_options_reply *msg)
{
  vapi_msg_nat44_ei_show_fq_options_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nat44_ei_show_fq_options_reply>()
{
  return ::vapi_msg_id_nat44_ei_show_fq_options_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nat44_ei_show_fq_options_reply>>()
{
  return ::vapi_msg_id_nat44_ei_show_fq_options_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nat44_ei_show_fq_options_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nat44_ei_show_fq_options_reply>(vapi_msg_id_nat44_ei_show_fq_options_reply);
}

template class Msg<vapi_msg_nat44_ei_show_fq_options_reply>;

using Nat44_ei_show_fq_options_reply = Msg<vapi_msg_nat44_ei_show_fq_options_reply>;
}
#endif
