#ifndef __included_hpp_dhcp_api_json
#define __included_hpp_dhcp_api_json

#include <vapi/vapi.hpp>
#include <vapi/dhcp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_plugin_get_version>(vapi_msg_dhcp_plugin_get_version *msg)
{
  vapi_msg_dhcp_plugin_get_version_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_plugin_get_version>(vapi_msg_dhcp_plugin_get_version *msg)
{
  vapi_msg_dhcp_plugin_get_version_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_plugin_get_version>()
{
  return ::vapi_msg_id_dhcp_plugin_get_version; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_plugin_get_version>>()
{
  return ::vapi_msg_id_dhcp_plugin_get_version; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_plugin_get_version()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_plugin_get_version>(vapi_msg_id_dhcp_plugin_get_version);
}

template <> inline vapi_msg_dhcp_plugin_get_version* vapi_alloc<vapi_msg_dhcp_plugin_get_version>(Connection &con)
{
  vapi_msg_dhcp_plugin_get_version* result = vapi_alloc_dhcp_plugin_get_version(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_plugin_get_version>;

template class Request<vapi_msg_dhcp_plugin_get_version, vapi_msg_dhcp_plugin_get_version_reply>;

using Dhcp_plugin_get_version = Request<vapi_msg_dhcp_plugin_get_version, vapi_msg_dhcp_plugin_get_version_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_plugin_get_version_reply>(vapi_msg_dhcp_plugin_get_version_reply *msg)
{
  vapi_msg_dhcp_plugin_get_version_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_plugin_get_version_reply>(vapi_msg_dhcp_plugin_get_version_reply *msg)
{
  vapi_msg_dhcp_plugin_get_version_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_plugin_get_version_reply>()
{
  return ::vapi_msg_id_dhcp_plugin_get_version_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_plugin_get_version_reply>>()
{
  return ::vapi_msg_id_dhcp_plugin_get_version_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_plugin_get_version_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_plugin_get_version_reply>(vapi_msg_id_dhcp_plugin_get_version_reply);
}

template class Msg<vapi_msg_dhcp_plugin_get_version_reply>;

using Dhcp_plugin_get_version_reply = Msg<vapi_msg_dhcp_plugin_get_version_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_plugin_control_ping>(vapi_msg_dhcp_plugin_control_ping *msg)
{
  vapi_msg_dhcp_plugin_control_ping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_plugin_control_ping>(vapi_msg_dhcp_plugin_control_ping *msg)
{
  vapi_msg_dhcp_plugin_control_ping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_plugin_control_ping>()
{
  return ::vapi_msg_id_dhcp_plugin_control_ping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_plugin_control_ping>>()
{
  return ::vapi_msg_id_dhcp_plugin_control_ping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_plugin_control_ping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_plugin_control_ping>(vapi_msg_id_dhcp_plugin_control_ping);
}

template <> inline vapi_msg_dhcp_plugin_control_ping* vapi_alloc<vapi_msg_dhcp_plugin_control_ping>(Connection &con)
{
  vapi_msg_dhcp_plugin_control_ping* result = vapi_alloc_dhcp_plugin_control_ping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_plugin_control_ping>;

template class Request<vapi_msg_dhcp_plugin_control_ping, vapi_msg_dhcp_plugin_control_ping_reply>;

using Dhcp_plugin_control_ping = Request<vapi_msg_dhcp_plugin_control_ping, vapi_msg_dhcp_plugin_control_ping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_plugin_control_ping_reply>(vapi_msg_dhcp_plugin_control_ping_reply *msg)
{
  vapi_msg_dhcp_plugin_control_ping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_plugin_control_ping_reply>(vapi_msg_dhcp_plugin_control_ping_reply *msg)
{
  vapi_msg_dhcp_plugin_control_ping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_plugin_control_ping_reply>()
{
  return ::vapi_msg_id_dhcp_plugin_control_ping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_plugin_control_ping_reply>>()
{
  return ::vapi_msg_id_dhcp_plugin_control_ping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_plugin_control_ping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_plugin_control_ping_reply>(vapi_msg_id_dhcp_plugin_control_ping_reply);
}

template class Msg<vapi_msg_dhcp_plugin_control_ping_reply>;

using Dhcp_plugin_control_ping_reply = Msg<vapi_msg_dhcp_plugin_control_ping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_proxy_config>(vapi_msg_dhcp_proxy_config *msg)
{
  vapi_msg_dhcp_proxy_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_proxy_config>(vapi_msg_dhcp_proxy_config *msg)
{
  vapi_msg_dhcp_proxy_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_proxy_config>()
{
  return ::vapi_msg_id_dhcp_proxy_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_proxy_config>>()
{
  return ::vapi_msg_id_dhcp_proxy_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_proxy_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_proxy_config>(vapi_msg_id_dhcp_proxy_config);
}

template <> inline vapi_msg_dhcp_proxy_config* vapi_alloc<vapi_msg_dhcp_proxy_config>(Connection &con)
{
  vapi_msg_dhcp_proxy_config* result = vapi_alloc_dhcp_proxy_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_proxy_config>;

template class Request<vapi_msg_dhcp_proxy_config, vapi_msg_dhcp_proxy_config_reply>;

using Dhcp_proxy_config = Request<vapi_msg_dhcp_proxy_config, vapi_msg_dhcp_proxy_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_proxy_config_reply>(vapi_msg_dhcp_proxy_config_reply *msg)
{
  vapi_msg_dhcp_proxy_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_proxy_config_reply>(vapi_msg_dhcp_proxy_config_reply *msg)
{
  vapi_msg_dhcp_proxy_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_proxy_config_reply>()
{
  return ::vapi_msg_id_dhcp_proxy_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_proxy_config_reply>>()
{
  return ::vapi_msg_id_dhcp_proxy_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_proxy_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_proxy_config_reply>(vapi_msg_id_dhcp_proxy_config_reply);
}

template class Msg<vapi_msg_dhcp_proxy_config_reply>;

using Dhcp_proxy_config_reply = Msg<vapi_msg_dhcp_proxy_config_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_proxy_set_vss>(vapi_msg_dhcp_proxy_set_vss *msg)
{
  vapi_msg_dhcp_proxy_set_vss_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_proxy_set_vss>(vapi_msg_dhcp_proxy_set_vss *msg)
{
  vapi_msg_dhcp_proxy_set_vss_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_proxy_set_vss>()
{
  return ::vapi_msg_id_dhcp_proxy_set_vss; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_proxy_set_vss>>()
{
  return ::vapi_msg_id_dhcp_proxy_set_vss; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_proxy_set_vss()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_proxy_set_vss>(vapi_msg_id_dhcp_proxy_set_vss);
}

template <> inline vapi_msg_dhcp_proxy_set_vss* vapi_alloc<vapi_msg_dhcp_proxy_set_vss>(Connection &con)
{
  vapi_msg_dhcp_proxy_set_vss* result = vapi_alloc_dhcp_proxy_set_vss(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_proxy_set_vss>;

template class Request<vapi_msg_dhcp_proxy_set_vss, vapi_msg_dhcp_proxy_set_vss_reply>;

using Dhcp_proxy_set_vss = Request<vapi_msg_dhcp_proxy_set_vss, vapi_msg_dhcp_proxy_set_vss_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_proxy_set_vss_reply>(vapi_msg_dhcp_proxy_set_vss_reply *msg)
{
  vapi_msg_dhcp_proxy_set_vss_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_proxy_set_vss_reply>(vapi_msg_dhcp_proxy_set_vss_reply *msg)
{
  vapi_msg_dhcp_proxy_set_vss_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_proxy_set_vss_reply>()
{
  return ::vapi_msg_id_dhcp_proxy_set_vss_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_proxy_set_vss_reply>>()
{
  return ::vapi_msg_id_dhcp_proxy_set_vss_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_proxy_set_vss_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_proxy_set_vss_reply>(vapi_msg_id_dhcp_proxy_set_vss_reply);
}

template class Msg<vapi_msg_dhcp_proxy_set_vss_reply>;

using Dhcp_proxy_set_vss_reply = Msg<vapi_msg_dhcp_proxy_set_vss_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_client_config>(vapi_msg_dhcp_client_config *msg)
{
  vapi_msg_dhcp_client_config_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_client_config>(vapi_msg_dhcp_client_config *msg)
{
  vapi_msg_dhcp_client_config_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_client_config>()
{
  return ::vapi_msg_id_dhcp_client_config; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_client_config>>()
{
  return ::vapi_msg_id_dhcp_client_config; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_client_config()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_client_config>(vapi_msg_id_dhcp_client_config);
}

template <> inline vapi_msg_dhcp_client_config* vapi_alloc<vapi_msg_dhcp_client_config>(Connection &con)
{
  vapi_msg_dhcp_client_config* result = vapi_alloc_dhcp_client_config(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_client_config>;

template class Request<vapi_msg_dhcp_client_config, vapi_msg_dhcp_client_config_reply>;

using Dhcp_client_config = Request<vapi_msg_dhcp_client_config, vapi_msg_dhcp_client_config_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_client_config_reply>(vapi_msg_dhcp_client_config_reply *msg)
{
  vapi_msg_dhcp_client_config_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_client_config_reply>(vapi_msg_dhcp_client_config_reply *msg)
{
  vapi_msg_dhcp_client_config_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_client_config_reply>()
{
  return ::vapi_msg_id_dhcp_client_config_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_client_config_reply>>()
{
  return ::vapi_msg_id_dhcp_client_config_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_client_config_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_client_config_reply>(vapi_msg_id_dhcp_client_config_reply);
}

template class Msg<vapi_msg_dhcp_client_config_reply>;

using Dhcp_client_config_reply = Msg<vapi_msg_dhcp_client_config_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_compl_event>(vapi_msg_dhcp_compl_event *msg)
{
  vapi_msg_dhcp_compl_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_compl_event>(vapi_msg_dhcp_compl_event *msg)
{
  vapi_msg_dhcp_compl_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_compl_event>()
{
  return ::vapi_msg_id_dhcp_compl_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_compl_event>>()
{
  return ::vapi_msg_id_dhcp_compl_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_compl_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_compl_event>(vapi_msg_id_dhcp_compl_event);
}

template class Msg<vapi_msg_dhcp_compl_event>;

using Dhcp_compl_event = Msg<vapi_msg_dhcp_compl_event>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_client_dump>(vapi_msg_dhcp_client_dump *msg)
{
  vapi_msg_dhcp_client_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_client_dump>(vapi_msg_dhcp_client_dump *msg)
{
  vapi_msg_dhcp_client_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_client_dump>()
{
  return ::vapi_msg_id_dhcp_client_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_client_dump>>()
{
  return ::vapi_msg_id_dhcp_client_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_client_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_client_dump>(vapi_msg_id_dhcp_client_dump);
}

template <> inline vapi_msg_dhcp_client_dump* vapi_alloc<vapi_msg_dhcp_client_dump>(Connection &con)
{
  vapi_msg_dhcp_client_dump* result = vapi_alloc_dhcp_client_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_client_dump>;

template class Dump<vapi_msg_dhcp_client_dump, vapi_msg_dhcp_client_details>;

using Dhcp_client_dump = Dump<vapi_msg_dhcp_client_dump, vapi_msg_dhcp_client_details>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_client_details>(vapi_msg_dhcp_client_details *msg)
{
  vapi_msg_dhcp_client_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_client_details>(vapi_msg_dhcp_client_details *msg)
{
  vapi_msg_dhcp_client_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_client_details>()
{
  return ::vapi_msg_id_dhcp_client_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_client_details>>()
{
  return ::vapi_msg_id_dhcp_client_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_client_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_client_details>(vapi_msg_id_dhcp_client_details);
}

template class Msg<vapi_msg_dhcp_client_details>;

using Dhcp_client_details = Msg<vapi_msg_dhcp_client_details>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_proxy_dump>(vapi_msg_dhcp_proxy_dump *msg)
{
  vapi_msg_dhcp_proxy_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_proxy_dump>(vapi_msg_dhcp_proxy_dump *msg)
{
  vapi_msg_dhcp_proxy_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_proxy_dump>()
{
  return ::vapi_msg_id_dhcp_proxy_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_proxy_dump>>()
{
  return ::vapi_msg_id_dhcp_proxy_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_proxy_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_proxy_dump>(vapi_msg_id_dhcp_proxy_dump);
}

template <> inline vapi_msg_dhcp_proxy_dump* vapi_alloc<vapi_msg_dhcp_proxy_dump>(Connection &con)
{
  vapi_msg_dhcp_proxy_dump* result = vapi_alloc_dhcp_proxy_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_proxy_dump>;

template class Dump<vapi_msg_dhcp_proxy_dump, vapi_msg_dhcp_proxy_details>;

using Dhcp_proxy_dump = Dump<vapi_msg_dhcp_proxy_dump, vapi_msg_dhcp_proxy_details>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_proxy_details>(vapi_msg_dhcp_proxy_details *msg)
{
  vapi_msg_dhcp_proxy_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_proxy_details>(vapi_msg_dhcp_proxy_details *msg)
{
  vapi_msg_dhcp_proxy_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_proxy_details>()
{
  return ::vapi_msg_id_dhcp_proxy_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_proxy_details>>()
{
  return ::vapi_msg_id_dhcp_proxy_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_proxy_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_proxy_details>(vapi_msg_id_dhcp_proxy_details);
}

template class Msg<vapi_msg_dhcp_proxy_details>;

using Dhcp_proxy_details = Msg<vapi_msg_dhcp_proxy_details>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp_client_detect_enable_disable>(vapi_msg_dhcp_client_detect_enable_disable *msg)
{
  vapi_msg_dhcp_client_detect_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_client_detect_enable_disable>(vapi_msg_dhcp_client_detect_enable_disable *msg)
{
  vapi_msg_dhcp_client_detect_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_client_detect_enable_disable>()
{
  return ::vapi_msg_id_dhcp_client_detect_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_client_detect_enable_disable>>()
{
  return ::vapi_msg_id_dhcp_client_detect_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_client_detect_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_client_detect_enable_disable>(vapi_msg_id_dhcp_client_detect_enable_disable);
}

template <> inline vapi_msg_dhcp_client_detect_enable_disable* vapi_alloc<vapi_msg_dhcp_client_detect_enable_disable>(Connection &con)
{
  vapi_msg_dhcp_client_detect_enable_disable* result = vapi_alloc_dhcp_client_detect_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp_client_detect_enable_disable>;

template class Request<vapi_msg_dhcp_client_detect_enable_disable, vapi_msg_dhcp_client_detect_enable_disable_reply>;

using Dhcp_client_detect_enable_disable = Request<vapi_msg_dhcp_client_detect_enable_disable, vapi_msg_dhcp_client_detect_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp_client_detect_enable_disable_reply>(vapi_msg_dhcp_client_detect_enable_disable_reply *msg)
{
  vapi_msg_dhcp_client_detect_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp_client_detect_enable_disable_reply>(vapi_msg_dhcp_client_detect_enable_disable_reply *msg)
{
  vapi_msg_dhcp_client_detect_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp_client_detect_enable_disable_reply>()
{
  return ::vapi_msg_id_dhcp_client_detect_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp_client_detect_enable_disable_reply>>()
{
  return ::vapi_msg_id_dhcp_client_detect_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp_client_detect_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp_client_detect_enable_disable_reply>(vapi_msg_id_dhcp_client_detect_enable_disable_reply);
}

template class Msg<vapi_msg_dhcp_client_detect_enable_disable_reply>;

using Dhcp_client_detect_enable_disable_reply = Msg<vapi_msg_dhcp_client_detect_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_duid_ll_set>(vapi_msg_dhcp6_duid_ll_set *msg)
{
  vapi_msg_dhcp6_duid_ll_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_duid_ll_set>(vapi_msg_dhcp6_duid_ll_set *msg)
{
  vapi_msg_dhcp6_duid_ll_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_duid_ll_set>()
{
  return ::vapi_msg_id_dhcp6_duid_ll_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_duid_ll_set>>()
{
  return ::vapi_msg_id_dhcp6_duid_ll_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_duid_ll_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_duid_ll_set>(vapi_msg_id_dhcp6_duid_ll_set);
}

template <> inline vapi_msg_dhcp6_duid_ll_set* vapi_alloc<vapi_msg_dhcp6_duid_ll_set>(Connection &con)
{
  vapi_msg_dhcp6_duid_ll_set* result = vapi_alloc_dhcp6_duid_ll_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp6_duid_ll_set>;

template class Request<vapi_msg_dhcp6_duid_ll_set, vapi_msg_dhcp6_duid_ll_set_reply>;

using Dhcp6_duid_ll_set = Request<vapi_msg_dhcp6_duid_ll_set, vapi_msg_dhcp6_duid_ll_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_duid_ll_set_reply>(vapi_msg_dhcp6_duid_ll_set_reply *msg)
{
  vapi_msg_dhcp6_duid_ll_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_duid_ll_set_reply>(vapi_msg_dhcp6_duid_ll_set_reply *msg)
{
  vapi_msg_dhcp6_duid_ll_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_duid_ll_set_reply>()
{
  return ::vapi_msg_id_dhcp6_duid_ll_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_duid_ll_set_reply>>()
{
  return ::vapi_msg_id_dhcp6_duid_ll_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_duid_ll_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_duid_ll_set_reply>(vapi_msg_id_dhcp6_duid_ll_set_reply);
}

template class Msg<vapi_msg_dhcp6_duid_ll_set_reply>;

using Dhcp6_duid_ll_set_reply = Msg<vapi_msg_dhcp6_duid_ll_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_clients_enable_disable>(vapi_msg_dhcp6_clients_enable_disable *msg)
{
  vapi_msg_dhcp6_clients_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_clients_enable_disable>(vapi_msg_dhcp6_clients_enable_disable *msg)
{
  vapi_msg_dhcp6_clients_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_clients_enable_disable>()
{
  return ::vapi_msg_id_dhcp6_clients_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_clients_enable_disable>>()
{
  return ::vapi_msg_id_dhcp6_clients_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_clients_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_clients_enable_disable>(vapi_msg_id_dhcp6_clients_enable_disable);
}

template <> inline vapi_msg_dhcp6_clients_enable_disable* vapi_alloc<vapi_msg_dhcp6_clients_enable_disable>(Connection &con)
{
  vapi_msg_dhcp6_clients_enable_disable* result = vapi_alloc_dhcp6_clients_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp6_clients_enable_disable>;

template class Request<vapi_msg_dhcp6_clients_enable_disable, vapi_msg_dhcp6_clients_enable_disable_reply>;

using Dhcp6_clients_enable_disable = Request<vapi_msg_dhcp6_clients_enable_disable, vapi_msg_dhcp6_clients_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_clients_enable_disable_reply>(vapi_msg_dhcp6_clients_enable_disable_reply *msg)
{
  vapi_msg_dhcp6_clients_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_clients_enable_disable_reply>(vapi_msg_dhcp6_clients_enable_disable_reply *msg)
{
  vapi_msg_dhcp6_clients_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_clients_enable_disable_reply>()
{
  return ::vapi_msg_id_dhcp6_clients_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_clients_enable_disable_reply>>()
{
  return ::vapi_msg_id_dhcp6_clients_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_clients_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_clients_enable_disable_reply>(vapi_msg_id_dhcp6_clients_enable_disable_reply);
}

template class Msg<vapi_msg_dhcp6_clients_enable_disable_reply>;

using Dhcp6_clients_enable_disable_reply = Msg<vapi_msg_dhcp6_clients_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_send_client_message>(vapi_msg_dhcp6_send_client_message *msg)
{
  vapi_msg_dhcp6_send_client_message_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_send_client_message>(vapi_msg_dhcp6_send_client_message *msg)
{
  vapi_msg_dhcp6_send_client_message_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_send_client_message>()
{
  return ::vapi_msg_id_dhcp6_send_client_message; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_send_client_message>>()
{
  return ::vapi_msg_id_dhcp6_send_client_message; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_send_client_message()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_send_client_message>(vapi_msg_id_dhcp6_send_client_message);
}

template <> inline vapi_msg_dhcp6_send_client_message* vapi_alloc<vapi_msg_dhcp6_send_client_message, size_t>(Connection &con, size_t _addresses_array_size)
{
  vapi_msg_dhcp6_send_client_message* result = vapi_alloc_dhcp6_send_client_message(con.vapi_ctx, _addresses_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp6_send_client_message>;

template class Request<vapi_msg_dhcp6_send_client_message, vapi_msg_dhcp6_send_client_message_reply, size_t>;

using Dhcp6_send_client_message = Request<vapi_msg_dhcp6_send_client_message, vapi_msg_dhcp6_send_client_message_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_send_client_message_reply>(vapi_msg_dhcp6_send_client_message_reply *msg)
{
  vapi_msg_dhcp6_send_client_message_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_send_client_message_reply>(vapi_msg_dhcp6_send_client_message_reply *msg)
{
  vapi_msg_dhcp6_send_client_message_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_send_client_message_reply>()
{
  return ::vapi_msg_id_dhcp6_send_client_message_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_send_client_message_reply>>()
{
  return ::vapi_msg_id_dhcp6_send_client_message_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_send_client_message_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_send_client_message_reply>(vapi_msg_id_dhcp6_send_client_message_reply);
}

template class Msg<vapi_msg_dhcp6_send_client_message_reply>;

using Dhcp6_send_client_message_reply = Msg<vapi_msg_dhcp6_send_client_message_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_pd_send_client_message>(vapi_msg_dhcp6_pd_send_client_message *msg)
{
  vapi_msg_dhcp6_pd_send_client_message_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_pd_send_client_message>(vapi_msg_dhcp6_pd_send_client_message *msg)
{
  vapi_msg_dhcp6_pd_send_client_message_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_pd_send_client_message>()
{
  return ::vapi_msg_id_dhcp6_pd_send_client_message; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_pd_send_client_message>>()
{
  return ::vapi_msg_id_dhcp6_pd_send_client_message; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_pd_send_client_message()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_pd_send_client_message>(vapi_msg_id_dhcp6_pd_send_client_message);
}

template <> inline vapi_msg_dhcp6_pd_send_client_message* vapi_alloc<vapi_msg_dhcp6_pd_send_client_message, size_t>(Connection &con, size_t _prefixes_array_size)
{
  vapi_msg_dhcp6_pd_send_client_message* result = vapi_alloc_dhcp6_pd_send_client_message(con.vapi_ctx, _prefixes_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dhcp6_pd_send_client_message>;

template class Request<vapi_msg_dhcp6_pd_send_client_message, vapi_msg_dhcp6_pd_send_client_message_reply, size_t>;

using Dhcp6_pd_send_client_message = Request<vapi_msg_dhcp6_pd_send_client_message, vapi_msg_dhcp6_pd_send_client_message_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_pd_send_client_message_reply>(vapi_msg_dhcp6_pd_send_client_message_reply *msg)
{
  vapi_msg_dhcp6_pd_send_client_message_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_pd_send_client_message_reply>(vapi_msg_dhcp6_pd_send_client_message_reply *msg)
{
  vapi_msg_dhcp6_pd_send_client_message_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_pd_send_client_message_reply>()
{
  return ::vapi_msg_id_dhcp6_pd_send_client_message_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_pd_send_client_message_reply>>()
{
  return ::vapi_msg_id_dhcp6_pd_send_client_message_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_pd_send_client_message_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_pd_send_client_message_reply>(vapi_msg_id_dhcp6_pd_send_client_message_reply);
}

template class Msg<vapi_msg_dhcp6_pd_send_client_message_reply>;

using Dhcp6_pd_send_client_message_reply = Msg<vapi_msg_dhcp6_pd_send_client_message_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_dhcp6_reply_events>(vapi_msg_want_dhcp6_reply_events *msg)
{
  vapi_msg_want_dhcp6_reply_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_dhcp6_reply_events>(vapi_msg_want_dhcp6_reply_events *msg)
{
  vapi_msg_want_dhcp6_reply_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_dhcp6_reply_events>()
{
  return ::vapi_msg_id_want_dhcp6_reply_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_dhcp6_reply_events>>()
{
  return ::vapi_msg_id_want_dhcp6_reply_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_dhcp6_reply_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_dhcp6_reply_events>(vapi_msg_id_want_dhcp6_reply_events);
}

template <> inline vapi_msg_want_dhcp6_reply_events* vapi_alloc<vapi_msg_want_dhcp6_reply_events>(Connection &con)
{
  vapi_msg_want_dhcp6_reply_events* result = vapi_alloc_want_dhcp6_reply_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_dhcp6_reply_events>;

template class Request<vapi_msg_want_dhcp6_reply_events, vapi_msg_want_dhcp6_reply_events_reply>;

using Want_dhcp6_reply_events = Request<vapi_msg_want_dhcp6_reply_events, vapi_msg_want_dhcp6_reply_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_dhcp6_reply_events_reply>(vapi_msg_want_dhcp6_reply_events_reply *msg)
{
  vapi_msg_want_dhcp6_reply_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_dhcp6_reply_events_reply>(vapi_msg_want_dhcp6_reply_events_reply *msg)
{
  vapi_msg_want_dhcp6_reply_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_dhcp6_reply_events_reply>()
{
  return ::vapi_msg_id_want_dhcp6_reply_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_dhcp6_reply_events_reply>>()
{
  return ::vapi_msg_id_want_dhcp6_reply_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_dhcp6_reply_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_dhcp6_reply_events_reply>(vapi_msg_id_want_dhcp6_reply_events_reply);
}

template class Msg<vapi_msg_want_dhcp6_reply_events_reply>;

using Want_dhcp6_reply_events_reply = Msg<vapi_msg_want_dhcp6_reply_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_dhcp6_pd_reply_events>(vapi_msg_want_dhcp6_pd_reply_events *msg)
{
  vapi_msg_want_dhcp6_pd_reply_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_dhcp6_pd_reply_events>(vapi_msg_want_dhcp6_pd_reply_events *msg)
{
  vapi_msg_want_dhcp6_pd_reply_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_dhcp6_pd_reply_events>()
{
  return ::vapi_msg_id_want_dhcp6_pd_reply_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_dhcp6_pd_reply_events>>()
{
  return ::vapi_msg_id_want_dhcp6_pd_reply_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_dhcp6_pd_reply_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_dhcp6_pd_reply_events>(vapi_msg_id_want_dhcp6_pd_reply_events);
}

template <> inline vapi_msg_want_dhcp6_pd_reply_events* vapi_alloc<vapi_msg_want_dhcp6_pd_reply_events>(Connection &con)
{
  vapi_msg_want_dhcp6_pd_reply_events* result = vapi_alloc_want_dhcp6_pd_reply_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_dhcp6_pd_reply_events>;

template class Request<vapi_msg_want_dhcp6_pd_reply_events, vapi_msg_want_dhcp6_pd_reply_events_reply>;

using Want_dhcp6_pd_reply_events = Request<vapi_msg_want_dhcp6_pd_reply_events, vapi_msg_want_dhcp6_pd_reply_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_dhcp6_pd_reply_events_reply>(vapi_msg_want_dhcp6_pd_reply_events_reply *msg)
{
  vapi_msg_want_dhcp6_pd_reply_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_dhcp6_pd_reply_events_reply>(vapi_msg_want_dhcp6_pd_reply_events_reply *msg)
{
  vapi_msg_want_dhcp6_pd_reply_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_dhcp6_pd_reply_events_reply>()
{
  return ::vapi_msg_id_want_dhcp6_pd_reply_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_dhcp6_pd_reply_events_reply>>()
{
  return ::vapi_msg_id_want_dhcp6_pd_reply_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_dhcp6_pd_reply_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_dhcp6_pd_reply_events_reply>(vapi_msg_id_want_dhcp6_pd_reply_events_reply);
}

template class Msg<vapi_msg_want_dhcp6_pd_reply_events_reply>;

using Want_dhcp6_pd_reply_events_reply = Msg<vapi_msg_want_dhcp6_pd_reply_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_reply_event>(vapi_msg_dhcp6_reply_event *msg)
{
  vapi_msg_dhcp6_reply_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_reply_event>(vapi_msg_dhcp6_reply_event *msg)
{
  vapi_msg_dhcp6_reply_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_reply_event>()
{
  return ::vapi_msg_id_dhcp6_reply_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_reply_event>>()
{
  return ::vapi_msg_id_dhcp6_reply_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_reply_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_reply_event>(vapi_msg_id_dhcp6_reply_event);
}

template class Msg<vapi_msg_dhcp6_reply_event>;

using Dhcp6_reply_event = Msg<vapi_msg_dhcp6_reply_event>;
template <> inline void vapi_swap_to_be<vapi_msg_dhcp6_pd_reply_event>(vapi_msg_dhcp6_pd_reply_event *msg)
{
  vapi_msg_dhcp6_pd_reply_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dhcp6_pd_reply_event>(vapi_msg_dhcp6_pd_reply_event *msg)
{
  vapi_msg_dhcp6_pd_reply_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dhcp6_pd_reply_event>()
{
  return ::vapi_msg_id_dhcp6_pd_reply_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dhcp6_pd_reply_event>>()
{
  return ::vapi_msg_id_dhcp6_pd_reply_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dhcp6_pd_reply_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dhcp6_pd_reply_event>(vapi_msg_id_dhcp6_pd_reply_event);
}

template class Msg<vapi_msg_dhcp6_pd_reply_event>;

using Dhcp6_pd_reply_event = Msg<vapi_msg_dhcp6_pd_reply_event>;
}
#endif
