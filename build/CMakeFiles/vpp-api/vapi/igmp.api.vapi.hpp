#ifndef __included_hpp_igmp_api_json
#define __included_hpp_igmp_api_json

#include <vapi/vapi.hpp>
#include <vapi/igmp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_igmp_listen>(vapi_msg_igmp_listen *msg)
{
  vapi_msg_igmp_listen_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_listen>(vapi_msg_igmp_listen *msg)
{
  vapi_msg_igmp_listen_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_listen>()
{
  return ::vapi_msg_id_igmp_listen; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_listen>>()
{
  return ::vapi_msg_id_igmp_listen; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_listen()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_listen>(vapi_msg_id_igmp_listen);
}

template <> inline vapi_msg_igmp_listen* vapi_alloc<vapi_msg_igmp_listen, size_t>(Connection &con, size_t group_saddrs_array_size)
{
  vapi_msg_igmp_listen* result = vapi_alloc_igmp_listen(con.vapi_ctx, group_saddrs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_listen>;

template class Request<vapi_msg_igmp_listen, vapi_msg_igmp_listen_reply, size_t>;

using Igmp_listen = Request<vapi_msg_igmp_listen, vapi_msg_igmp_listen_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_listen_reply>(vapi_msg_igmp_listen_reply *msg)
{
  vapi_msg_igmp_listen_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_listen_reply>(vapi_msg_igmp_listen_reply *msg)
{
  vapi_msg_igmp_listen_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_listen_reply>()
{
  return ::vapi_msg_id_igmp_listen_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_listen_reply>>()
{
  return ::vapi_msg_id_igmp_listen_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_listen_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_listen_reply>(vapi_msg_id_igmp_listen_reply);
}

template class Msg<vapi_msg_igmp_listen_reply>;

using Igmp_listen_reply = Msg<vapi_msg_igmp_listen_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_enable_disable>(vapi_msg_igmp_enable_disable *msg)
{
  vapi_msg_igmp_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_enable_disable>(vapi_msg_igmp_enable_disable *msg)
{
  vapi_msg_igmp_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_enable_disable>()
{
  return ::vapi_msg_id_igmp_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_enable_disable>>()
{
  return ::vapi_msg_id_igmp_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_enable_disable>(vapi_msg_id_igmp_enable_disable);
}

template <> inline vapi_msg_igmp_enable_disable* vapi_alloc<vapi_msg_igmp_enable_disable>(Connection &con)
{
  vapi_msg_igmp_enable_disable* result = vapi_alloc_igmp_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_enable_disable>;

template class Request<vapi_msg_igmp_enable_disable, vapi_msg_igmp_enable_disable_reply>;

using Igmp_enable_disable = Request<vapi_msg_igmp_enable_disable, vapi_msg_igmp_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_enable_disable_reply>(vapi_msg_igmp_enable_disable_reply *msg)
{
  vapi_msg_igmp_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_enable_disable_reply>(vapi_msg_igmp_enable_disable_reply *msg)
{
  vapi_msg_igmp_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_enable_disable_reply>()
{
  return ::vapi_msg_id_igmp_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_enable_disable_reply>>()
{
  return ::vapi_msg_id_igmp_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_enable_disable_reply>(vapi_msg_id_igmp_enable_disable_reply);
}

template class Msg<vapi_msg_igmp_enable_disable_reply>;

using Igmp_enable_disable_reply = Msg<vapi_msg_igmp_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_proxy_device_add_del>(vapi_msg_igmp_proxy_device_add_del *msg)
{
  vapi_msg_igmp_proxy_device_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_proxy_device_add_del>(vapi_msg_igmp_proxy_device_add_del *msg)
{
  vapi_msg_igmp_proxy_device_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_proxy_device_add_del>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_proxy_device_add_del>>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_proxy_device_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_proxy_device_add_del>(vapi_msg_id_igmp_proxy_device_add_del);
}

template <> inline vapi_msg_igmp_proxy_device_add_del* vapi_alloc<vapi_msg_igmp_proxy_device_add_del>(Connection &con)
{
  vapi_msg_igmp_proxy_device_add_del* result = vapi_alloc_igmp_proxy_device_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_proxy_device_add_del>;

template class Request<vapi_msg_igmp_proxy_device_add_del, vapi_msg_igmp_proxy_device_add_del_reply>;

using Igmp_proxy_device_add_del = Request<vapi_msg_igmp_proxy_device_add_del, vapi_msg_igmp_proxy_device_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_proxy_device_add_del_reply>(vapi_msg_igmp_proxy_device_add_del_reply *msg)
{
  vapi_msg_igmp_proxy_device_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_proxy_device_add_del_reply>(vapi_msg_igmp_proxy_device_add_del_reply *msg)
{
  vapi_msg_igmp_proxy_device_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_proxy_device_add_del_reply>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_proxy_device_add_del_reply>>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_proxy_device_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_proxy_device_add_del_reply>(vapi_msg_id_igmp_proxy_device_add_del_reply);
}

template class Msg<vapi_msg_igmp_proxy_device_add_del_reply>;

using Igmp_proxy_device_add_del_reply = Msg<vapi_msg_igmp_proxy_device_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_proxy_device_add_del_interface>(vapi_msg_igmp_proxy_device_add_del_interface *msg)
{
  vapi_msg_igmp_proxy_device_add_del_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_proxy_device_add_del_interface>(vapi_msg_igmp_proxy_device_add_del_interface *msg)
{
  vapi_msg_igmp_proxy_device_add_del_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_proxy_device_add_del_interface>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_proxy_device_add_del_interface>>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_proxy_device_add_del_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_proxy_device_add_del_interface>(vapi_msg_id_igmp_proxy_device_add_del_interface);
}

template <> inline vapi_msg_igmp_proxy_device_add_del_interface* vapi_alloc<vapi_msg_igmp_proxy_device_add_del_interface>(Connection &con)
{
  vapi_msg_igmp_proxy_device_add_del_interface* result = vapi_alloc_igmp_proxy_device_add_del_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_proxy_device_add_del_interface>;

template class Request<vapi_msg_igmp_proxy_device_add_del_interface, vapi_msg_igmp_proxy_device_add_del_interface_reply>;

using Igmp_proxy_device_add_del_interface = Request<vapi_msg_igmp_proxy_device_add_del_interface, vapi_msg_igmp_proxy_device_add_del_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_proxy_device_add_del_interface_reply>(vapi_msg_igmp_proxy_device_add_del_interface_reply *msg)
{
  vapi_msg_igmp_proxy_device_add_del_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_proxy_device_add_del_interface_reply>(vapi_msg_igmp_proxy_device_add_del_interface_reply *msg)
{
  vapi_msg_igmp_proxy_device_add_del_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_proxy_device_add_del_interface_reply>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_proxy_device_add_del_interface_reply>>()
{
  return ::vapi_msg_id_igmp_proxy_device_add_del_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_proxy_device_add_del_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_proxy_device_add_del_interface_reply>(vapi_msg_id_igmp_proxy_device_add_del_interface_reply);
}

template class Msg<vapi_msg_igmp_proxy_device_add_del_interface_reply>;

using Igmp_proxy_device_add_del_interface_reply = Msg<vapi_msg_igmp_proxy_device_add_del_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_dump>(vapi_msg_igmp_dump *msg)
{
  vapi_msg_igmp_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_dump>(vapi_msg_igmp_dump *msg)
{
  vapi_msg_igmp_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_dump>()
{
  return ::vapi_msg_id_igmp_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_dump>>()
{
  return ::vapi_msg_id_igmp_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_dump>(vapi_msg_id_igmp_dump);
}

template <> inline vapi_msg_igmp_dump* vapi_alloc<vapi_msg_igmp_dump>(Connection &con)
{
  vapi_msg_igmp_dump* result = vapi_alloc_igmp_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_dump>;

template class Dump<vapi_msg_igmp_dump, vapi_msg_igmp_details>;

using Igmp_dump = Dump<vapi_msg_igmp_dump, vapi_msg_igmp_details>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_details>(vapi_msg_igmp_details *msg)
{
  vapi_msg_igmp_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_details>(vapi_msg_igmp_details *msg)
{
  vapi_msg_igmp_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_details>()
{
  return ::vapi_msg_id_igmp_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_details>>()
{
  return ::vapi_msg_id_igmp_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_details>(vapi_msg_id_igmp_details);
}

template class Msg<vapi_msg_igmp_details>;

using Igmp_details = Msg<vapi_msg_igmp_details>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_clear_interface>(vapi_msg_igmp_clear_interface *msg)
{
  vapi_msg_igmp_clear_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_clear_interface>(vapi_msg_igmp_clear_interface *msg)
{
  vapi_msg_igmp_clear_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_clear_interface>()
{
  return ::vapi_msg_id_igmp_clear_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_clear_interface>>()
{
  return ::vapi_msg_id_igmp_clear_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_clear_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_clear_interface>(vapi_msg_id_igmp_clear_interface);
}

template <> inline vapi_msg_igmp_clear_interface* vapi_alloc<vapi_msg_igmp_clear_interface>(Connection &con)
{
  vapi_msg_igmp_clear_interface* result = vapi_alloc_igmp_clear_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_clear_interface>;

template class Request<vapi_msg_igmp_clear_interface, vapi_msg_igmp_clear_interface_reply>;

using Igmp_clear_interface = Request<vapi_msg_igmp_clear_interface, vapi_msg_igmp_clear_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_clear_interface_reply>(vapi_msg_igmp_clear_interface_reply *msg)
{
  vapi_msg_igmp_clear_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_clear_interface_reply>(vapi_msg_igmp_clear_interface_reply *msg)
{
  vapi_msg_igmp_clear_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_clear_interface_reply>()
{
  return ::vapi_msg_id_igmp_clear_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_clear_interface_reply>>()
{
  return ::vapi_msg_id_igmp_clear_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_clear_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_clear_interface_reply>(vapi_msg_id_igmp_clear_interface_reply);
}

template class Msg<vapi_msg_igmp_clear_interface_reply>;

using Igmp_clear_interface_reply = Msg<vapi_msg_igmp_clear_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_igmp_events>(vapi_msg_want_igmp_events *msg)
{
  vapi_msg_want_igmp_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_igmp_events>(vapi_msg_want_igmp_events *msg)
{
  vapi_msg_want_igmp_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_igmp_events>()
{
  return ::vapi_msg_id_want_igmp_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_igmp_events>>()
{
  return ::vapi_msg_id_want_igmp_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_igmp_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_igmp_events>(vapi_msg_id_want_igmp_events);
}

template <> inline vapi_msg_want_igmp_events* vapi_alloc<vapi_msg_want_igmp_events>(Connection &con)
{
  vapi_msg_want_igmp_events* result = vapi_alloc_want_igmp_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_igmp_events>;

template class Request<vapi_msg_want_igmp_events, vapi_msg_want_igmp_events_reply>;

using Want_igmp_events = Request<vapi_msg_want_igmp_events, vapi_msg_want_igmp_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_igmp_events_reply>(vapi_msg_want_igmp_events_reply *msg)
{
  vapi_msg_want_igmp_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_igmp_events_reply>(vapi_msg_want_igmp_events_reply *msg)
{
  vapi_msg_want_igmp_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_igmp_events_reply>()
{
  return ::vapi_msg_id_want_igmp_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_igmp_events_reply>>()
{
  return ::vapi_msg_id_want_igmp_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_igmp_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_igmp_events_reply>(vapi_msg_id_want_igmp_events_reply);
}

template class Msg<vapi_msg_want_igmp_events_reply>;

using Want_igmp_events_reply = Msg<vapi_msg_want_igmp_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_event>(vapi_msg_igmp_event *msg)
{
  vapi_msg_igmp_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_event>(vapi_msg_igmp_event *msg)
{
  vapi_msg_igmp_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_event>()
{
  return ::vapi_msg_id_igmp_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_event>>()
{
  return ::vapi_msg_id_igmp_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_event>(vapi_msg_id_igmp_event);
}

template class Msg<vapi_msg_igmp_event>;

using Igmp_event = Msg<vapi_msg_igmp_event>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_group_prefix_set>(vapi_msg_igmp_group_prefix_set *msg)
{
  vapi_msg_igmp_group_prefix_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_group_prefix_set>(vapi_msg_igmp_group_prefix_set *msg)
{
  vapi_msg_igmp_group_prefix_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_group_prefix_set>()
{
  return ::vapi_msg_id_igmp_group_prefix_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_group_prefix_set>>()
{
  return ::vapi_msg_id_igmp_group_prefix_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_group_prefix_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_group_prefix_set>(vapi_msg_id_igmp_group_prefix_set);
}

template <> inline vapi_msg_igmp_group_prefix_set* vapi_alloc<vapi_msg_igmp_group_prefix_set>(Connection &con)
{
  vapi_msg_igmp_group_prefix_set* result = vapi_alloc_igmp_group_prefix_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_group_prefix_set>;

template class Request<vapi_msg_igmp_group_prefix_set, vapi_msg_igmp_group_prefix_set_reply>;

using Igmp_group_prefix_set = Request<vapi_msg_igmp_group_prefix_set, vapi_msg_igmp_group_prefix_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_group_prefix_set_reply>(vapi_msg_igmp_group_prefix_set_reply *msg)
{
  vapi_msg_igmp_group_prefix_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_group_prefix_set_reply>(vapi_msg_igmp_group_prefix_set_reply *msg)
{
  vapi_msg_igmp_group_prefix_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_group_prefix_set_reply>()
{
  return ::vapi_msg_id_igmp_group_prefix_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_group_prefix_set_reply>>()
{
  return ::vapi_msg_id_igmp_group_prefix_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_group_prefix_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_group_prefix_set_reply>(vapi_msg_id_igmp_group_prefix_set_reply);
}

template class Msg<vapi_msg_igmp_group_prefix_set_reply>;

using Igmp_group_prefix_set_reply = Msg<vapi_msg_igmp_group_prefix_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_igmp_group_prefix_dump>(vapi_msg_igmp_group_prefix_dump *msg)
{
  vapi_msg_igmp_group_prefix_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_group_prefix_dump>(vapi_msg_igmp_group_prefix_dump *msg)
{
  vapi_msg_igmp_group_prefix_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_group_prefix_dump>()
{
  return ::vapi_msg_id_igmp_group_prefix_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_group_prefix_dump>>()
{
  return ::vapi_msg_id_igmp_group_prefix_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_group_prefix_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_group_prefix_dump>(vapi_msg_id_igmp_group_prefix_dump);
}

template <> inline vapi_msg_igmp_group_prefix_dump* vapi_alloc<vapi_msg_igmp_group_prefix_dump>(Connection &con)
{
  vapi_msg_igmp_group_prefix_dump* result = vapi_alloc_igmp_group_prefix_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_igmp_group_prefix_dump>;

template class Dump<vapi_msg_igmp_group_prefix_dump, vapi_msg_igmp_group_prefix_details>;

using Igmp_group_prefix_dump = Dump<vapi_msg_igmp_group_prefix_dump, vapi_msg_igmp_group_prefix_details>;

template <> inline void vapi_swap_to_be<vapi_msg_igmp_group_prefix_details>(vapi_msg_igmp_group_prefix_details *msg)
{
  vapi_msg_igmp_group_prefix_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_igmp_group_prefix_details>(vapi_msg_igmp_group_prefix_details *msg)
{
  vapi_msg_igmp_group_prefix_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_igmp_group_prefix_details>()
{
  return ::vapi_msg_id_igmp_group_prefix_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_igmp_group_prefix_details>>()
{
  return ::vapi_msg_id_igmp_group_prefix_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_igmp_group_prefix_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_igmp_group_prefix_details>(vapi_msg_id_igmp_group_prefix_details);
}

template class Msg<vapi_msg_igmp_group_prefix_details>;

using Igmp_group_prefix_details = Msg<vapi_msg_igmp_group_prefix_details>;
}
#endif
