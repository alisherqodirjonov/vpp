#ifndef __included_hpp_wireguard_api_json
#define __included_hpp_wireguard_api_json

#include <vapi/vapi.hpp>
#include <vapi/wireguard.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_interface_create>(vapi_msg_wireguard_interface_create *msg)
{
  vapi_msg_wireguard_interface_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_interface_create>(vapi_msg_wireguard_interface_create *msg)
{
  vapi_msg_wireguard_interface_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_interface_create>()
{
  return ::vapi_msg_id_wireguard_interface_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_interface_create>>()
{
  return ::vapi_msg_id_wireguard_interface_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_interface_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_interface_create>(vapi_msg_id_wireguard_interface_create);
}

template <> inline vapi_msg_wireguard_interface_create* vapi_alloc<vapi_msg_wireguard_interface_create>(Connection &con)
{
  vapi_msg_wireguard_interface_create* result = vapi_alloc_wireguard_interface_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wireguard_interface_create>;

template class Request<vapi_msg_wireguard_interface_create, vapi_msg_wireguard_interface_create_reply>;

using Wireguard_interface_create = Request<vapi_msg_wireguard_interface_create, vapi_msg_wireguard_interface_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_interface_create_reply>(vapi_msg_wireguard_interface_create_reply *msg)
{
  vapi_msg_wireguard_interface_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_interface_create_reply>(vapi_msg_wireguard_interface_create_reply *msg)
{
  vapi_msg_wireguard_interface_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_interface_create_reply>()
{
  return ::vapi_msg_id_wireguard_interface_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_interface_create_reply>>()
{
  return ::vapi_msg_id_wireguard_interface_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_interface_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_interface_create_reply>(vapi_msg_id_wireguard_interface_create_reply);
}

template class Msg<vapi_msg_wireguard_interface_create_reply>;

using Wireguard_interface_create_reply = Msg<vapi_msg_wireguard_interface_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_wireguard_interface_delete>(vapi_msg_wireguard_interface_delete *msg)
{
  vapi_msg_wireguard_interface_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_interface_delete>(vapi_msg_wireguard_interface_delete *msg)
{
  vapi_msg_wireguard_interface_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_interface_delete>()
{
  return ::vapi_msg_id_wireguard_interface_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_interface_delete>>()
{
  return ::vapi_msg_id_wireguard_interface_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_interface_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_interface_delete>(vapi_msg_id_wireguard_interface_delete);
}

template <> inline vapi_msg_wireguard_interface_delete* vapi_alloc<vapi_msg_wireguard_interface_delete>(Connection &con)
{
  vapi_msg_wireguard_interface_delete* result = vapi_alloc_wireguard_interface_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wireguard_interface_delete>;

template class Request<vapi_msg_wireguard_interface_delete, vapi_msg_wireguard_interface_delete_reply>;

using Wireguard_interface_delete = Request<vapi_msg_wireguard_interface_delete, vapi_msg_wireguard_interface_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_interface_delete_reply>(vapi_msg_wireguard_interface_delete_reply *msg)
{
  vapi_msg_wireguard_interface_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_interface_delete_reply>(vapi_msg_wireguard_interface_delete_reply *msg)
{
  vapi_msg_wireguard_interface_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_interface_delete_reply>()
{
  return ::vapi_msg_id_wireguard_interface_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_interface_delete_reply>>()
{
  return ::vapi_msg_id_wireguard_interface_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_interface_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_interface_delete_reply>(vapi_msg_id_wireguard_interface_delete_reply);
}

template class Msg<vapi_msg_wireguard_interface_delete_reply>;

using Wireguard_interface_delete_reply = Msg<vapi_msg_wireguard_interface_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_wireguard_interface_dump>(vapi_msg_wireguard_interface_dump *msg)
{
  vapi_msg_wireguard_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_interface_dump>(vapi_msg_wireguard_interface_dump *msg)
{
  vapi_msg_wireguard_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_interface_dump>()
{
  return ::vapi_msg_id_wireguard_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_interface_dump>>()
{
  return ::vapi_msg_id_wireguard_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_interface_dump>(vapi_msg_id_wireguard_interface_dump);
}

template <> inline vapi_msg_wireguard_interface_dump* vapi_alloc<vapi_msg_wireguard_interface_dump>(Connection &con)
{
  vapi_msg_wireguard_interface_dump* result = vapi_alloc_wireguard_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wireguard_interface_dump>;

template class Dump<vapi_msg_wireguard_interface_dump, vapi_msg_wireguard_interface_details>;

using Wireguard_interface_dump = Dump<vapi_msg_wireguard_interface_dump, vapi_msg_wireguard_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_interface_details>(vapi_msg_wireguard_interface_details *msg)
{
  vapi_msg_wireguard_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_interface_details>(vapi_msg_wireguard_interface_details *msg)
{
  vapi_msg_wireguard_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_interface_details>()
{
  return ::vapi_msg_id_wireguard_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_interface_details>>()
{
  return ::vapi_msg_id_wireguard_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_interface_details>(vapi_msg_id_wireguard_interface_details);
}

template class Msg<vapi_msg_wireguard_interface_details>;

using Wireguard_interface_details = Msg<vapi_msg_wireguard_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_want_wireguard_peer_events>(vapi_msg_want_wireguard_peer_events *msg)
{
  vapi_msg_want_wireguard_peer_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_wireguard_peer_events>(vapi_msg_want_wireguard_peer_events *msg)
{
  vapi_msg_want_wireguard_peer_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_wireguard_peer_events>()
{
  return ::vapi_msg_id_want_wireguard_peer_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_wireguard_peer_events>>()
{
  return ::vapi_msg_id_want_wireguard_peer_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_wireguard_peer_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_wireguard_peer_events>(vapi_msg_id_want_wireguard_peer_events);
}

template <> inline vapi_msg_want_wireguard_peer_events* vapi_alloc<vapi_msg_want_wireguard_peer_events>(Connection &con)
{
  vapi_msg_want_wireguard_peer_events* result = vapi_alloc_want_wireguard_peer_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_wireguard_peer_events>;

template class Request<vapi_msg_want_wireguard_peer_events, vapi_msg_want_wireguard_peer_events_reply>;

using Want_wireguard_peer_events = Request<vapi_msg_want_wireguard_peer_events, vapi_msg_want_wireguard_peer_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_wireguard_peer_events_reply>(vapi_msg_want_wireguard_peer_events_reply *msg)
{
  vapi_msg_want_wireguard_peer_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_wireguard_peer_events_reply>(vapi_msg_want_wireguard_peer_events_reply *msg)
{
  vapi_msg_want_wireguard_peer_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_wireguard_peer_events_reply>()
{
  return ::vapi_msg_id_want_wireguard_peer_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_wireguard_peer_events_reply>>()
{
  return ::vapi_msg_id_want_wireguard_peer_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_wireguard_peer_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_wireguard_peer_events_reply>(vapi_msg_id_want_wireguard_peer_events_reply);
}

template class Msg<vapi_msg_want_wireguard_peer_events_reply>;

using Want_wireguard_peer_events_reply = Msg<vapi_msg_want_wireguard_peer_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peer_event>(vapi_msg_wireguard_peer_event *msg)
{
  vapi_msg_wireguard_peer_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peer_event>(vapi_msg_wireguard_peer_event *msg)
{
  vapi_msg_wireguard_peer_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peer_event>()
{
  return ::vapi_msg_id_wireguard_peer_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peer_event>>()
{
  return ::vapi_msg_id_wireguard_peer_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peer_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peer_event>(vapi_msg_id_wireguard_peer_event);
}

template class Msg<vapi_msg_wireguard_peer_event>;

using Wireguard_peer_event = Msg<vapi_msg_wireguard_peer_event>;
template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peer_add>(vapi_msg_wireguard_peer_add *msg)
{
  vapi_msg_wireguard_peer_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peer_add>(vapi_msg_wireguard_peer_add *msg)
{
  vapi_msg_wireguard_peer_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peer_add>()
{
  return ::vapi_msg_id_wireguard_peer_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peer_add>>()
{
  return ::vapi_msg_id_wireguard_peer_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peer_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peer_add>(vapi_msg_id_wireguard_peer_add);
}

template <> inline vapi_msg_wireguard_peer_add* vapi_alloc<vapi_msg_wireguard_peer_add, size_t>(Connection &con, size_t peer_allowed_ips_array_size)
{
  vapi_msg_wireguard_peer_add* result = vapi_alloc_wireguard_peer_add(con.vapi_ctx, peer_allowed_ips_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wireguard_peer_add>;

template class Request<vapi_msg_wireguard_peer_add, vapi_msg_wireguard_peer_add_reply, size_t>;

using Wireguard_peer_add = Request<vapi_msg_wireguard_peer_add, vapi_msg_wireguard_peer_add_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peer_add_reply>(vapi_msg_wireguard_peer_add_reply *msg)
{
  vapi_msg_wireguard_peer_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peer_add_reply>(vapi_msg_wireguard_peer_add_reply *msg)
{
  vapi_msg_wireguard_peer_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peer_add_reply>()
{
  return ::vapi_msg_id_wireguard_peer_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peer_add_reply>>()
{
  return ::vapi_msg_id_wireguard_peer_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peer_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peer_add_reply>(vapi_msg_id_wireguard_peer_add_reply);
}

template class Msg<vapi_msg_wireguard_peer_add_reply>;

using Wireguard_peer_add_reply = Msg<vapi_msg_wireguard_peer_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peer_remove>(vapi_msg_wireguard_peer_remove *msg)
{
  vapi_msg_wireguard_peer_remove_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peer_remove>(vapi_msg_wireguard_peer_remove *msg)
{
  vapi_msg_wireguard_peer_remove_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peer_remove>()
{
  return ::vapi_msg_id_wireguard_peer_remove; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peer_remove>>()
{
  return ::vapi_msg_id_wireguard_peer_remove; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peer_remove()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peer_remove>(vapi_msg_id_wireguard_peer_remove);
}

template <> inline vapi_msg_wireguard_peer_remove* vapi_alloc<vapi_msg_wireguard_peer_remove>(Connection &con)
{
  vapi_msg_wireguard_peer_remove* result = vapi_alloc_wireguard_peer_remove(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wireguard_peer_remove>;

template class Request<vapi_msg_wireguard_peer_remove, vapi_msg_wireguard_peer_remove_reply>;

using Wireguard_peer_remove = Request<vapi_msg_wireguard_peer_remove, vapi_msg_wireguard_peer_remove_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peer_remove_reply>(vapi_msg_wireguard_peer_remove_reply *msg)
{
  vapi_msg_wireguard_peer_remove_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peer_remove_reply>(vapi_msg_wireguard_peer_remove_reply *msg)
{
  vapi_msg_wireguard_peer_remove_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peer_remove_reply>()
{
  return ::vapi_msg_id_wireguard_peer_remove_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peer_remove_reply>>()
{
  return ::vapi_msg_id_wireguard_peer_remove_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peer_remove_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peer_remove_reply>(vapi_msg_id_wireguard_peer_remove_reply);
}

template class Msg<vapi_msg_wireguard_peer_remove_reply>;

using Wireguard_peer_remove_reply = Msg<vapi_msg_wireguard_peer_remove_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peers_dump>(vapi_msg_wireguard_peers_dump *msg)
{
  vapi_msg_wireguard_peers_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peers_dump>(vapi_msg_wireguard_peers_dump *msg)
{
  vapi_msg_wireguard_peers_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peers_dump>()
{
  return ::vapi_msg_id_wireguard_peers_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peers_dump>>()
{
  return ::vapi_msg_id_wireguard_peers_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peers_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peers_dump>(vapi_msg_id_wireguard_peers_dump);
}

template <> inline vapi_msg_wireguard_peers_dump* vapi_alloc<vapi_msg_wireguard_peers_dump>(Connection &con)
{
  vapi_msg_wireguard_peers_dump* result = vapi_alloc_wireguard_peers_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wireguard_peers_dump>;

template class Dump<vapi_msg_wireguard_peers_dump, vapi_msg_wireguard_peers_details>;

using Wireguard_peers_dump = Dump<vapi_msg_wireguard_peers_dump, vapi_msg_wireguard_peers_details>;

template <> inline void vapi_swap_to_be<vapi_msg_wireguard_peers_details>(vapi_msg_wireguard_peers_details *msg)
{
  vapi_msg_wireguard_peers_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wireguard_peers_details>(vapi_msg_wireguard_peers_details *msg)
{
  vapi_msg_wireguard_peers_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wireguard_peers_details>()
{
  return ::vapi_msg_id_wireguard_peers_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wireguard_peers_details>>()
{
  return ::vapi_msg_id_wireguard_peers_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wireguard_peers_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wireguard_peers_details>(vapi_msg_id_wireguard_peers_details);
}

template class Msg<vapi_msg_wireguard_peers_details>;

using Wireguard_peers_details = Msg<vapi_msg_wireguard_peers_details>;
template <> inline void vapi_swap_to_be<vapi_msg_wg_set_async_mode>(vapi_msg_wg_set_async_mode *msg)
{
  vapi_msg_wg_set_async_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wg_set_async_mode>(vapi_msg_wg_set_async_mode *msg)
{
  vapi_msg_wg_set_async_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wg_set_async_mode>()
{
  return ::vapi_msg_id_wg_set_async_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wg_set_async_mode>>()
{
  return ::vapi_msg_id_wg_set_async_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wg_set_async_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wg_set_async_mode>(vapi_msg_id_wg_set_async_mode);
}

template <> inline vapi_msg_wg_set_async_mode* vapi_alloc<vapi_msg_wg_set_async_mode>(Connection &con)
{
  vapi_msg_wg_set_async_mode* result = vapi_alloc_wg_set_async_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_wg_set_async_mode>;

template class Request<vapi_msg_wg_set_async_mode, vapi_msg_wg_set_async_mode_reply>;

using Wg_set_async_mode = Request<vapi_msg_wg_set_async_mode, vapi_msg_wg_set_async_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_wg_set_async_mode_reply>(vapi_msg_wg_set_async_mode_reply *msg)
{
  vapi_msg_wg_set_async_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_wg_set_async_mode_reply>(vapi_msg_wg_set_async_mode_reply *msg)
{
  vapi_msg_wg_set_async_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_wg_set_async_mode_reply>()
{
  return ::vapi_msg_id_wg_set_async_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_wg_set_async_mode_reply>>()
{
  return ::vapi_msg_id_wg_set_async_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_wg_set_async_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_wg_set_async_mode_reply>(vapi_msg_id_wg_set_async_mode_reply);
}

template class Msg<vapi_msg_wg_set_async_mode_reply>;

using Wg_set_async_mode_reply = Msg<vapi_msg_wg_set_async_mode_reply>;
}
#endif
