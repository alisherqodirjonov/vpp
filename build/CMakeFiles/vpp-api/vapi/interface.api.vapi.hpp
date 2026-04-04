#ifndef __included_hpp_interface_api_json
#define __included_hpp_interface_api_json

#include <vapi/vapi.hpp>
#include <vapi/interface.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_flags>(vapi_msg_sw_interface_set_flags *msg)
{
  vapi_msg_sw_interface_set_flags_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_flags>(vapi_msg_sw_interface_set_flags *msg)
{
  vapi_msg_sw_interface_set_flags_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_flags>()
{
  return ::vapi_msg_id_sw_interface_set_flags; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_flags>>()
{
  return ::vapi_msg_id_sw_interface_set_flags; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_flags()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_flags>(vapi_msg_id_sw_interface_set_flags);
}

template <> inline vapi_msg_sw_interface_set_flags* vapi_alloc<vapi_msg_sw_interface_set_flags>(Connection &con)
{
  vapi_msg_sw_interface_set_flags* result = vapi_alloc_sw_interface_set_flags(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_flags>;

template class Request<vapi_msg_sw_interface_set_flags, vapi_msg_sw_interface_set_flags_reply>;

using Sw_interface_set_flags = Request<vapi_msg_sw_interface_set_flags, vapi_msg_sw_interface_set_flags_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_flags_reply>(vapi_msg_sw_interface_set_flags_reply *msg)
{
  vapi_msg_sw_interface_set_flags_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_flags_reply>(vapi_msg_sw_interface_set_flags_reply *msg)
{
  vapi_msg_sw_interface_set_flags_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_flags_reply>()
{
  return ::vapi_msg_id_sw_interface_set_flags_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_flags_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_flags_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_flags_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_flags_reply>(vapi_msg_id_sw_interface_set_flags_reply);
}

template class Msg<vapi_msg_sw_interface_set_flags_reply>;

using Sw_interface_set_flags_reply = Msg<vapi_msg_sw_interface_set_flags_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_promisc>(vapi_msg_sw_interface_set_promisc *msg)
{
  vapi_msg_sw_interface_set_promisc_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_promisc>(vapi_msg_sw_interface_set_promisc *msg)
{
  vapi_msg_sw_interface_set_promisc_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_promisc>()
{
  return ::vapi_msg_id_sw_interface_set_promisc; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_promisc>>()
{
  return ::vapi_msg_id_sw_interface_set_promisc; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_promisc()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_promisc>(vapi_msg_id_sw_interface_set_promisc);
}

template <> inline vapi_msg_sw_interface_set_promisc* vapi_alloc<vapi_msg_sw_interface_set_promisc>(Connection &con)
{
  vapi_msg_sw_interface_set_promisc* result = vapi_alloc_sw_interface_set_promisc(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_promisc>;

template class Request<vapi_msg_sw_interface_set_promisc, vapi_msg_sw_interface_set_promisc_reply>;

using Sw_interface_set_promisc = Request<vapi_msg_sw_interface_set_promisc, vapi_msg_sw_interface_set_promisc_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_promisc_reply>(vapi_msg_sw_interface_set_promisc_reply *msg)
{
  vapi_msg_sw_interface_set_promisc_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_promisc_reply>(vapi_msg_sw_interface_set_promisc_reply *msg)
{
  vapi_msg_sw_interface_set_promisc_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_promisc_reply>()
{
  return ::vapi_msg_id_sw_interface_set_promisc_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_promisc_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_promisc_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_promisc_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_promisc_reply>(vapi_msg_id_sw_interface_set_promisc_reply);
}

template class Msg<vapi_msg_sw_interface_set_promisc_reply>;

using Sw_interface_set_promisc_reply = Msg<vapi_msg_sw_interface_set_promisc_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_hw_interface_set_mtu>(vapi_msg_hw_interface_set_mtu *msg)
{
  vapi_msg_hw_interface_set_mtu_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_hw_interface_set_mtu>(vapi_msg_hw_interface_set_mtu *msg)
{
  vapi_msg_hw_interface_set_mtu_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_hw_interface_set_mtu>()
{
  return ::vapi_msg_id_hw_interface_set_mtu; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_hw_interface_set_mtu>>()
{
  return ::vapi_msg_id_hw_interface_set_mtu; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_hw_interface_set_mtu()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_hw_interface_set_mtu>(vapi_msg_id_hw_interface_set_mtu);
}

template <> inline vapi_msg_hw_interface_set_mtu* vapi_alloc<vapi_msg_hw_interface_set_mtu>(Connection &con)
{
  vapi_msg_hw_interface_set_mtu* result = vapi_alloc_hw_interface_set_mtu(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_hw_interface_set_mtu>;

template class Request<vapi_msg_hw_interface_set_mtu, vapi_msg_hw_interface_set_mtu_reply>;

using Hw_interface_set_mtu = Request<vapi_msg_hw_interface_set_mtu, vapi_msg_hw_interface_set_mtu_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_hw_interface_set_mtu_reply>(vapi_msg_hw_interface_set_mtu_reply *msg)
{
  vapi_msg_hw_interface_set_mtu_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_hw_interface_set_mtu_reply>(vapi_msg_hw_interface_set_mtu_reply *msg)
{
  vapi_msg_hw_interface_set_mtu_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_hw_interface_set_mtu_reply>()
{
  return ::vapi_msg_id_hw_interface_set_mtu_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_hw_interface_set_mtu_reply>>()
{
  return ::vapi_msg_id_hw_interface_set_mtu_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_hw_interface_set_mtu_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_hw_interface_set_mtu_reply>(vapi_msg_id_hw_interface_set_mtu_reply);
}

template class Msg<vapi_msg_hw_interface_set_mtu_reply>;

using Hw_interface_set_mtu_reply = Msg<vapi_msg_hw_interface_set_mtu_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_mtu>(vapi_msg_sw_interface_set_mtu *msg)
{
  vapi_msg_sw_interface_set_mtu_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_mtu>(vapi_msg_sw_interface_set_mtu *msg)
{
  vapi_msg_sw_interface_set_mtu_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_mtu>()
{
  return ::vapi_msg_id_sw_interface_set_mtu; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_mtu>>()
{
  return ::vapi_msg_id_sw_interface_set_mtu; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_mtu()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_mtu>(vapi_msg_id_sw_interface_set_mtu);
}

template <> inline vapi_msg_sw_interface_set_mtu* vapi_alloc<vapi_msg_sw_interface_set_mtu>(Connection &con)
{
  vapi_msg_sw_interface_set_mtu* result = vapi_alloc_sw_interface_set_mtu(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_mtu>;

template class Request<vapi_msg_sw_interface_set_mtu, vapi_msg_sw_interface_set_mtu_reply>;

using Sw_interface_set_mtu = Request<vapi_msg_sw_interface_set_mtu, vapi_msg_sw_interface_set_mtu_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_mtu_reply>(vapi_msg_sw_interface_set_mtu_reply *msg)
{
  vapi_msg_sw_interface_set_mtu_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_mtu_reply>(vapi_msg_sw_interface_set_mtu_reply *msg)
{
  vapi_msg_sw_interface_set_mtu_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_mtu_reply>()
{
  return ::vapi_msg_id_sw_interface_set_mtu_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_mtu_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_mtu_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_mtu_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_mtu_reply>(vapi_msg_id_sw_interface_set_mtu_reply);
}

template class Msg<vapi_msg_sw_interface_set_mtu_reply>;

using Sw_interface_set_mtu_reply = Msg<vapi_msg_sw_interface_set_mtu_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_ip_directed_broadcast>(vapi_msg_sw_interface_set_ip_directed_broadcast *msg)
{
  vapi_msg_sw_interface_set_ip_directed_broadcast_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_ip_directed_broadcast>(vapi_msg_sw_interface_set_ip_directed_broadcast *msg)
{
  vapi_msg_sw_interface_set_ip_directed_broadcast_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_ip_directed_broadcast>()
{
  return ::vapi_msg_id_sw_interface_set_ip_directed_broadcast; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_ip_directed_broadcast>>()
{
  return ::vapi_msg_id_sw_interface_set_ip_directed_broadcast; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_ip_directed_broadcast()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_ip_directed_broadcast>(vapi_msg_id_sw_interface_set_ip_directed_broadcast);
}

template <> inline vapi_msg_sw_interface_set_ip_directed_broadcast* vapi_alloc<vapi_msg_sw_interface_set_ip_directed_broadcast>(Connection &con)
{
  vapi_msg_sw_interface_set_ip_directed_broadcast* result = vapi_alloc_sw_interface_set_ip_directed_broadcast(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_ip_directed_broadcast>;

template class Request<vapi_msg_sw_interface_set_ip_directed_broadcast, vapi_msg_sw_interface_set_ip_directed_broadcast_reply>;

using Sw_interface_set_ip_directed_broadcast = Request<vapi_msg_sw_interface_set_ip_directed_broadcast, vapi_msg_sw_interface_set_ip_directed_broadcast_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>(vapi_msg_sw_interface_set_ip_directed_broadcast_reply *msg)
{
  vapi_msg_sw_interface_set_ip_directed_broadcast_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>(vapi_msg_sw_interface_set_ip_directed_broadcast_reply *msg)
{
  vapi_msg_sw_interface_set_ip_directed_broadcast_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>()
{
  return ::vapi_msg_id_sw_interface_set_ip_directed_broadcast_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_ip_directed_broadcast_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_ip_directed_broadcast_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>(vapi_msg_id_sw_interface_set_ip_directed_broadcast_reply);
}

template class Msg<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>;

using Sw_interface_set_ip_directed_broadcast_reply = Msg<vapi_msg_sw_interface_set_ip_directed_broadcast_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_event>(vapi_msg_sw_interface_event *msg)
{
  vapi_msg_sw_interface_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_event>(vapi_msg_sw_interface_event *msg)
{
  vapi_msg_sw_interface_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_event>()
{
  return ::vapi_msg_id_sw_interface_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_event>>()
{
  return ::vapi_msg_id_sw_interface_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_event>(vapi_msg_id_sw_interface_event);
}

template class Msg<vapi_msg_sw_interface_event>;

using Sw_interface_event = Msg<vapi_msg_sw_interface_event>;
template <> inline void vapi_swap_to_be<vapi_msg_want_interface_events>(vapi_msg_want_interface_events *msg)
{
  vapi_msg_want_interface_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_interface_events>(vapi_msg_want_interface_events *msg)
{
  vapi_msg_want_interface_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_interface_events>()
{
  return ::vapi_msg_id_want_interface_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_interface_events>>()
{
  return ::vapi_msg_id_want_interface_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_interface_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_interface_events>(vapi_msg_id_want_interface_events);
}

template <> inline vapi_msg_want_interface_events* vapi_alloc<vapi_msg_want_interface_events>(Connection &con)
{
  vapi_msg_want_interface_events* result = vapi_alloc_want_interface_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_interface_events>;

template class Request<vapi_msg_want_interface_events, vapi_msg_want_interface_events_reply>;

using Want_interface_events = Request<vapi_msg_want_interface_events, vapi_msg_want_interface_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_interface_events_reply>(vapi_msg_want_interface_events_reply *msg)
{
  vapi_msg_want_interface_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_interface_events_reply>(vapi_msg_want_interface_events_reply *msg)
{
  vapi_msg_want_interface_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_interface_events_reply>()
{
  return ::vapi_msg_id_want_interface_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_interface_events_reply>>()
{
  return ::vapi_msg_id_want_interface_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_interface_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_interface_events_reply>(vapi_msg_id_want_interface_events_reply);
}

template class Msg<vapi_msg_want_interface_events_reply>;

using Want_interface_events_reply = Msg<vapi_msg_want_interface_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_details>(vapi_msg_sw_interface_details *msg)
{
  vapi_msg_sw_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_details>(vapi_msg_sw_interface_details *msg)
{
  vapi_msg_sw_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_details>()
{
  return ::vapi_msg_id_sw_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_details>>()
{
  return ::vapi_msg_id_sw_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_details>(vapi_msg_id_sw_interface_details);
}

template class Msg<vapi_msg_sw_interface_details>;

using Sw_interface_details = Msg<vapi_msg_sw_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_dump>(vapi_msg_sw_interface_dump *msg)
{
  vapi_msg_sw_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_dump>(vapi_msg_sw_interface_dump *msg)
{
  vapi_msg_sw_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_dump>()
{
  return ::vapi_msg_id_sw_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_dump>>()
{
  return ::vapi_msg_id_sw_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_dump>(vapi_msg_id_sw_interface_dump);
}

template <> inline vapi_msg_sw_interface_dump* vapi_alloc<vapi_msg_sw_interface_dump, size_t>(Connection &con, size_t name_filter_buf_array_size)
{
  vapi_msg_sw_interface_dump* result = vapi_alloc_sw_interface_dump(con.vapi_ctx, name_filter_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_dump>;

template class Dump<vapi_msg_sw_interface_dump, vapi_msg_sw_interface_details, size_t>;

using Sw_interface_dump = Dump<vapi_msg_sw_interface_dump, vapi_msg_sw_interface_details, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_add_del_address>(vapi_msg_sw_interface_add_del_address *msg)
{
  vapi_msg_sw_interface_add_del_address_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_add_del_address>(vapi_msg_sw_interface_add_del_address *msg)
{
  vapi_msg_sw_interface_add_del_address_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_add_del_address>()
{
  return ::vapi_msg_id_sw_interface_add_del_address; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_add_del_address>>()
{
  return ::vapi_msg_id_sw_interface_add_del_address; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_add_del_address()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_add_del_address>(vapi_msg_id_sw_interface_add_del_address);
}

template <> inline vapi_msg_sw_interface_add_del_address* vapi_alloc<vapi_msg_sw_interface_add_del_address>(Connection &con)
{
  vapi_msg_sw_interface_add_del_address* result = vapi_alloc_sw_interface_add_del_address(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_add_del_address>;

template class Request<vapi_msg_sw_interface_add_del_address, vapi_msg_sw_interface_add_del_address_reply>;

using Sw_interface_add_del_address = Request<vapi_msg_sw_interface_add_del_address, vapi_msg_sw_interface_add_del_address_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_add_del_address_reply>(vapi_msg_sw_interface_add_del_address_reply *msg)
{
  vapi_msg_sw_interface_add_del_address_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_add_del_address_reply>(vapi_msg_sw_interface_add_del_address_reply *msg)
{
  vapi_msg_sw_interface_add_del_address_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_add_del_address_reply>()
{
  return ::vapi_msg_id_sw_interface_add_del_address_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_add_del_address_reply>>()
{
  return ::vapi_msg_id_sw_interface_add_del_address_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_add_del_address_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_add_del_address_reply>(vapi_msg_id_sw_interface_add_del_address_reply);
}

template class Msg<vapi_msg_sw_interface_add_del_address_reply>;

using Sw_interface_add_del_address_reply = Msg<vapi_msg_sw_interface_add_del_address_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_address_replace_begin>(vapi_msg_sw_interface_address_replace_begin *msg)
{
  vapi_msg_sw_interface_address_replace_begin_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_address_replace_begin>(vapi_msg_sw_interface_address_replace_begin *msg)
{
  vapi_msg_sw_interface_address_replace_begin_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_address_replace_begin>()
{
  return ::vapi_msg_id_sw_interface_address_replace_begin; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_address_replace_begin>>()
{
  return ::vapi_msg_id_sw_interface_address_replace_begin; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_address_replace_begin()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_address_replace_begin>(vapi_msg_id_sw_interface_address_replace_begin);
}

template <> inline vapi_msg_sw_interface_address_replace_begin* vapi_alloc<vapi_msg_sw_interface_address_replace_begin>(Connection &con)
{
  vapi_msg_sw_interface_address_replace_begin* result = vapi_alloc_sw_interface_address_replace_begin(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_address_replace_begin>;

template class Request<vapi_msg_sw_interface_address_replace_begin, vapi_msg_sw_interface_address_replace_begin_reply>;

using Sw_interface_address_replace_begin = Request<vapi_msg_sw_interface_address_replace_begin, vapi_msg_sw_interface_address_replace_begin_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_address_replace_begin_reply>(vapi_msg_sw_interface_address_replace_begin_reply *msg)
{
  vapi_msg_sw_interface_address_replace_begin_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_address_replace_begin_reply>(vapi_msg_sw_interface_address_replace_begin_reply *msg)
{
  vapi_msg_sw_interface_address_replace_begin_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_address_replace_begin_reply>()
{
  return ::vapi_msg_id_sw_interface_address_replace_begin_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_address_replace_begin_reply>>()
{
  return ::vapi_msg_id_sw_interface_address_replace_begin_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_address_replace_begin_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_address_replace_begin_reply>(vapi_msg_id_sw_interface_address_replace_begin_reply);
}

template class Msg<vapi_msg_sw_interface_address_replace_begin_reply>;

using Sw_interface_address_replace_begin_reply = Msg<vapi_msg_sw_interface_address_replace_begin_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_address_replace_end>(vapi_msg_sw_interface_address_replace_end *msg)
{
  vapi_msg_sw_interface_address_replace_end_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_address_replace_end>(vapi_msg_sw_interface_address_replace_end *msg)
{
  vapi_msg_sw_interface_address_replace_end_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_address_replace_end>()
{
  return ::vapi_msg_id_sw_interface_address_replace_end; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_address_replace_end>>()
{
  return ::vapi_msg_id_sw_interface_address_replace_end; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_address_replace_end()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_address_replace_end>(vapi_msg_id_sw_interface_address_replace_end);
}

template <> inline vapi_msg_sw_interface_address_replace_end* vapi_alloc<vapi_msg_sw_interface_address_replace_end>(Connection &con)
{
  vapi_msg_sw_interface_address_replace_end* result = vapi_alloc_sw_interface_address_replace_end(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_address_replace_end>;

template class Request<vapi_msg_sw_interface_address_replace_end, vapi_msg_sw_interface_address_replace_end_reply>;

using Sw_interface_address_replace_end = Request<vapi_msg_sw_interface_address_replace_end, vapi_msg_sw_interface_address_replace_end_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_address_replace_end_reply>(vapi_msg_sw_interface_address_replace_end_reply *msg)
{
  vapi_msg_sw_interface_address_replace_end_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_address_replace_end_reply>(vapi_msg_sw_interface_address_replace_end_reply *msg)
{
  vapi_msg_sw_interface_address_replace_end_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_address_replace_end_reply>()
{
  return ::vapi_msg_id_sw_interface_address_replace_end_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_address_replace_end_reply>>()
{
  return ::vapi_msg_id_sw_interface_address_replace_end_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_address_replace_end_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_address_replace_end_reply>(vapi_msg_id_sw_interface_address_replace_end_reply);
}

template class Msg<vapi_msg_sw_interface_address_replace_end_reply>;

using Sw_interface_address_replace_end_reply = Msg<vapi_msg_sw_interface_address_replace_end_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_table>(vapi_msg_sw_interface_set_table *msg)
{
  vapi_msg_sw_interface_set_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_table>(vapi_msg_sw_interface_set_table *msg)
{
  vapi_msg_sw_interface_set_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_table>()
{
  return ::vapi_msg_id_sw_interface_set_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_table>>()
{
  return ::vapi_msg_id_sw_interface_set_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_table>(vapi_msg_id_sw_interface_set_table);
}

template <> inline vapi_msg_sw_interface_set_table* vapi_alloc<vapi_msg_sw_interface_set_table>(Connection &con)
{
  vapi_msg_sw_interface_set_table* result = vapi_alloc_sw_interface_set_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_table>;

template class Request<vapi_msg_sw_interface_set_table, vapi_msg_sw_interface_set_table_reply>;

using Sw_interface_set_table = Request<vapi_msg_sw_interface_set_table, vapi_msg_sw_interface_set_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_table_reply>(vapi_msg_sw_interface_set_table_reply *msg)
{
  vapi_msg_sw_interface_set_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_table_reply>(vapi_msg_sw_interface_set_table_reply *msg)
{
  vapi_msg_sw_interface_set_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_table_reply>()
{
  return ::vapi_msg_id_sw_interface_set_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_table_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_table_reply>(vapi_msg_id_sw_interface_set_table_reply);
}

template class Msg<vapi_msg_sw_interface_set_table_reply>;

using Sw_interface_set_table_reply = Msg<vapi_msg_sw_interface_set_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_get_table>(vapi_msg_sw_interface_get_table *msg)
{
  vapi_msg_sw_interface_get_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_get_table>(vapi_msg_sw_interface_get_table *msg)
{
  vapi_msg_sw_interface_get_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_get_table>()
{
  return ::vapi_msg_id_sw_interface_get_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_get_table>>()
{
  return ::vapi_msg_id_sw_interface_get_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_get_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_get_table>(vapi_msg_id_sw_interface_get_table);
}

template <> inline vapi_msg_sw_interface_get_table* vapi_alloc<vapi_msg_sw_interface_get_table>(Connection &con)
{
  vapi_msg_sw_interface_get_table* result = vapi_alloc_sw_interface_get_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_get_table>;

template class Request<vapi_msg_sw_interface_get_table, vapi_msg_sw_interface_get_table_reply>;

using Sw_interface_get_table = Request<vapi_msg_sw_interface_get_table, vapi_msg_sw_interface_get_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_get_table_reply>(vapi_msg_sw_interface_get_table_reply *msg)
{
  vapi_msg_sw_interface_get_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_get_table_reply>(vapi_msg_sw_interface_get_table_reply *msg)
{
  vapi_msg_sw_interface_get_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_get_table_reply>()
{
  return ::vapi_msg_id_sw_interface_get_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_get_table_reply>>()
{
  return ::vapi_msg_id_sw_interface_get_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_get_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_get_table_reply>(vapi_msg_id_sw_interface_get_table_reply);
}

template class Msg<vapi_msg_sw_interface_get_table_reply>;

using Sw_interface_get_table_reply = Msg<vapi_msg_sw_interface_get_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_unnumbered>(vapi_msg_sw_interface_set_unnumbered *msg)
{
  vapi_msg_sw_interface_set_unnumbered_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_unnumbered>(vapi_msg_sw_interface_set_unnumbered *msg)
{
  vapi_msg_sw_interface_set_unnumbered_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_unnumbered>()
{
  return ::vapi_msg_id_sw_interface_set_unnumbered; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_unnumbered>>()
{
  return ::vapi_msg_id_sw_interface_set_unnumbered; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_unnumbered()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_unnumbered>(vapi_msg_id_sw_interface_set_unnumbered);
}

template <> inline vapi_msg_sw_interface_set_unnumbered* vapi_alloc<vapi_msg_sw_interface_set_unnumbered>(Connection &con)
{
  vapi_msg_sw_interface_set_unnumbered* result = vapi_alloc_sw_interface_set_unnumbered(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_unnumbered>;

template class Request<vapi_msg_sw_interface_set_unnumbered, vapi_msg_sw_interface_set_unnumbered_reply>;

using Sw_interface_set_unnumbered = Request<vapi_msg_sw_interface_set_unnumbered, vapi_msg_sw_interface_set_unnumbered_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_unnumbered_reply>(vapi_msg_sw_interface_set_unnumbered_reply *msg)
{
  vapi_msg_sw_interface_set_unnumbered_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_unnumbered_reply>(vapi_msg_sw_interface_set_unnumbered_reply *msg)
{
  vapi_msg_sw_interface_set_unnumbered_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_unnumbered_reply>()
{
  return ::vapi_msg_id_sw_interface_set_unnumbered_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_unnumbered_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_unnumbered_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_unnumbered_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_unnumbered_reply>(vapi_msg_id_sw_interface_set_unnumbered_reply);
}

template class Msg<vapi_msg_sw_interface_set_unnumbered_reply>;

using Sw_interface_set_unnumbered_reply = Msg<vapi_msg_sw_interface_set_unnumbered_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_clear_stats>(vapi_msg_sw_interface_clear_stats *msg)
{
  vapi_msg_sw_interface_clear_stats_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_clear_stats>(vapi_msg_sw_interface_clear_stats *msg)
{
  vapi_msg_sw_interface_clear_stats_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_clear_stats>()
{
  return ::vapi_msg_id_sw_interface_clear_stats; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_clear_stats>>()
{
  return ::vapi_msg_id_sw_interface_clear_stats; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_clear_stats()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_clear_stats>(vapi_msg_id_sw_interface_clear_stats);
}

template <> inline vapi_msg_sw_interface_clear_stats* vapi_alloc<vapi_msg_sw_interface_clear_stats>(Connection &con)
{
  vapi_msg_sw_interface_clear_stats* result = vapi_alloc_sw_interface_clear_stats(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_clear_stats>;

template class Request<vapi_msg_sw_interface_clear_stats, vapi_msg_sw_interface_clear_stats_reply>;

using Sw_interface_clear_stats = Request<vapi_msg_sw_interface_clear_stats, vapi_msg_sw_interface_clear_stats_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_clear_stats_reply>(vapi_msg_sw_interface_clear_stats_reply *msg)
{
  vapi_msg_sw_interface_clear_stats_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_clear_stats_reply>(vapi_msg_sw_interface_clear_stats_reply *msg)
{
  vapi_msg_sw_interface_clear_stats_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_clear_stats_reply>()
{
  return ::vapi_msg_id_sw_interface_clear_stats_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_clear_stats_reply>>()
{
  return ::vapi_msg_id_sw_interface_clear_stats_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_clear_stats_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_clear_stats_reply>(vapi_msg_id_sw_interface_clear_stats_reply);
}

template class Msg<vapi_msg_sw_interface_clear_stats_reply>;

using Sw_interface_clear_stats_reply = Msg<vapi_msg_sw_interface_clear_stats_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tag_add_del>(vapi_msg_sw_interface_tag_add_del *msg)
{
  vapi_msg_sw_interface_tag_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tag_add_del>(vapi_msg_sw_interface_tag_add_del *msg)
{
  vapi_msg_sw_interface_tag_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tag_add_del>()
{
  return ::vapi_msg_id_sw_interface_tag_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tag_add_del>>()
{
  return ::vapi_msg_id_sw_interface_tag_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tag_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tag_add_del>(vapi_msg_id_sw_interface_tag_add_del);
}

template <> inline vapi_msg_sw_interface_tag_add_del* vapi_alloc<vapi_msg_sw_interface_tag_add_del>(Connection &con)
{
  vapi_msg_sw_interface_tag_add_del* result = vapi_alloc_sw_interface_tag_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_tag_add_del>;

template class Request<vapi_msg_sw_interface_tag_add_del, vapi_msg_sw_interface_tag_add_del_reply>;

using Sw_interface_tag_add_del = Request<vapi_msg_sw_interface_tag_add_del, vapi_msg_sw_interface_tag_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tag_add_del_reply>(vapi_msg_sw_interface_tag_add_del_reply *msg)
{
  vapi_msg_sw_interface_tag_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tag_add_del_reply>(vapi_msg_sw_interface_tag_add_del_reply *msg)
{
  vapi_msg_sw_interface_tag_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tag_add_del_reply>()
{
  return ::vapi_msg_id_sw_interface_tag_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tag_add_del_reply>>()
{
  return ::vapi_msg_id_sw_interface_tag_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tag_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tag_add_del_reply>(vapi_msg_id_sw_interface_tag_add_del_reply);
}

template class Msg<vapi_msg_sw_interface_tag_add_del_reply>;

using Sw_interface_tag_add_del_reply = Msg<vapi_msg_sw_interface_tag_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_add_del_mac_address>(vapi_msg_sw_interface_add_del_mac_address *msg)
{
  vapi_msg_sw_interface_add_del_mac_address_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_add_del_mac_address>(vapi_msg_sw_interface_add_del_mac_address *msg)
{
  vapi_msg_sw_interface_add_del_mac_address_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_add_del_mac_address>()
{
  return ::vapi_msg_id_sw_interface_add_del_mac_address; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_add_del_mac_address>>()
{
  return ::vapi_msg_id_sw_interface_add_del_mac_address; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_add_del_mac_address()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_add_del_mac_address>(vapi_msg_id_sw_interface_add_del_mac_address);
}

template <> inline vapi_msg_sw_interface_add_del_mac_address* vapi_alloc<vapi_msg_sw_interface_add_del_mac_address>(Connection &con)
{
  vapi_msg_sw_interface_add_del_mac_address* result = vapi_alloc_sw_interface_add_del_mac_address(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_add_del_mac_address>;

template class Request<vapi_msg_sw_interface_add_del_mac_address, vapi_msg_sw_interface_add_del_mac_address_reply>;

using Sw_interface_add_del_mac_address = Request<vapi_msg_sw_interface_add_del_mac_address, vapi_msg_sw_interface_add_del_mac_address_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_add_del_mac_address_reply>(vapi_msg_sw_interface_add_del_mac_address_reply *msg)
{
  vapi_msg_sw_interface_add_del_mac_address_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_add_del_mac_address_reply>(vapi_msg_sw_interface_add_del_mac_address_reply *msg)
{
  vapi_msg_sw_interface_add_del_mac_address_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_add_del_mac_address_reply>()
{
  return ::vapi_msg_id_sw_interface_add_del_mac_address_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_add_del_mac_address_reply>>()
{
  return ::vapi_msg_id_sw_interface_add_del_mac_address_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_add_del_mac_address_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_add_del_mac_address_reply>(vapi_msg_id_sw_interface_add_del_mac_address_reply);
}

template class Msg<vapi_msg_sw_interface_add_del_mac_address_reply>;

using Sw_interface_add_del_mac_address_reply = Msg<vapi_msg_sw_interface_add_del_mac_address_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_mac_address>(vapi_msg_sw_interface_set_mac_address *msg)
{
  vapi_msg_sw_interface_set_mac_address_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_mac_address>(vapi_msg_sw_interface_set_mac_address *msg)
{
  vapi_msg_sw_interface_set_mac_address_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_mac_address>()
{
  return ::vapi_msg_id_sw_interface_set_mac_address; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_mac_address>>()
{
  return ::vapi_msg_id_sw_interface_set_mac_address; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_mac_address()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_mac_address>(vapi_msg_id_sw_interface_set_mac_address);
}

template <> inline vapi_msg_sw_interface_set_mac_address* vapi_alloc<vapi_msg_sw_interface_set_mac_address>(Connection &con)
{
  vapi_msg_sw_interface_set_mac_address* result = vapi_alloc_sw_interface_set_mac_address(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_mac_address>;

template class Request<vapi_msg_sw_interface_set_mac_address, vapi_msg_sw_interface_set_mac_address_reply>;

using Sw_interface_set_mac_address = Request<vapi_msg_sw_interface_set_mac_address, vapi_msg_sw_interface_set_mac_address_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_mac_address_reply>(vapi_msg_sw_interface_set_mac_address_reply *msg)
{
  vapi_msg_sw_interface_set_mac_address_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_mac_address_reply>(vapi_msg_sw_interface_set_mac_address_reply *msg)
{
  vapi_msg_sw_interface_set_mac_address_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_mac_address_reply>()
{
  return ::vapi_msg_id_sw_interface_set_mac_address_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_mac_address_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_mac_address_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_mac_address_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_mac_address_reply>(vapi_msg_id_sw_interface_set_mac_address_reply);
}

template class Msg<vapi_msg_sw_interface_set_mac_address_reply>;

using Sw_interface_set_mac_address_reply = Msg<vapi_msg_sw_interface_set_mac_address_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_get_mac_address>(vapi_msg_sw_interface_get_mac_address *msg)
{
  vapi_msg_sw_interface_get_mac_address_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_get_mac_address>(vapi_msg_sw_interface_get_mac_address *msg)
{
  vapi_msg_sw_interface_get_mac_address_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_get_mac_address>()
{
  return ::vapi_msg_id_sw_interface_get_mac_address; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_get_mac_address>>()
{
  return ::vapi_msg_id_sw_interface_get_mac_address; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_get_mac_address()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_get_mac_address>(vapi_msg_id_sw_interface_get_mac_address);
}

template <> inline vapi_msg_sw_interface_get_mac_address* vapi_alloc<vapi_msg_sw_interface_get_mac_address>(Connection &con)
{
  vapi_msg_sw_interface_get_mac_address* result = vapi_alloc_sw_interface_get_mac_address(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_get_mac_address>;

template class Request<vapi_msg_sw_interface_get_mac_address, vapi_msg_sw_interface_get_mac_address_reply>;

using Sw_interface_get_mac_address = Request<vapi_msg_sw_interface_get_mac_address, vapi_msg_sw_interface_get_mac_address_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_get_mac_address_reply>(vapi_msg_sw_interface_get_mac_address_reply *msg)
{
  vapi_msg_sw_interface_get_mac_address_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_get_mac_address_reply>(vapi_msg_sw_interface_get_mac_address_reply *msg)
{
  vapi_msg_sw_interface_get_mac_address_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_get_mac_address_reply>()
{
  return ::vapi_msg_id_sw_interface_get_mac_address_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_get_mac_address_reply>>()
{
  return ::vapi_msg_id_sw_interface_get_mac_address_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_get_mac_address_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_get_mac_address_reply>(vapi_msg_id_sw_interface_get_mac_address_reply);
}

template class Msg<vapi_msg_sw_interface_get_mac_address_reply>;

using Sw_interface_get_mac_address_reply = Msg<vapi_msg_sw_interface_get_mac_address_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_rx_mode>(vapi_msg_sw_interface_set_rx_mode *msg)
{
  vapi_msg_sw_interface_set_rx_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_rx_mode>(vapi_msg_sw_interface_set_rx_mode *msg)
{
  vapi_msg_sw_interface_set_rx_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_rx_mode>()
{
  return ::vapi_msg_id_sw_interface_set_rx_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_rx_mode>>()
{
  return ::vapi_msg_id_sw_interface_set_rx_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_rx_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_rx_mode>(vapi_msg_id_sw_interface_set_rx_mode);
}

template <> inline vapi_msg_sw_interface_set_rx_mode* vapi_alloc<vapi_msg_sw_interface_set_rx_mode>(Connection &con)
{
  vapi_msg_sw_interface_set_rx_mode* result = vapi_alloc_sw_interface_set_rx_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_rx_mode>;

template class Request<vapi_msg_sw_interface_set_rx_mode, vapi_msg_sw_interface_set_rx_mode_reply>;

using Sw_interface_set_rx_mode = Request<vapi_msg_sw_interface_set_rx_mode, vapi_msg_sw_interface_set_rx_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_rx_mode_reply>(vapi_msg_sw_interface_set_rx_mode_reply *msg)
{
  vapi_msg_sw_interface_set_rx_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_rx_mode_reply>(vapi_msg_sw_interface_set_rx_mode_reply *msg)
{
  vapi_msg_sw_interface_set_rx_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_rx_mode_reply>()
{
  return ::vapi_msg_id_sw_interface_set_rx_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_rx_mode_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_rx_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_rx_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_rx_mode_reply>(vapi_msg_id_sw_interface_set_rx_mode_reply);
}

template class Msg<vapi_msg_sw_interface_set_rx_mode_reply>;

using Sw_interface_set_rx_mode_reply = Msg<vapi_msg_sw_interface_set_rx_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_rx_placement>(vapi_msg_sw_interface_set_rx_placement *msg)
{
  vapi_msg_sw_interface_set_rx_placement_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_rx_placement>(vapi_msg_sw_interface_set_rx_placement *msg)
{
  vapi_msg_sw_interface_set_rx_placement_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_rx_placement>()
{
  return ::vapi_msg_id_sw_interface_set_rx_placement; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_rx_placement>>()
{
  return ::vapi_msg_id_sw_interface_set_rx_placement; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_rx_placement()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_rx_placement>(vapi_msg_id_sw_interface_set_rx_placement);
}

template <> inline vapi_msg_sw_interface_set_rx_placement* vapi_alloc<vapi_msg_sw_interface_set_rx_placement>(Connection &con)
{
  vapi_msg_sw_interface_set_rx_placement* result = vapi_alloc_sw_interface_set_rx_placement(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_rx_placement>;

template class Request<vapi_msg_sw_interface_set_rx_placement, vapi_msg_sw_interface_set_rx_placement_reply>;

using Sw_interface_set_rx_placement = Request<vapi_msg_sw_interface_set_rx_placement, vapi_msg_sw_interface_set_rx_placement_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_rx_placement_reply>(vapi_msg_sw_interface_set_rx_placement_reply *msg)
{
  vapi_msg_sw_interface_set_rx_placement_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_rx_placement_reply>(vapi_msg_sw_interface_set_rx_placement_reply *msg)
{
  vapi_msg_sw_interface_set_rx_placement_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_rx_placement_reply>()
{
  return ::vapi_msg_id_sw_interface_set_rx_placement_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_rx_placement_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_rx_placement_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_rx_placement_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_rx_placement_reply>(vapi_msg_id_sw_interface_set_rx_placement_reply);
}

template class Msg<vapi_msg_sw_interface_set_rx_placement_reply>;

using Sw_interface_set_rx_placement_reply = Msg<vapi_msg_sw_interface_set_rx_placement_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_tx_placement>(vapi_msg_sw_interface_set_tx_placement *msg)
{
  vapi_msg_sw_interface_set_tx_placement_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_tx_placement>(vapi_msg_sw_interface_set_tx_placement *msg)
{
  vapi_msg_sw_interface_set_tx_placement_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_tx_placement>()
{
  return ::vapi_msg_id_sw_interface_set_tx_placement; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_tx_placement>>()
{
  return ::vapi_msg_id_sw_interface_set_tx_placement; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_tx_placement()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_tx_placement>(vapi_msg_id_sw_interface_set_tx_placement);
}

template <> inline vapi_msg_sw_interface_set_tx_placement* vapi_alloc<vapi_msg_sw_interface_set_tx_placement, size_t>(Connection &con, size_t _threads_array_size)
{
  vapi_msg_sw_interface_set_tx_placement* result = vapi_alloc_sw_interface_set_tx_placement(con.vapi_ctx, _threads_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_tx_placement>;

template class Request<vapi_msg_sw_interface_set_tx_placement, vapi_msg_sw_interface_set_tx_placement_reply, size_t>;

using Sw_interface_set_tx_placement = Request<vapi_msg_sw_interface_set_tx_placement, vapi_msg_sw_interface_set_tx_placement_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_tx_placement_reply>(vapi_msg_sw_interface_set_tx_placement_reply *msg)
{
  vapi_msg_sw_interface_set_tx_placement_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_tx_placement_reply>(vapi_msg_sw_interface_set_tx_placement_reply *msg)
{
  vapi_msg_sw_interface_set_tx_placement_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_tx_placement_reply>()
{
  return ::vapi_msg_id_sw_interface_set_tx_placement_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_tx_placement_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_tx_placement_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_tx_placement_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_tx_placement_reply>(vapi_msg_id_sw_interface_set_tx_placement_reply);
}

template class Msg<vapi_msg_sw_interface_set_tx_placement_reply>;

using Sw_interface_set_tx_placement_reply = Msg<vapi_msg_sw_interface_set_tx_placement_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_interface_name>(vapi_msg_sw_interface_set_interface_name *msg)
{
  vapi_msg_sw_interface_set_interface_name_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_interface_name>(vapi_msg_sw_interface_set_interface_name *msg)
{
  vapi_msg_sw_interface_set_interface_name_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_interface_name>()
{
  return ::vapi_msg_id_sw_interface_set_interface_name; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_interface_name>>()
{
  return ::vapi_msg_id_sw_interface_set_interface_name; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_interface_name()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_interface_name>(vapi_msg_id_sw_interface_set_interface_name);
}

template <> inline vapi_msg_sw_interface_set_interface_name* vapi_alloc<vapi_msg_sw_interface_set_interface_name>(Connection &con)
{
  vapi_msg_sw_interface_set_interface_name* result = vapi_alloc_sw_interface_set_interface_name(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_interface_name>;

template class Request<vapi_msg_sw_interface_set_interface_name, vapi_msg_sw_interface_set_interface_name_reply>;

using Sw_interface_set_interface_name = Request<vapi_msg_sw_interface_set_interface_name, vapi_msg_sw_interface_set_interface_name_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_interface_name_reply>(vapi_msg_sw_interface_set_interface_name_reply *msg)
{
  vapi_msg_sw_interface_set_interface_name_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_interface_name_reply>(vapi_msg_sw_interface_set_interface_name_reply *msg)
{
  vapi_msg_sw_interface_set_interface_name_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_interface_name_reply>()
{
  return ::vapi_msg_id_sw_interface_set_interface_name_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_interface_name_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_interface_name_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_interface_name_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_interface_name_reply>(vapi_msg_id_sw_interface_set_interface_name_reply);
}

template class Msg<vapi_msg_sw_interface_set_interface_name_reply>;

using Sw_interface_set_interface_name_reply = Msg<vapi_msg_sw_interface_set_interface_name_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_rx_placement_dump>(vapi_msg_sw_interface_rx_placement_dump *msg)
{
  vapi_msg_sw_interface_rx_placement_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_rx_placement_dump>(vapi_msg_sw_interface_rx_placement_dump *msg)
{
  vapi_msg_sw_interface_rx_placement_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_rx_placement_dump>()
{
  return ::vapi_msg_id_sw_interface_rx_placement_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_rx_placement_dump>>()
{
  return ::vapi_msg_id_sw_interface_rx_placement_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_rx_placement_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_rx_placement_dump>(vapi_msg_id_sw_interface_rx_placement_dump);
}

template <> inline vapi_msg_sw_interface_rx_placement_dump* vapi_alloc<vapi_msg_sw_interface_rx_placement_dump>(Connection &con)
{
  vapi_msg_sw_interface_rx_placement_dump* result = vapi_alloc_sw_interface_rx_placement_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_rx_placement_dump>;

template class Dump<vapi_msg_sw_interface_rx_placement_dump, vapi_msg_sw_interface_rx_placement_details>;

using Sw_interface_rx_placement_dump = Dump<vapi_msg_sw_interface_rx_placement_dump, vapi_msg_sw_interface_rx_placement_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_rx_placement_details>(vapi_msg_sw_interface_rx_placement_details *msg)
{
  vapi_msg_sw_interface_rx_placement_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_rx_placement_details>(vapi_msg_sw_interface_rx_placement_details *msg)
{
  vapi_msg_sw_interface_rx_placement_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_rx_placement_details>()
{
  return ::vapi_msg_id_sw_interface_rx_placement_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_rx_placement_details>>()
{
  return ::vapi_msg_id_sw_interface_rx_placement_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_rx_placement_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_rx_placement_details>(vapi_msg_id_sw_interface_rx_placement_details);
}

template class Msg<vapi_msg_sw_interface_rx_placement_details>;

using Sw_interface_rx_placement_details = Msg<vapi_msg_sw_interface_rx_placement_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tx_placement_get>(vapi_msg_sw_interface_tx_placement_get *msg)
{
  vapi_msg_sw_interface_tx_placement_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tx_placement_get>(vapi_msg_sw_interface_tx_placement_get *msg)
{
  vapi_msg_sw_interface_tx_placement_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tx_placement_get>()
{
  return ::vapi_msg_id_sw_interface_tx_placement_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tx_placement_get>>()
{
  return ::vapi_msg_id_sw_interface_tx_placement_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tx_placement_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tx_placement_get>(vapi_msg_id_sw_interface_tx_placement_get);
}

template <> inline vapi_msg_sw_interface_tx_placement_get* vapi_alloc<vapi_msg_sw_interface_tx_placement_get>(Connection &con)
{
  vapi_msg_sw_interface_tx_placement_get* result = vapi_alloc_sw_interface_tx_placement_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_tx_placement_get>;

template class Stream<vapi_msg_sw_interface_tx_placement_get, vapi_msg_sw_interface_tx_placement_get_reply, vapi_msg_sw_interface_tx_placement_details>;

using Sw_interface_tx_placement_get = Stream<vapi_msg_sw_interface_tx_placement_get, vapi_msg_sw_interface_tx_placement_get_reply, vapi_msg_sw_interface_tx_placement_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tx_placement_get_reply>(vapi_msg_sw_interface_tx_placement_get_reply *msg)
{
  vapi_msg_sw_interface_tx_placement_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tx_placement_get_reply>(vapi_msg_sw_interface_tx_placement_get_reply *msg)
{
  vapi_msg_sw_interface_tx_placement_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tx_placement_get_reply>()
{
  return ::vapi_msg_id_sw_interface_tx_placement_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tx_placement_get_reply>>()
{
  return ::vapi_msg_id_sw_interface_tx_placement_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tx_placement_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tx_placement_get_reply>(vapi_msg_id_sw_interface_tx_placement_get_reply);
}

template class Msg<vapi_msg_sw_interface_tx_placement_get_reply>;

using Sw_interface_tx_placement_get_reply = Msg<vapi_msg_sw_interface_tx_placement_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_tx_placement_details>(vapi_msg_sw_interface_tx_placement_details *msg)
{
  vapi_msg_sw_interface_tx_placement_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_tx_placement_details>(vapi_msg_sw_interface_tx_placement_details *msg)
{
  vapi_msg_sw_interface_tx_placement_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_tx_placement_details>()
{
  return ::vapi_msg_id_sw_interface_tx_placement_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_tx_placement_details>>()
{
  return ::vapi_msg_id_sw_interface_tx_placement_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_tx_placement_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_tx_placement_details>(vapi_msg_id_sw_interface_tx_placement_details);
}

template class Msg<vapi_msg_sw_interface_tx_placement_details>;

template <> inline void vapi_swap_to_be<vapi_msg_interface_name_renumber>(vapi_msg_interface_name_renumber *msg)
{
  vapi_msg_interface_name_renumber_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_interface_name_renumber>(vapi_msg_interface_name_renumber *msg)
{
  vapi_msg_interface_name_renumber_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_interface_name_renumber>()
{
  return ::vapi_msg_id_interface_name_renumber; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_interface_name_renumber>>()
{
  return ::vapi_msg_id_interface_name_renumber; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_interface_name_renumber()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_interface_name_renumber>(vapi_msg_id_interface_name_renumber);
}

template <> inline vapi_msg_interface_name_renumber* vapi_alloc<vapi_msg_interface_name_renumber>(Connection &con)
{
  vapi_msg_interface_name_renumber* result = vapi_alloc_interface_name_renumber(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_interface_name_renumber>;

template class Request<vapi_msg_interface_name_renumber, vapi_msg_interface_name_renumber_reply>;

using Interface_name_renumber = Request<vapi_msg_interface_name_renumber, vapi_msg_interface_name_renumber_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_interface_name_renumber_reply>(vapi_msg_interface_name_renumber_reply *msg)
{
  vapi_msg_interface_name_renumber_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_interface_name_renumber_reply>(vapi_msg_interface_name_renumber_reply *msg)
{
  vapi_msg_interface_name_renumber_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_interface_name_renumber_reply>()
{
  return ::vapi_msg_id_interface_name_renumber_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_interface_name_renumber_reply>>()
{
  return ::vapi_msg_id_interface_name_renumber_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_interface_name_renumber_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_interface_name_renumber_reply>(vapi_msg_id_interface_name_renumber_reply);
}

template class Msg<vapi_msg_interface_name_renumber_reply>;

using Interface_name_renumber_reply = Msg<vapi_msg_interface_name_renumber_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_create_subif>(vapi_msg_create_subif *msg)
{
  vapi_msg_create_subif_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_subif>(vapi_msg_create_subif *msg)
{
  vapi_msg_create_subif_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_subif>()
{
  return ::vapi_msg_id_create_subif; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_subif>>()
{
  return ::vapi_msg_id_create_subif; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_subif()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_subif>(vapi_msg_id_create_subif);
}

template <> inline vapi_msg_create_subif* vapi_alloc<vapi_msg_create_subif>(Connection &con)
{
  vapi_msg_create_subif* result = vapi_alloc_create_subif(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_create_subif>;

template class Request<vapi_msg_create_subif, vapi_msg_create_subif_reply>;

using Create_subif = Request<vapi_msg_create_subif, vapi_msg_create_subif_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_create_subif_reply>(vapi_msg_create_subif_reply *msg)
{
  vapi_msg_create_subif_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_subif_reply>(vapi_msg_create_subif_reply *msg)
{
  vapi_msg_create_subif_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_subif_reply>()
{
  return ::vapi_msg_id_create_subif_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_subif_reply>>()
{
  return ::vapi_msg_id_create_subif_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_subif_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_subif_reply>(vapi_msg_id_create_subif_reply);
}

template class Msg<vapi_msg_create_subif_reply>;

using Create_subif_reply = Msg<vapi_msg_create_subif_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_create_vlan_subif>(vapi_msg_create_vlan_subif *msg)
{
  vapi_msg_create_vlan_subif_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_vlan_subif>(vapi_msg_create_vlan_subif *msg)
{
  vapi_msg_create_vlan_subif_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_vlan_subif>()
{
  return ::vapi_msg_id_create_vlan_subif; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_vlan_subif>>()
{
  return ::vapi_msg_id_create_vlan_subif; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_vlan_subif()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_vlan_subif>(vapi_msg_id_create_vlan_subif);
}

template <> inline vapi_msg_create_vlan_subif* vapi_alloc<vapi_msg_create_vlan_subif>(Connection &con)
{
  vapi_msg_create_vlan_subif* result = vapi_alloc_create_vlan_subif(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_create_vlan_subif>;

template class Request<vapi_msg_create_vlan_subif, vapi_msg_create_vlan_subif_reply>;

using Create_vlan_subif = Request<vapi_msg_create_vlan_subif, vapi_msg_create_vlan_subif_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_create_vlan_subif_reply>(vapi_msg_create_vlan_subif_reply *msg)
{
  vapi_msg_create_vlan_subif_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_vlan_subif_reply>(vapi_msg_create_vlan_subif_reply *msg)
{
  vapi_msg_create_vlan_subif_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_vlan_subif_reply>()
{
  return ::vapi_msg_id_create_vlan_subif_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_vlan_subif_reply>>()
{
  return ::vapi_msg_id_create_vlan_subif_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_vlan_subif_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_vlan_subif_reply>(vapi_msg_id_create_vlan_subif_reply);
}

template class Msg<vapi_msg_create_vlan_subif_reply>;

using Create_vlan_subif_reply = Msg<vapi_msg_create_vlan_subif_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_delete_subif>(vapi_msg_delete_subif *msg)
{
  vapi_msg_delete_subif_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_delete_subif>(vapi_msg_delete_subif *msg)
{
  vapi_msg_delete_subif_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_delete_subif>()
{
  return ::vapi_msg_id_delete_subif; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_delete_subif>>()
{
  return ::vapi_msg_id_delete_subif; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_delete_subif()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_delete_subif>(vapi_msg_id_delete_subif);
}

template <> inline vapi_msg_delete_subif* vapi_alloc<vapi_msg_delete_subif>(Connection &con)
{
  vapi_msg_delete_subif* result = vapi_alloc_delete_subif(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_delete_subif>;

template class Request<vapi_msg_delete_subif, vapi_msg_delete_subif_reply>;

using Delete_subif = Request<vapi_msg_delete_subif, vapi_msg_delete_subif_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_delete_subif_reply>(vapi_msg_delete_subif_reply *msg)
{
  vapi_msg_delete_subif_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_delete_subif_reply>(vapi_msg_delete_subif_reply *msg)
{
  vapi_msg_delete_subif_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_delete_subif_reply>()
{
  return ::vapi_msg_id_delete_subif_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_delete_subif_reply>>()
{
  return ::vapi_msg_id_delete_subif_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_delete_subif_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_delete_subif_reply>(vapi_msg_id_delete_subif_reply);
}

template class Msg<vapi_msg_delete_subif_reply>;

using Delete_subif_reply = Msg<vapi_msg_delete_subif_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_create_loopback>(vapi_msg_create_loopback *msg)
{
  vapi_msg_create_loopback_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_loopback>(vapi_msg_create_loopback *msg)
{
  vapi_msg_create_loopback_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_loopback>()
{
  return ::vapi_msg_id_create_loopback; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_loopback>>()
{
  return ::vapi_msg_id_create_loopback; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_loopback()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_loopback>(vapi_msg_id_create_loopback);
}

template <> inline vapi_msg_create_loopback* vapi_alloc<vapi_msg_create_loopback>(Connection &con)
{
  vapi_msg_create_loopback* result = vapi_alloc_create_loopback(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_create_loopback>;

template class Request<vapi_msg_create_loopback, vapi_msg_create_loopback_reply>;

using Create_loopback = Request<vapi_msg_create_loopback, vapi_msg_create_loopback_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_create_loopback_reply>(vapi_msg_create_loopback_reply *msg)
{
  vapi_msg_create_loopback_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_loopback_reply>(vapi_msg_create_loopback_reply *msg)
{
  vapi_msg_create_loopback_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_loopback_reply>()
{
  return ::vapi_msg_id_create_loopback_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_loopback_reply>>()
{
  return ::vapi_msg_id_create_loopback_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_loopback_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_loopback_reply>(vapi_msg_id_create_loopback_reply);
}

template class Msg<vapi_msg_create_loopback_reply>;

using Create_loopback_reply = Msg<vapi_msg_create_loopback_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_create_loopback_instance>(vapi_msg_create_loopback_instance *msg)
{
  vapi_msg_create_loopback_instance_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_loopback_instance>(vapi_msg_create_loopback_instance *msg)
{
  vapi_msg_create_loopback_instance_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_loopback_instance>()
{
  return ::vapi_msg_id_create_loopback_instance; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_loopback_instance>>()
{
  return ::vapi_msg_id_create_loopback_instance; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_loopback_instance()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_loopback_instance>(vapi_msg_id_create_loopback_instance);
}

template <> inline vapi_msg_create_loopback_instance* vapi_alloc<vapi_msg_create_loopback_instance>(Connection &con)
{
  vapi_msg_create_loopback_instance* result = vapi_alloc_create_loopback_instance(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_create_loopback_instance>;

template class Request<vapi_msg_create_loopback_instance, vapi_msg_create_loopback_instance_reply>;

using Create_loopback_instance = Request<vapi_msg_create_loopback_instance, vapi_msg_create_loopback_instance_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_create_loopback_instance_reply>(vapi_msg_create_loopback_instance_reply *msg)
{
  vapi_msg_create_loopback_instance_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_loopback_instance_reply>(vapi_msg_create_loopback_instance_reply *msg)
{
  vapi_msg_create_loopback_instance_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_loopback_instance_reply>()
{
  return ::vapi_msg_id_create_loopback_instance_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_loopback_instance_reply>>()
{
  return ::vapi_msg_id_create_loopback_instance_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_loopback_instance_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_loopback_instance_reply>(vapi_msg_id_create_loopback_instance_reply);
}

template class Msg<vapi_msg_create_loopback_instance_reply>;

using Create_loopback_instance_reply = Msg<vapi_msg_create_loopback_instance_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_delete_loopback>(vapi_msg_delete_loopback *msg)
{
  vapi_msg_delete_loopback_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_delete_loopback>(vapi_msg_delete_loopback *msg)
{
  vapi_msg_delete_loopback_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_delete_loopback>()
{
  return ::vapi_msg_id_delete_loopback; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_delete_loopback>>()
{
  return ::vapi_msg_id_delete_loopback; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_delete_loopback()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_delete_loopback>(vapi_msg_id_delete_loopback);
}

template <> inline vapi_msg_delete_loopback* vapi_alloc<vapi_msg_delete_loopback>(Connection &con)
{
  vapi_msg_delete_loopback* result = vapi_alloc_delete_loopback(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_delete_loopback>;

template class Request<vapi_msg_delete_loopback, vapi_msg_delete_loopback_reply>;

using Delete_loopback = Request<vapi_msg_delete_loopback, vapi_msg_delete_loopback_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_delete_loopback_reply>(vapi_msg_delete_loopback_reply *msg)
{
  vapi_msg_delete_loopback_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_delete_loopback_reply>(vapi_msg_delete_loopback_reply *msg)
{
  vapi_msg_delete_loopback_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_delete_loopback_reply>()
{
  return ::vapi_msg_id_delete_loopback_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_delete_loopback_reply>>()
{
  return ::vapi_msg_id_delete_loopback_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_delete_loopback_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_delete_loopback_reply>(vapi_msg_id_delete_loopback_reply);
}

template class Msg<vapi_msg_delete_loopback_reply>;

using Delete_loopback_reply = Msg<vapi_msg_delete_loopback_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_collect_detailed_interface_stats>(vapi_msg_collect_detailed_interface_stats *msg)
{
  vapi_msg_collect_detailed_interface_stats_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_collect_detailed_interface_stats>(vapi_msg_collect_detailed_interface_stats *msg)
{
  vapi_msg_collect_detailed_interface_stats_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_collect_detailed_interface_stats>()
{
  return ::vapi_msg_id_collect_detailed_interface_stats; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_collect_detailed_interface_stats>>()
{
  return ::vapi_msg_id_collect_detailed_interface_stats; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_collect_detailed_interface_stats()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_collect_detailed_interface_stats>(vapi_msg_id_collect_detailed_interface_stats);
}

template <> inline vapi_msg_collect_detailed_interface_stats* vapi_alloc<vapi_msg_collect_detailed_interface_stats>(Connection &con)
{
  vapi_msg_collect_detailed_interface_stats* result = vapi_alloc_collect_detailed_interface_stats(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_collect_detailed_interface_stats>;

template class Request<vapi_msg_collect_detailed_interface_stats, vapi_msg_collect_detailed_interface_stats_reply>;

using Collect_detailed_interface_stats = Request<vapi_msg_collect_detailed_interface_stats, vapi_msg_collect_detailed_interface_stats_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_collect_detailed_interface_stats_reply>(vapi_msg_collect_detailed_interface_stats_reply *msg)
{
  vapi_msg_collect_detailed_interface_stats_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_collect_detailed_interface_stats_reply>(vapi_msg_collect_detailed_interface_stats_reply *msg)
{
  vapi_msg_collect_detailed_interface_stats_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_collect_detailed_interface_stats_reply>()
{
  return ::vapi_msg_id_collect_detailed_interface_stats_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_collect_detailed_interface_stats_reply>>()
{
  return ::vapi_msg_id_collect_detailed_interface_stats_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_collect_detailed_interface_stats_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_collect_detailed_interface_stats_reply>(vapi_msg_id_collect_detailed_interface_stats_reply);
}

template class Msg<vapi_msg_collect_detailed_interface_stats_reply>;

using Collect_detailed_interface_stats_reply = Msg<vapi_msg_collect_detailed_interface_stats_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pcap_set_filter_function>(vapi_msg_pcap_set_filter_function *msg)
{
  vapi_msg_pcap_set_filter_function_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pcap_set_filter_function>(vapi_msg_pcap_set_filter_function *msg)
{
  vapi_msg_pcap_set_filter_function_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pcap_set_filter_function>()
{
  return ::vapi_msg_id_pcap_set_filter_function; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pcap_set_filter_function>>()
{
  return ::vapi_msg_id_pcap_set_filter_function; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pcap_set_filter_function()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pcap_set_filter_function>(vapi_msg_id_pcap_set_filter_function);
}

template <> inline vapi_msg_pcap_set_filter_function* vapi_alloc<vapi_msg_pcap_set_filter_function, size_t>(Connection &con, size_t filter_function_name_buf_array_size)
{
  vapi_msg_pcap_set_filter_function* result = vapi_alloc_pcap_set_filter_function(con.vapi_ctx, filter_function_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pcap_set_filter_function>;

template class Request<vapi_msg_pcap_set_filter_function, vapi_msg_pcap_set_filter_function_reply, size_t>;

using Pcap_set_filter_function = Request<vapi_msg_pcap_set_filter_function, vapi_msg_pcap_set_filter_function_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_pcap_set_filter_function_reply>(vapi_msg_pcap_set_filter_function_reply *msg)
{
  vapi_msg_pcap_set_filter_function_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pcap_set_filter_function_reply>(vapi_msg_pcap_set_filter_function_reply *msg)
{
  vapi_msg_pcap_set_filter_function_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pcap_set_filter_function_reply>()
{
  return ::vapi_msg_id_pcap_set_filter_function_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pcap_set_filter_function_reply>>()
{
  return ::vapi_msg_id_pcap_set_filter_function_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pcap_set_filter_function_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pcap_set_filter_function_reply>(vapi_msg_id_pcap_set_filter_function_reply);
}

template class Msg<vapi_msg_pcap_set_filter_function_reply>;

using Pcap_set_filter_function_reply = Msg<vapi_msg_pcap_set_filter_function_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pcap_trace_on>(vapi_msg_pcap_trace_on *msg)
{
  vapi_msg_pcap_trace_on_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pcap_trace_on>(vapi_msg_pcap_trace_on *msg)
{
  vapi_msg_pcap_trace_on_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pcap_trace_on>()
{
  return ::vapi_msg_id_pcap_trace_on; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pcap_trace_on>>()
{
  return ::vapi_msg_id_pcap_trace_on; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pcap_trace_on()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pcap_trace_on>(vapi_msg_id_pcap_trace_on);
}

template <> inline vapi_msg_pcap_trace_on* vapi_alloc<vapi_msg_pcap_trace_on>(Connection &con)
{
  vapi_msg_pcap_trace_on* result = vapi_alloc_pcap_trace_on(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pcap_trace_on>;

template class Request<vapi_msg_pcap_trace_on, vapi_msg_pcap_trace_on_reply>;

using Pcap_trace_on = Request<vapi_msg_pcap_trace_on, vapi_msg_pcap_trace_on_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pcap_trace_on_reply>(vapi_msg_pcap_trace_on_reply *msg)
{
  vapi_msg_pcap_trace_on_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pcap_trace_on_reply>(vapi_msg_pcap_trace_on_reply *msg)
{
  vapi_msg_pcap_trace_on_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pcap_trace_on_reply>()
{
  return ::vapi_msg_id_pcap_trace_on_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pcap_trace_on_reply>>()
{
  return ::vapi_msg_id_pcap_trace_on_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pcap_trace_on_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pcap_trace_on_reply>(vapi_msg_id_pcap_trace_on_reply);
}

template class Msg<vapi_msg_pcap_trace_on_reply>;

using Pcap_trace_on_reply = Msg<vapi_msg_pcap_trace_on_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pcap_trace_off>(vapi_msg_pcap_trace_off *msg)
{
  vapi_msg_pcap_trace_off_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pcap_trace_off>(vapi_msg_pcap_trace_off *msg)
{
  vapi_msg_pcap_trace_off_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pcap_trace_off>()
{
  return ::vapi_msg_id_pcap_trace_off; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pcap_trace_off>>()
{
  return ::vapi_msg_id_pcap_trace_off; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pcap_trace_off()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pcap_trace_off>(vapi_msg_id_pcap_trace_off);
}

template <> inline vapi_msg_pcap_trace_off* vapi_alloc<vapi_msg_pcap_trace_off>(Connection &con)
{
  vapi_msg_pcap_trace_off* result = vapi_alloc_pcap_trace_off(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pcap_trace_off>;

template class Request<vapi_msg_pcap_trace_off, vapi_msg_pcap_trace_off_reply>;

using Pcap_trace_off = Request<vapi_msg_pcap_trace_off, vapi_msg_pcap_trace_off_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pcap_trace_off_reply>(vapi_msg_pcap_trace_off_reply *msg)
{
  vapi_msg_pcap_trace_off_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pcap_trace_off_reply>(vapi_msg_pcap_trace_off_reply *msg)
{
  vapi_msg_pcap_trace_off_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pcap_trace_off_reply>()
{
  return ::vapi_msg_id_pcap_trace_off_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pcap_trace_off_reply>>()
{
  return ::vapi_msg_id_pcap_trace_off_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pcap_trace_off_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pcap_trace_off_reply>(vapi_msg_id_pcap_trace_off_reply);
}

template class Msg<vapi_msg_pcap_trace_off_reply>;

using Pcap_trace_off_reply = Msg<vapi_msg_pcap_trace_off_reply>;
}
#endif
