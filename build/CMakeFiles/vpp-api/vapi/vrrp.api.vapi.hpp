#ifndef __included_hpp_vrrp_api_json
#define __included_hpp_vrrp_api_json

#include <vapi/vapi.hpp>
#include <vapi/vrrp.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_add_del>(vapi_msg_vrrp_vr_add_del *msg)
{
  vapi_msg_vrrp_vr_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_add_del>(vapi_msg_vrrp_vr_add_del *msg)
{
  vapi_msg_vrrp_vr_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_add_del>()
{
  return ::vapi_msg_id_vrrp_vr_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_add_del>>()
{
  return ::vapi_msg_id_vrrp_vr_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_add_del>(vapi_msg_id_vrrp_vr_add_del);
}

template <> inline vapi_msg_vrrp_vr_add_del* vapi_alloc<vapi_msg_vrrp_vr_add_del, size_t>(Connection &con, size_t _addrs_array_size)
{
  vapi_msg_vrrp_vr_add_del* result = vapi_alloc_vrrp_vr_add_del(con.vapi_ctx, _addrs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_add_del>;

template class Request<vapi_msg_vrrp_vr_add_del, vapi_msg_vrrp_vr_add_del_reply, size_t>;

using Vrrp_vr_add_del = Request<vapi_msg_vrrp_vr_add_del, vapi_msg_vrrp_vr_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_add_del_reply>(vapi_msg_vrrp_vr_add_del_reply *msg)
{
  vapi_msg_vrrp_vr_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_add_del_reply>(vapi_msg_vrrp_vr_add_del_reply *msg)
{
  vapi_msg_vrrp_vr_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_add_del_reply>()
{
  return ::vapi_msg_id_vrrp_vr_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_add_del_reply>>()
{
  return ::vapi_msg_id_vrrp_vr_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_add_del_reply>(vapi_msg_id_vrrp_vr_add_del_reply);
}

template class Msg<vapi_msg_vrrp_vr_add_del_reply>;

using Vrrp_vr_add_del_reply = Msg<vapi_msg_vrrp_vr_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_update>(vapi_msg_vrrp_vr_update *msg)
{
  vapi_msg_vrrp_vr_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_update>(vapi_msg_vrrp_vr_update *msg)
{
  vapi_msg_vrrp_vr_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_update>()
{
  return ::vapi_msg_id_vrrp_vr_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_update>>()
{
  return ::vapi_msg_id_vrrp_vr_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_update>(vapi_msg_id_vrrp_vr_update);
}

template <> inline vapi_msg_vrrp_vr_update* vapi_alloc<vapi_msg_vrrp_vr_update, size_t>(Connection &con, size_t _addrs_array_size)
{
  vapi_msg_vrrp_vr_update* result = vapi_alloc_vrrp_vr_update(con.vapi_ctx, _addrs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_update>;

template class Request<vapi_msg_vrrp_vr_update, vapi_msg_vrrp_vr_update_reply, size_t>;

using Vrrp_vr_update = Request<vapi_msg_vrrp_vr_update, vapi_msg_vrrp_vr_update_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_update_reply>(vapi_msg_vrrp_vr_update_reply *msg)
{
  vapi_msg_vrrp_vr_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_update_reply>(vapi_msg_vrrp_vr_update_reply *msg)
{
  vapi_msg_vrrp_vr_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_update_reply>()
{
  return ::vapi_msg_id_vrrp_vr_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_update_reply>>()
{
  return ::vapi_msg_id_vrrp_vr_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_update_reply>(vapi_msg_id_vrrp_vr_update_reply);
}

template class Msg<vapi_msg_vrrp_vr_update_reply>;

using Vrrp_vr_update_reply = Msg<vapi_msg_vrrp_vr_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_del>(vapi_msg_vrrp_vr_del *msg)
{
  vapi_msg_vrrp_vr_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_del>(vapi_msg_vrrp_vr_del *msg)
{
  vapi_msg_vrrp_vr_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_del>()
{
  return ::vapi_msg_id_vrrp_vr_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_del>>()
{
  return ::vapi_msg_id_vrrp_vr_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_del>(vapi_msg_id_vrrp_vr_del);
}

template <> inline vapi_msg_vrrp_vr_del* vapi_alloc<vapi_msg_vrrp_vr_del>(Connection &con)
{
  vapi_msg_vrrp_vr_del* result = vapi_alloc_vrrp_vr_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_del>;

template class Request<vapi_msg_vrrp_vr_del, vapi_msg_vrrp_vr_del_reply>;

using Vrrp_vr_del = Request<vapi_msg_vrrp_vr_del, vapi_msg_vrrp_vr_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_del_reply>(vapi_msg_vrrp_vr_del_reply *msg)
{
  vapi_msg_vrrp_vr_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_del_reply>(vapi_msg_vrrp_vr_del_reply *msg)
{
  vapi_msg_vrrp_vr_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_del_reply>()
{
  return ::vapi_msg_id_vrrp_vr_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_del_reply>>()
{
  return ::vapi_msg_id_vrrp_vr_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_del_reply>(vapi_msg_id_vrrp_vr_del_reply);
}

template class Msg<vapi_msg_vrrp_vr_del_reply>;

using Vrrp_vr_del_reply = Msg<vapi_msg_vrrp_vr_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_dump>(vapi_msg_vrrp_vr_dump *msg)
{
  vapi_msg_vrrp_vr_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_dump>(vapi_msg_vrrp_vr_dump *msg)
{
  vapi_msg_vrrp_vr_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_dump>()
{
  return ::vapi_msg_id_vrrp_vr_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_dump>>()
{
  return ::vapi_msg_id_vrrp_vr_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_dump>(vapi_msg_id_vrrp_vr_dump);
}

template <> inline vapi_msg_vrrp_vr_dump* vapi_alloc<vapi_msg_vrrp_vr_dump>(Connection &con)
{
  vapi_msg_vrrp_vr_dump* result = vapi_alloc_vrrp_vr_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_dump>;

template class Dump<vapi_msg_vrrp_vr_dump, vapi_msg_vrrp_vr_details>;

using Vrrp_vr_dump = Dump<vapi_msg_vrrp_vr_dump, vapi_msg_vrrp_vr_details>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_details>(vapi_msg_vrrp_vr_details *msg)
{
  vapi_msg_vrrp_vr_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_details>(vapi_msg_vrrp_vr_details *msg)
{
  vapi_msg_vrrp_vr_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_details>()
{
  return ::vapi_msg_id_vrrp_vr_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_details>>()
{
  return ::vapi_msg_id_vrrp_vr_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_details>(vapi_msg_id_vrrp_vr_details);
}

template class Msg<vapi_msg_vrrp_vr_details>;

using Vrrp_vr_details = Msg<vapi_msg_vrrp_vr_details>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_start_stop>(vapi_msg_vrrp_vr_start_stop *msg)
{
  vapi_msg_vrrp_vr_start_stop_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_start_stop>(vapi_msg_vrrp_vr_start_stop *msg)
{
  vapi_msg_vrrp_vr_start_stop_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_start_stop>()
{
  return ::vapi_msg_id_vrrp_vr_start_stop; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_start_stop>>()
{
  return ::vapi_msg_id_vrrp_vr_start_stop; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_start_stop()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_start_stop>(vapi_msg_id_vrrp_vr_start_stop);
}

template <> inline vapi_msg_vrrp_vr_start_stop* vapi_alloc<vapi_msg_vrrp_vr_start_stop>(Connection &con)
{
  vapi_msg_vrrp_vr_start_stop* result = vapi_alloc_vrrp_vr_start_stop(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_start_stop>;

template class Request<vapi_msg_vrrp_vr_start_stop, vapi_msg_vrrp_vr_start_stop_reply>;

using Vrrp_vr_start_stop = Request<vapi_msg_vrrp_vr_start_stop, vapi_msg_vrrp_vr_start_stop_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_start_stop_reply>(vapi_msg_vrrp_vr_start_stop_reply *msg)
{
  vapi_msg_vrrp_vr_start_stop_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_start_stop_reply>(vapi_msg_vrrp_vr_start_stop_reply *msg)
{
  vapi_msg_vrrp_vr_start_stop_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_start_stop_reply>()
{
  return ::vapi_msg_id_vrrp_vr_start_stop_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_start_stop_reply>>()
{
  return ::vapi_msg_id_vrrp_vr_start_stop_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_start_stop_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_start_stop_reply>(vapi_msg_id_vrrp_vr_start_stop_reply);
}

template class Msg<vapi_msg_vrrp_vr_start_stop_reply>;

using Vrrp_vr_start_stop_reply = Msg<vapi_msg_vrrp_vr_start_stop_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_set_peers>(vapi_msg_vrrp_vr_set_peers *msg)
{
  vapi_msg_vrrp_vr_set_peers_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_set_peers>(vapi_msg_vrrp_vr_set_peers *msg)
{
  vapi_msg_vrrp_vr_set_peers_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_set_peers>()
{
  return ::vapi_msg_id_vrrp_vr_set_peers; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_set_peers>>()
{
  return ::vapi_msg_id_vrrp_vr_set_peers; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_set_peers()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_set_peers>(vapi_msg_id_vrrp_vr_set_peers);
}

template <> inline vapi_msg_vrrp_vr_set_peers* vapi_alloc<vapi_msg_vrrp_vr_set_peers, size_t>(Connection &con, size_t _addrs_array_size)
{
  vapi_msg_vrrp_vr_set_peers* result = vapi_alloc_vrrp_vr_set_peers(con.vapi_ctx, _addrs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_set_peers>;

template class Request<vapi_msg_vrrp_vr_set_peers, vapi_msg_vrrp_vr_set_peers_reply, size_t>;

using Vrrp_vr_set_peers = Request<vapi_msg_vrrp_vr_set_peers, vapi_msg_vrrp_vr_set_peers_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_set_peers_reply>(vapi_msg_vrrp_vr_set_peers_reply *msg)
{
  vapi_msg_vrrp_vr_set_peers_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_set_peers_reply>(vapi_msg_vrrp_vr_set_peers_reply *msg)
{
  vapi_msg_vrrp_vr_set_peers_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_set_peers_reply>()
{
  return ::vapi_msg_id_vrrp_vr_set_peers_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_set_peers_reply>>()
{
  return ::vapi_msg_id_vrrp_vr_set_peers_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_set_peers_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_set_peers_reply>(vapi_msg_id_vrrp_vr_set_peers_reply);
}

template class Msg<vapi_msg_vrrp_vr_set_peers_reply>;

using Vrrp_vr_set_peers_reply = Msg<vapi_msg_vrrp_vr_set_peers_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_peer_dump>(vapi_msg_vrrp_vr_peer_dump *msg)
{
  vapi_msg_vrrp_vr_peer_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_peer_dump>(vapi_msg_vrrp_vr_peer_dump *msg)
{
  vapi_msg_vrrp_vr_peer_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_peer_dump>()
{
  return ::vapi_msg_id_vrrp_vr_peer_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_peer_dump>>()
{
  return ::vapi_msg_id_vrrp_vr_peer_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_peer_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_peer_dump>(vapi_msg_id_vrrp_vr_peer_dump);
}

template <> inline vapi_msg_vrrp_vr_peer_dump* vapi_alloc<vapi_msg_vrrp_vr_peer_dump>(Connection &con)
{
  vapi_msg_vrrp_vr_peer_dump* result = vapi_alloc_vrrp_vr_peer_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_peer_dump>;

template class Dump<vapi_msg_vrrp_vr_peer_dump, vapi_msg_vrrp_vr_peer_details>;

using Vrrp_vr_peer_dump = Dump<vapi_msg_vrrp_vr_peer_dump, vapi_msg_vrrp_vr_peer_details>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_peer_details>(vapi_msg_vrrp_vr_peer_details *msg)
{
  vapi_msg_vrrp_vr_peer_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_peer_details>(vapi_msg_vrrp_vr_peer_details *msg)
{
  vapi_msg_vrrp_vr_peer_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_peer_details>()
{
  return ::vapi_msg_id_vrrp_vr_peer_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_peer_details>>()
{
  return ::vapi_msg_id_vrrp_vr_peer_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_peer_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_peer_details>(vapi_msg_id_vrrp_vr_peer_details);
}

template class Msg<vapi_msg_vrrp_vr_peer_details>;

using Vrrp_vr_peer_details = Msg<vapi_msg_vrrp_vr_peer_details>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_track_if_add_del>(vapi_msg_vrrp_vr_track_if_add_del *msg)
{
  vapi_msg_vrrp_vr_track_if_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_track_if_add_del>(vapi_msg_vrrp_vr_track_if_add_del *msg)
{
  vapi_msg_vrrp_vr_track_if_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_track_if_add_del>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_track_if_add_del>>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_track_if_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_track_if_add_del>(vapi_msg_id_vrrp_vr_track_if_add_del);
}

template <> inline vapi_msg_vrrp_vr_track_if_add_del* vapi_alloc<vapi_msg_vrrp_vr_track_if_add_del, size_t>(Connection &con, size_t _ifs_array_size)
{
  vapi_msg_vrrp_vr_track_if_add_del* result = vapi_alloc_vrrp_vr_track_if_add_del(con.vapi_ctx, _ifs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_track_if_add_del>;

template class Request<vapi_msg_vrrp_vr_track_if_add_del, vapi_msg_vrrp_vr_track_if_add_del_reply, size_t>;

using Vrrp_vr_track_if_add_del = Request<vapi_msg_vrrp_vr_track_if_add_del, vapi_msg_vrrp_vr_track_if_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_track_if_add_del_reply>(vapi_msg_vrrp_vr_track_if_add_del_reply *msg)
{
  vapi_msg_vrrp_vr_track_if_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_track_if_add_del_reply>(vapi_msg_vrrp_vr_track_if_add_del_reply *msg)
{
  vapi_msg_vrrp_vr_track_if_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_track_if_add_del_reply>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_track_if_add_del_reply>>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_track_if_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_track_if_add_del_reply>(vapi_msg_id_vrrp_vr_track_if_add_del_reply);
}

template class Msg<vapi_msg_vrrp_vr_track_if_add_del_reply>;

using Vrrp_vr_track_if_add_del_reply = Msg<vapi_msg_vrrp_vr_track_if_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_track_if_dump>(vapi_msg_vrrp_vr_track_if_dump *msg)
{
  vapi_msg_vrrp_vr_track_if_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_track_if_dump>(vapi_msg_vrrp_vr_track_if_dump *msg)
{
  vapi_msg_vrrp_vr_track_if_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_track_if_dump>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_track_if_dump>>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_track_if_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_track_if_dump>(vapi_msg_id_vrrp_vr_track_if_dump);
}

template <> inline vapi_msg_vrrp_vr_track_if_dump* vapi_alloc<vapi_msg_vrrp_vr_track_if_dump>(Connection &con)
{
  vapi_msg_vrrp_vr_track_if_dump* result = vapi_alloc_vrrp_vr_track_if_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vrrp_vr_track_if_dump>;

template class Dump<vapi_msg_vrrp_vr_track_if_dump, vapi_msg_vrrp_vr_track_if_details>;

using Vrrp_vr_track_if_dump = Dump<vapi_msg_vrrp_vr_track_if_dump, vapi_msg_vrrp_vr_track_if_details>;

template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_track_if_details>(vapi_msg_vrrp_vr_track_if_details *msg)
{
  vapi_msg_vrrp_vr_track_if_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_track_if_details>(vapi_msg_vrrp_vr_track_if_details *msg)
{
  vapi_msg_vrrp_vr_track_if_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_track_if_details>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_track_if_details>>()
{
  return ::vapi_msg_id_vrrp_vr_track_if_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_track_if_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_track_if_details>(vapi_msg_id_vrrp_vr_track_if_details);
}

template class Msg<vapi_msg_vrrp_vr_track_if_details>;

using Vrrp_vr_track_if_details = Msg<vapi_msg_vrrp_vr_track_if_details>;
template <> inline void vapi_swap_to_be<vapi_msg_vrrp_vr_event>(vapi_msg_vrrp_vr_event *msg)
{
  vapi_msg_vrrp_vr_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vrrp_vr_event>(vapi_msg_vrrp_vr_event *msg)
{
  vapi_msg_vrrp_vr_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vrrp_vr_event>()
{
  return ::vapi_msg_id_vrrp_vr_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vrrp_vr_event>>()
{
  return ::vapi_msg_id_vrrp_vr_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vrrp_vr_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vrrp_vr_event>(vapi_msg_id_vrrp_vr_event);
}

template class Msg<vapi_msg_vrrp_vr_event>;

using Vrrp_vr_event = Msg<vapi_msg_vrrp_vr_event>;
template <> inline void vapi_swap_to_be<vapi_msg_want_vrrp_vr_events>(vapi_msg_want_vrrp_vr_events *msg)
{
  vapi_msg_want_vrrp_vr_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_vrrp_vr_events>(vapi_msg_want_vrrp_vr_events *msg)
{
  vapi_msg_want_vrrp_vr_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_vrrp_vr_events>()
{
  return ::vapi_msg_id_want_vrrp_vr_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_vrrp_vr_events>>()
{
  return ::vapi_msg_id_want_vrrp_vr_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_vrrp_vr_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_vrrp_vr_events>(vapi_msg_id_want_vrrp_vr_events);
}

template <> inline vapi_msg_want_vrrp_vr_events* vapi_alloc<vapi_msg_want_vrrp_vr_events>(Connection &con)
{
  vapi_msg_want_vrrp_vr_events* result = vapi_alloc_want_vrrp_vr_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_vrrp_vr_events>;

template class Request<vapi_msg_want_vrrp_vr_events, vapi_msg_want_vrrp_vr_events_reply>;

using Want_vrrp_vr_events = Request<vapi_msg_want_vrrp_vr_events, vapi_msg_want_vrrp_vr_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_vrrp_vr_events_reply>(vapi_msg_want_vrrp_vr_events_reply *msg)
{
  vapi_msg_want_vrrp_vr_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_vrrp_vr_events_reply>(vapi_msg_want_vrrp_vr_events_reply *msg)
{
  vapi_msg_want_vrrp_vr_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_vrrp_vr_events_reply>()
{
  return ::vapi_msg_id_want_vrrp_vr_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_vrrp_vr_events_reply>>()
{
  return ::vapi_msg_id_want_vrrp_vr_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_vrrp_vr_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_vrrp_vr_events_reply>(vapi_msg_id_want_vrrp_vr_events_reply);
}

template class Msg<vapi_msg_want_vrrp_vr_events_reply>;

using Want_vrrp_vr_events_reply = Msg<vapi_msg_want_vrrp_vr_events_reply>;
}
#endif
