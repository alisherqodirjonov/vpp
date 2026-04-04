#ifndef __included_hpp_gtpu_api_json
#define __included_hpp_gtpu_api_json

#include <vapi/vapi.hpp>
#include <vapi/gtpu.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_add_del_tunnel>(vapi_msg_gtpu_add_del_tunnel *msg)
{
  vapi_msg_gtpu_add_del_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_add_del_tunnel>(vapi_msg_gtpu_add_del_tunnel *msg)
{
  vapi_msg_gtpu_add_del_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_add_del_tunnel>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_add_del_tunnel>>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_add_del_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_add_del_tunnel>(vapi_msg_id_gtpu_add_del_tunnel);
}

template <> inline vapi_msg_gtpu_add_del_tunnel* vapi_alloc<vapi_msg_gtpu_add_del_tunnel>(Connection &con)
{
  vapi_msg_gtpu_add_del_tunnel* result = vapi_alloc_gtpu_add_del_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_add_del_tunnel>;

template class Request<vapi_msg_gtpu_add_del_tunnel, vapi_msg_gtpu_add_del_tunnel_reply>;

using Gtpu_add_del_tunnel = Request<vapi_msg_gtpu_add_del_tunnel, vapi_msg_gtpu_add_del_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_add_del_tunnel_reply>(vapi_msg_gtpu_add_del_tunnel_reply *msg)
{
  vapi_msg_gtpu_add_del_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_add_del_tunnel_reply>(vapi_msg_gtpu_add_del_tunnel_reply *msg)
{
  vapi_msg_gtpu_add_del_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_add_del_tunnel_reply>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_add_del_tunnel_reply>>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_add_del_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_add_del_tunnel_reply>(vapi_msg_id_gtpu_add_del_tunnel_reply);
}

template class Msg<vapi_msg_gtpu_add_del_tunnel_reply>;

using Gtpu_add_del_tunnel_reply = Msg<vapi_msg_gtpu_add_del_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_add_del_tunnel_v2>(vapi_msg_gtpu_add_del_tunnel_v2 *msg)
{
  vapi_msg_gtpu_add_del_tunnel_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_add_del_tunnel_v2>(vapi_msg_gtpu_add_del_tunnel_v2 *msg)
{
  vapi_msg_gtpu_add_del_tunnel_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_add_del_tunnel_v2>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_add_del_tunnel_v2>>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_add_del_tunnel_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_add_del_tunnel_v2>(vapi_msg_id_gtpu_add_del_tunnel_v2);
}

template <> inline vapi_msg_gtpu_add_del_tunnel_v2* vapi_alloc<vapi_msg_gtpu_add_del_tunnel_v2>(Connection &con)
{
  vapi_msg_gtpu_add_del_tunnel_v2* result = vapi_alloc_gtpu_add_del_tunnel_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_add_del_tunnel_v2>;

template class Request<vapi_msg_gtpu_add_del_tunnel_v2, vapi_msg_gtpu_add_del_tunnel_v2_reply>;

using Gtpu_add_del_tunnel_v2 = Request<vapi_msg_gtpu_add_del_tunnel_v2, vapi_msg_gtpu_add_del_tunnel_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_add_del_tunnel_v2_reply>(vapi_msg_gtpu_add_del_tunnel_v2_reply *msg)
{
  vapi_msg_gtpu_add_del_tunnel_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_add_del_tunnel_v2_reply>(vapi_msg_gtpu_add_del_tunnel_v2_reply *msg)
{
  vapi_msg_gtpu_add_del_tunnel_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_add_del_tunnel_v2_reply>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_add_del_tunnel_v2_reply>>()
{
  return ::vapi_msg_id_gtpu_add_del_tunnel_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_add_del_tunnel_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_add_del_tunnel_v2_reply>(vapi_msg_id_gtpu_add_del_tunnel_v2_reply);
}

template class Msg<vapi_msg_gtpu_add_del_tunnel_v2_reply>;

using Gtpu_add_del_tunnel_v2_reply = Msg<vapi_msg_gtpu_add_del_tunnel_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_tunnel_update_tteid>(vapi_msg_gtpu_tunnel_update_tteid *msg)
{
  vapi_msg_gtpu_tunnel_update_tteid_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_tunnel_update_tteid>(vapi_msg_gtpu_tunnel_update_tteid *msg)
{
  vapi_msg_gtpu_tunnel_update_tteid_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_tunnel_update_tteid>()
{
  return ::vapi_msg_id_gtpu_tunnel_update_tteid; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_tunnel_update_tteid>>()
{
  return ::vapi_msg_id_gtpu_tunnel_update_tteid; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_tunnel_update_tteid()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_tunnel_update_tteid>(vapi_msg_id_gtpu_tunnel_update_tteid);
}

template <> inline vapi_msg_gtpu_tunnel_update_tteid* vapi_alloc<vapi_msg_gtpu_tunnel_update_tteid>(Connection &con)
{
  vapi_msg_gtpu_tunnel_update_tteid* result = vapi_alloc_gtpu_tunnel_update_tteid(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_tunnel_update_tteid>;

template class Request<vapi_msg_gtpu_tunnel_update_tteid, vapi_msg_gtpu_tunnel_update_tteid_reply>;

using Gtpu_tunnel_update_tteid = Request<vapi_msg_gtpu_tunnel_update_tteid, vapi_msg_gtpu_tunnel_update_tteid_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_tunnel_update_tteid_reply>(vapi_msg_gtpu_tunnel_update_tteid_reply *msg)
{
  vapi_msg_gtpu_tunnel_update_tteid_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_tunnel_update_tteid_reply>(vapi_msg_gtpu_tunnel_update_tteid_reply *msg)
{
  vapi_msg_gtpu_tunnel_update_tteid_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_tunnel_update_tteid_reply>()
{
  return ::vapi_msg_id_gtpu_tunnel_update_tteid_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_tunnel_update_tteid_reply>>()
{
  return ::vapi_msg_id_gtpu_tunnel_update_tteid_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_tunnel_update_tteid_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_tunnel_update_tteid_reply>(vapi_msg_id_gtpu_tunnel_update_tteid_reply);
}

template class Msg<vapi_msg_gtpu_tunnel_update_tteid_reply>;

using Gtpu_tunnel_update_tteid_reply = Msg<vapi_msg_gtpu_tunnel_update_tteid_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_tunnel_dump>(vapi_msg_gtpu_tunnel_dump *msg)
{
  vapi_msg_gtpu_tunnel_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_tunnel_dump>(vapi_msg_gtpu_tunnel_dump *msg)
{
  vapi_msg_gtpu_tunnel_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_tunnel_dump>()
{
  return ::vapi_msg_id_gtpu_tunnel_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_tunnel_dump>>()
{
  return ::vapi_msg_id_gtpu_tunnel_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_tunnel_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_tunnel_dump>(vapi_msg_id_gtpu_tunnel_dump);
}

template <> inline vapi_msg_gtpu_tunnel_dump* vapi_alloc<vapi_msg_gtpu_tunnel_dump>(Connection &con)
{
  vapi_msg_gtpu_tunnel_dump* result = vapi_alloc_gtpu_tunnel_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_tunnel_dump>;

template class Dump<vapi_msg_gtpu_tunnel_dump, vapi_msg_gtpu_tunnel_details>;

using Gtpu_tunnel_dump = Dump<vapi_msg_gtpu_tunnel_dump, vapi_msg_gtpu_tunnel_details>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_tunnel_details>(vapi_msg_gtpu_tunnel_details *msg)
{
  vapi_msg_gtpu_tunnel_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_tunnel_details>(vapi_msg_gtpu_tunnel_details *msg)
{
  vapi_msg_gtpu_tunnel_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_tunnel_details>()
{
  return ::vapi_msg_id_gtpu_tunnel_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_tunnel_details>>()
{
  return ::vapi_msg_id_gtpu_tunnel_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_tunnel_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_tunnel_details>(vapi_msg_id_gtpu_tunnel_details);
}

template class Msg<vapi_msg_gtpu_tunnel_details>;

using Gtpu_tunnel_details = Msg<vapi_msg_gtpu_tunnel_details>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_tunnel_v2_dump>(vapi_msg_gtpu_tunnel_v2_dump *msg)
{
  vapi_msg_gtpu_tunnel_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_tunnel_v2_dump>(vapi_msg_gtpu_tunnel_v2_dump *msg)
{
  vapi_msg_gtpu_tunnel_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_tunnel_v2_dump>()
{
  return ::vapi_msg_id_gtpu_tunnel_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_tunnel_v2_dump>>()
{
  return ::vapi_msg_id_gtpu_tunnel_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_tunnel_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_tunnel_v2_dump>(vapi_msg_id_gtpu_tunnel_v2_dump);
}

template <> inline vapi_msg_gtpu_tunnel_v2_dump* vapi_alloc<vapi_msg_gtpu_tunnel_v2_dump>(Connection &con)
{
  vapi_msg_gtpu_tunnel_v2_dump* result = vapi_alloc_gtpu_tunnel_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_tunnel_v2_dump>;

template class Dump<vapi_msg_gtpu_tunnel_v2_dump, vapi_msg_gtpu_tunnel_v2_details>;

using Gtpu_tunnel_v2_dump = Dump<vapi_msg_gtpu_tunnel_v2_dump, vapi_msg_gtpu_tunnel_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_tunnel_v2_details>(vapi_msg_gtpu_tunnel_v2_details *msg)
{
  vapi_msg_gtpu_tunnel_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_tunnel_v2_details>(vapi_msg_gtpu_tunnel_v2_details *msg)
{
  vapi_msg_gtpu_tunnel_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_tunnel_v2_details>()
{
  return ::vapi_msg_id_gtpu_tunnel_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_tunnel_v2_details>>()
{
  return ::vapi_msg_id_gtpu_tunnel_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_tunnel_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_tunnel_v2_details>(vapi_msg_id_gtpu_tunnel_v2_details);
}

template class Msg<vapi_msg_gtpu_tunnel_v2_details>;

using Gtpu_tunnel_v2_details = Msg<vapi_msg_gtpu_tunnel_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_gtpu_bypass>(vapi_msg_sw_interface_set_gtpu_bypass *msg)
{
  vapi_msg_sw_interface_set_gtpu_bypass_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_gtpu_bypass>(vapi_msg_sw_interface_set_gtpu_bypass *msg)
{
  vapi_msg_sw_interface_set_gtpu_bypass_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_gtpu_bypass>()
{
  return ::vapi_msg_id_sw_interface_set_gtpu_bypass; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_gtpu_bypass>>()
{
  return ::vapi_msg_id_sw_interface_set_gtpu_bypass; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_gtpu_bypass()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_gtpu_bypass>(vapi_msg_id_sw_interface_set_gtpu_bypass);
}

template <> inline vapi_msg_sw_interface_set_gtpu_bypass* vapi_alloc<vapi_msg_sw_interface_set_gtpu_bypass>(Connection &con)
{
  vapi_msg_sw_interface_set_gtpu_bypass* result = vapi_alloc_sw_interface_set_gtpu_bypass(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_gtpu_bypass>;

template class Request<vapi_msg_sw_interface_set_gtpu_bypass, vapi_msg_sw_interface_set_gtpu_bypass_reply>;

using Sw_interface_set_gtpu_bypass = Request<vapi_msg_sw_interface_set_gtpu_bypass, vapi_msg_sw_interface_set_gtpu_bypass_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_gtpu_bypass_reply>(vapi_msg_sw_interface_set_gtpu_bypass_reply *msg)
{
  vapi_msg_sw_interface_set_gtpu_bypass_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_gtpu_bypass_reply>(vapi_msg_sw_interface_set_gtpu_bypass_reply *msg)
{
  vapi_msg_sw_interface_set_gtpu_bypass_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_gtpu_bypass_reply>()
{
  return ::vapi_msg_id_sw_interface_set_gtpu_bypass_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_gtpu_bypass_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_gtpu_bypass_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_gtpu_bypass_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_gtpu_bypass_reply>(vapi_msg_id_sw_interface_set_gtpu_bypass_reply);
}

template class Msg<vapi_msg_sw_interface_set_gtpu_bypass_reply>;

using Sw_interface_set_gtpu_bypass_reply = Msg<vapi_msg_sw_interface_set_gtpu_bypass_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_offload_rx>(vapi_msg_gtpu_offload_rx *msg)
{
  vapi_msg_gtpu_offload_rx_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_offload_rx>(vapi_msg_gtpu_offload_rx *msg)
{
  vapi_msg_gtpu_offload_rx_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_offload_rx>()
{
  return ::vapi_msg_id_gtpu_offload_rx; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_offload_rx>>()
{
  return ::vapi_msg_id_gtpu_offload_rx; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_offload_rx()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_offload_rx>(vapi_msg_id_gtpu_offload_rx);
}

template <> inline vapi_msg_gtpu_offload_rx* vapi_alloc<vapi_msg_gtpu_offload_rx>(Connection &con)
{
  vapi_msg_gtpu_offload_rx* result = vapi_alloc_gtpu_offload_rx(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_offload_rx>;

template class Request<vapi_msg_gtpu_offload_rx, vapi_msg_gtpu_offload_rx_reply>;

using Gtpu_offload_rx = Request<vapi_msg_gtpu_offload_rx, vapi_msg_gtpu_offload_rx_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_offload_rx_reply>(vapi_msg_gtpu_offload_rx_reply *msg)
{
  vapi_msg_gtpu_offload_rx_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_offload_rx_reply>(vapi_msg_gtpu_offload_rx_reply *msg)
{
  vapi_msg_gtpu_offload_rx_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_offload_rx_reply>()
{
  return ::vapi_msg_id_gtpu_offload_rx_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_offload_rx_reply>>()
{
  return ::vapi_msg_id_gtpu_offload_rx_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_offload_rx_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_offload_rx_reply>(vapi_msg_id_gtpu_offload_rx_reply);
}

template class Msg<vapi_msg_gtpu_offload_rx_reply>;

using Gtpu_offload_rx_reply = Msg<vapi_msg_gtpu_offload_rx_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_add_del_forward>(vapi_msg_gtpu_add_del_forward *msg)
{
  vapi_msg_gtpu_add_del_forward_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_add_del_forward>(vapi_msg_gtpu_add_del_forward *msg)
{
  vapi_msg_gtpu_add_del_forward_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_add_del_forward>()
{
  return ::vapi_msg_id_gtpu_add_del_forward; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_add_del_forward>>()
{
  return ::vapi_msg_id_gtpu_add_del_forward; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_add_del_forward()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_add_del_forward>(vapi_msg_id_gtpu_add_del_forward);
}

template <> inline vapi_msg_gtpu_add_del_forward* vapi_alloc<vapi_msg_gtpu_add_del_forward>(Connection &con)
{
  vapi_msg_gtpu_add_del_forward* result = vapi_alloc_gtpu_add_del_forward(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_add_del_forward>;

template class Request<vapi_msg_gtpu_add_del_forward, vapi_msg_gtpu_add_del_forward_reply>;

using Gtpu_add_del_forward = Request<vapi_msg_gtpu_add_del_forward, vapi_msg_gtpu_add_del_forward_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_add_del_forward_reply>(vapi_msg_gtpu_add_del_forward_reply *msg)
{
  vapi_msg_gtpu_add_del_forward_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_add_del_forward_reply>(vapi_msg_gtpu_add_del_forward_reply *msg)
{
  vapi_msg_gtpu_add_del_forward_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_add_del_forward_reply>()
{
  return ::vapi_msg_id_gtpu_add_del_forward_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_add_del_forward_reply>>()
{
  return ::vapi_msg_id_gtpu_add_del_forward_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_add_del_forward_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_add_del_forward_reply>(vapi_msg_id_gtpu_add_del_forward_reply);
}

template class Msg<vapi_msg_gtpu_add_del_forward_reply>;

using Gtpu_add_del_forward_reply = Msg<vapi_msg_gtpu_add_del_forward_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gtpu_get_transfer_counts>(vapi_msg_gtpu_get_transfer_counts *msg)
{
  vapi_msg_gtpu_get_transfer_counts_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_get_transfer_counts>(vapi_msg_gtpu_get_transfer_counts *msg)
{
  vapi_msg_gtpu_get_transfer_counts_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_get_transfer_counts>()
{
  return ::vapi_msg_id_gtpu_get_transfer_counts; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_get_transfer_counts>>()
{
  return ::vapi_msg_id_gtpu_get_transfer_counts; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_get_transfer_counts()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_get_transfer_counts>(vapi_msg_id_gtpu_get_transfer_counts);
}

template <> inline vapi_msg_gtpu_get_transfer_counts* vapi_alloc<vapi_msg_gtpu_get_transfer_counts>(Connection &con)
{
  vapi_msg_gtpu_get_transfer_counts* result = vapi_alloc_gtpu_get_transfer_counts(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gtpu_get_transfer_counts>;

template class Request<vapi_msg_gtpu_get_transfer_counts, vapi_msg_gtpu_get_transfer_counts_reply>;

using Gtpu_get_transfer_counts = Request<vapi_msg_gtpu_get_transfer_counts, vapi_msg_gtpu_get_transfer_counts_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gtpu_get_transfer_counts_reply>(vapi_msg_gtpu_get_transfer_counts_reply *msg)
{
  vapi_msg_gtpu_get_transfer_counts_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gtpu_get_transfer_counts_reply>(vapi_msg_gtpu_get_transfer_counts_reply *msg)
{
  vapi_msg_gtpu_get_transfer_counts_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gtpu_get_transfer_counts_reply>()
{
  return ::vapi_msg_id_gtpu_get_transfer_counts_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gtpu_get_transfer_counts_reply>>()
{
  return ::vapi_msg_id_gtpu_get_transfer_counts_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gtpu_get_transfer_counts_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gtpu_get_transfer_counts_reply>(vapi_msg_id_gtpu_get_transfer_counts_reply);
}

template class Msg<vapi_msg_gtpu_get_transfer_counts_reply>;

using Gtpu_get_transfer_counts_reply = Msg<vapi_msg_gtpu_get_transfer_counts_reply>;
}
#endif
