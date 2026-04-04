#ifndef __included_hpp_vxlan_gpe_api_json
#define __included_hpp_vxlan_gpe_api_json

#include <vapi/vapi.hpp>
#include <vapi/vxlan_gpe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_add_del_tunnel>(vapi_msg_vxlan_gpe_add_del_tunnel *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_add_del_tunnel>(vapi_msg_vxlan_gpe_add_del_tunnel *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_add_del_tunnel>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_add_del_tunnel>>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_add_del_tunnel()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_add_del_tunnel>(vapi_msg_id_vxlan_gpe_add_del_tunnel);
}

template <> inline vapi_msg_vxlan_gpe_add_del_tunnel* vapi_alloc<vapi_msg_vxlan_gpe_add_del_tunnel>(Connection &con)
{
  vapi_msg_vxlan_gpe_add_del_tunnel* result = vapi_alloc_vxlan_gpe_add_del_tunnel(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_add_del_tunnel>;

template class Request<vapi_msg_vxlan_gpe_add_del_tunnel, vapi_msg_vxlan_gpe_add_del_tunnel_reply>;

using Vxlan_gpe_add_del_tunnel = Request<vapi_msg_vxlan_gpe_add_del_tunnel, vapi_msg_vxlan_gpe_add_del_tunnel_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_add_del_tunnel_v2>(vapi_msg_vxlan_gpe_add_del_tunnel_v2 *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_add_del_tunnel_v2>(vapi_msg_vxlan_gpe_add_del_tunnel_v2 *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_add_del_tunnel_v2>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_add_del_tunnel_v2>>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_add_del_tunnel_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_add_del_tunnel_v2>(vapi_msg_id_vxlan_gpe_add_del_tunnel_v2);
}

template <> inline vapi_msg_vxlan_gpe_add_del_tunnel_v2* vapi_alloc<vapi_msg_vxlan_gpe_add_del_tunnel_v2>(Connection &con)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_v2* result = vapi_alloc_vxlan_gpe_add_del_tunnel_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_add_del_tunnel_v2>;

template class Request<vapi_msg_vxlan_gpe_add_del_tunnel_v2, vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>;

using Vxlan_gpe_add_del_tunnel_v2 = Request<vapi_msg_vxlan_gpe_add_del_tunnel_v2, vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_add_del_tunnel_reply>(vapi_msg_vxlan_gpe_add_del_tunnel_reply *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_add_del_tunnel_reply>(vapi_msg_vxlan_gpe_add_del_tunnel_reply *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_add_del_tunnel_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_add_del_tunnel_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_add_del_tunnel_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_add_del_tunnel_reply>(vapi_msg_id_vxlan_gpe_add_del_tunnel_reply);
}

template class Msg<vapi_msg_vxlan_gpe_add_del_tunnel_reply>;

using Vxlan_gpe_add_del_tunnel_reply = Msg<vapi_msg_vxlan_gpe_add_del_tunnel_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>(vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>(vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply *msg)
{
  vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_add_del_tunnel_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_add_del_tunnel_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>(vapi_msg_id_vxlan_gpe_add_del_tunnel_v2_reply);
}

template class Msg<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>;

using Vxlan_gpe_add_del_tunnel_v2_reply = Msg<vapi_msg_vxlan_gpe_add_del_tunnel_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_tunnel_dump>(vapi_msg_vxlan_gpe_tunnel_dump *msg)
{
  vapi_msg_vxlan_gpe_tunnel_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_tunnel_dump>(vapi_msg_vxlan_gpe_tunnel_dump *msg)
{
  vapi_msg_vxlan_gpe_tunnel_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_tunnel_dump>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_tunnel_dump>>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_tunnel_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_tunnel_dump>(vapi_msg_id_vxlan_gpe_tunnel_dump);
}

template <> inline vapi_msg_vxlan_gpe_tunnel_dump* vapi_alloc<vapi_msg_vxlan_gpe_tunnel_dump>(Connection &con)
{
  vapi_msg_vxlan_gpe_tunnel_dump* result = vapi_alloc_vxlan_gpe_tunnel_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_tunnel_dump>;

template class Dump<vapi_msg_vxlan_gpe_tunnel_dump, vapi_msg_vxlan_gpe_tunnel_details>;

using Vxlan_gpe_tunnel_dump = Dump<vapi_msg_vxlan_gpe_tunnel_dump, vapi_msg_vxlan_gpe_tunnel_details>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_tunnel_v2_dump>(vapi_msg_vxlan_gpe_tunnel_v2_dump *msg)
{
  vapi_msg_vxlan_gpe_tunnel_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_tunnel_v2_dump>(vapi_msg_vxlan_gpe_tunnel_v2_dump *msg)
{
  vapi_msg_vxlan_gpe_tunnel_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_tunnel_v2_dump>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_tunnel_v2_dump>>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_tunnel_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_tunnel_v2_dump>(vapi_msg_id_vxlan_gpe_tunnel_v2_dump);
}

template <> inline vapi_msg_vxlan_gpe_tunnel_v2_dump* vapi_alloc<vapi_msg_vxlan_gpe_tunnel_v2_dump>(Connection &con)
{
  vapi_msg_vxlan_gpe_tunnel_v2_dump* result = vapi_alloc_vxlan_gpe_tunnel_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_tunnel_v2_dump>;

template class Dump<vapi_msg_vxlan_gpe_tunnel_v2_dump, vapi_msg_vxlan_gpe_tunnel_v2_details>;

using Vxlan_gpe_tunnel_v2_dump = Dump<vapi_msg_vxlan_gpe_tunnel_v2_dump, vapi_msg_vxlan_gpe_tunnel_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_tunnel_details>(vapi_msg_vxlan_gpe_tunnel_details *msg)
{
  vapi_msg_vxlan_gpe_tunnel_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_tunnel_details>(vapi_msg_vxlan_gpe_tunnel_details *msg)
{
  vapi_msg_vxlan_gpe_tunnel_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_tunnel_details>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_tunnel_details>>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_tunnel_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_tunnel_details>(vapi_msg_id_vxlan_gpe_tunnel_details);
}

template class Msg<vapi_msg_vxlan_gpe_tunnel_details>;

using Vxlan_gpe_tunnel_details = Msg<vapi_msg_vxlan_gpe_tunnel_details>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_tunnel_v2_details>(vapi_msg_vxlan_gpe_tunnel_v2_details *msg)
{
  vapi_msg_vxlan_gpe_tunnel_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_tunnel_v2_details>(vapi_msg_vxlan_gpe_tunnel_v2_details *msg)
{
  vapi_msg_vxlan_gpe_tunnel_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_tunnel_v2_details>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_tunnel_v2_details>>()
{
  return ::vapi_msg_id_vxlan_gpe_tunnel_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_tunnel_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_tunnel_v2_details>(vapi_msg_id_vxlan_gpe_tunnel_v2_details);
}

template class Msg<vapi_msg_vxlan_gpe_tunnel_v2_details>;

using Vxlan_gpe_tunnel_v2_details = Msg<vapi_msg_vxlan_gpe_tunnel_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_vxlan_gpe_bypass>(vapi_msg_sw_interface_set_vxlan_gpe_bypass *msg)
{
  vapi_msg_sw_interface_set_vxlan_gpe_bypass_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_vxlan_gpe_bypass>(vapi_msg_sw_interface_set_vxlan_gpe_bypass *msg)
{
  vapi_msg_sw_interface_set_vxlan_gpe_bypass_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_vxlan_gpe_bypass>()
{
  return ::vapi_msg_id_sw_interface_set_vxlan_gpe_bypass; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_vxlan_gpe_bypass>>()
{
  return ::vapi_msg_id_sw_interface_set_vxlan_gpe_bypass; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_vxlan_gpe_bypass()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_vxlan_gpe_bypass>(vapi_msg_id_sw_interface_set_vxlan_gpe_bypass);
}

template <> inline vapi_msg_sw_interface_set_vxlan_gpe_bypass* vapi_alloc<vapi_msg_sw_interface_set_vxlan_gpe_bypass>(Connection &con)
{
  vapi_msg_sw_interface_set_vxlan_gpe_bypass* result = vapi_alloc_sw_interface_set_vxlan_gpe_bypass(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_vxlan_gpe_bypass>;

template class Request<vapi_msg_sw_interface_set_vxlan_gpe_bypass, vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>;

using Sw_interface_set_vxlan_gpe_bypass = Request<vapi_msg_sw_interface_set_vxlan_gpe_bypass, vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>(vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply *msg)
{
  vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>(vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply *msg)
{
  vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>()
{
  return ::vapi_msg_id_sw_interface_set_vxlan_gpe_bypass_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_vxlan_gpe_bypass_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_vxlan_gpe_bypass_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>(vapi_msg_id_sw_interface_set_vxlan_gpe_bypass_reply);
}

template class Msg<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>;

using Sw_interface_set_vxlan_gpe_bypass_reply = Msg<vapi_msg_sw_interface_set_vxlan_gpe_bypass_reply>;
}
#endif
