#ifndef __included_hpp_ioam_vxlan_gpe_api_json
#define __included_hpp_ioam_vxlan_gpe_api_json

#include <vapi/vapi.hpp>
#include <vapi/ioam_vxlan_gpe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_enable>(vapi_msg_vxlan_gpe_ioam_enable *msg)
{
  vapi_msg_vxlan_gpe_ioam_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_enable>(vapi_msg_vxlan_gpe_ioam_enable *msg)
{
  vapi_msg_vxlan_gpe_ioam_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_enable>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_enable>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_enable>(vapi_msg_id_vxlan_gpe_ioam_enable);
}

template <> inline vapi_msg_vxlan_gpe_ioam_enable* vapi_alloc<vapi_msg_vxlan_gpe_ioam_enable>(Connection &con)
{
  vapi_msg_vxlan_gpe_ioam_enable* result = vapi_alloc_vxlan_gpe_ioam_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_ioam_enable>;

template class Request<vapi_msg_vxlan_gpe_ioam_enable, vapi_msg_vxlan_gpe_ioam_enable_reply>;

using Vxlan_gpe_ioam_enable = Request<vapi_msg_vxlan_gpe_ioam_enable, vapi_msg_vxlan_gpe_ioam_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_enable_reply>(vapi_msg_vxlan_gpe_ioam_enable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_enable_reply>(vapi_msg_vxlan_gpe_ioam_enable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_enable_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_enable_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_enable_reply>(vapi_msg_id_vxlan_gpe_ioam_enable_reply);
}

template class Msg<vapi_msg_vxlan_gpe_ioam_enable_reply>;

using Vxlan_gpe_ioam_enable_reply = Msg<vapi_msg_vxlan_gpe_ioam_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_disable>(vapi_msg_vxlan_gpe_ioam_disable *msg)
{
  vapi_msg_vxlan_gpe_ioam_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_disable>(vapi_msg_vxlan_gpe_ioam_disable *msg)
{
  vapi_msg_vxlan_gpe_ioam_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_disable>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_disable>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_disable>(vapi_msg_id_vxlan_gpe_ioam_disable);
}

template <> inline vapi_msg_vxlan_gpe_ioam_disable* vapi_alloc<vapi_msg_vxlan_gpe_ioam_disable>(Connection &con)
{
  vapi_msg_vxlan_gpe_ioam_disable* result = vapi_alloc_vxlan_gpe_ioam_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_ioam_disable>;

template class Request<vapi_msg_vxlan_gpe_ioam_disable, vapi_msg_vxlan_gpe_ioam_disable_reply>;

using Vxlan_gpe_ioam_disable = Request<vapi_msg_vxlan_gpe_ioam_disable, vapi_msg_vxlan_gpe_ioam_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_disable_reply>(vapi_msg_vxlan_gpe_ioam_disable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_disable_reply>(vapi_msg_vxlan_gpe_ioam_disable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_disable_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_disable_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_disable_reply>(vapi_msg_id_vxlan_gpe_ioam_disable_reply);
}

template class Msg<vapi_msg_vxlan_gpe_ioam_disable_reply>;

using Vxlan_gpe_ioam_disable_reply = Msg<vapi_msg_vxlan_gpe_ioam_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_vni_enable>(vapi_msg_vxlan_gpe_ioam_vni_enable *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_vni_enable>(vapi_msg_vxlan_gpe_ioam_vni_enable *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_vni_enable>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_vni_enable>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_vni_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_vni_enable>(vapi_msg_id_vxlan_gpe_ioam_vni_enable);
}

template <> inline vapi_msg_vxlan_gpe_ioam_vni_enable* vapi_alloc<vapi_msg_vxlan_gpe_ioam_vni_enable>(Connection &con)
{
  vapi_msg_vxlan_gpe_ioam_vni_enable* result = vapi_alloc_vxlan_gpe_ioam_vni_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_ioam_vni_enable>;

template class Request<vapi_msg_vxlan_gpe_ioam_vni_enable, vapi_msg_vxlan_gpe_ioam_vni_enable_reply>;

using Vxlan_gpe_ioam_vni_enable = Request<vapi_msg_vxlan_gpe_ioam_vni_enable, vapi_msg_vxlan_gpe_ioam_vni_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>(vapi_msg_vxlan_gpe_ioam_vni_enable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>(vapi_msg_vxlan_gpe_ioam_vni_enable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_vni_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>(vapi_msg_id_vxlan_gpe_ioam_vni_enable_reply);
}

template class Msg<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>;

using Vxlan_gpe_ioam_vni_enable_reply = Msg<vapi_msg_vxlan_gpe_ioam_vni_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_vni_disable>(vapi_msg_vxlan_gpe_ioam_vni_disable *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_vni_disable>(vapi_msg_vxlan_gpe_ioam_vni_disable *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_vni_disable>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_vni_disable>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_vni_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_vni_disable>(vapi_msg_id_vxlan_gpe_ioam_vni_disable);
}

template <> inline vapi_msg_vxlan_gpe_ioam_vni_disable* vapi_alloc<vapi_msg_vxlan_gpe_ioam_vni_disable>(Connection &con)
{
  vapi_msg_vxlan_gpe_ioam_vni_disable* result = vapi_alloc_vxlan_gpe_ioam_vni_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_ioam_vni_disable>;

template class Request<vapi_msg_vxlan_gpe_ioam_vni_disable, vapi_msg_vxlan_gpe_ioam_vni_disable_reply>;

using Vxlan_gpe_ioam_vni_disable = Request<vapi_msg_vxlan_gpe_ioam_vni_disable, vapi_msg_vxlan_gpe_ioam_vni_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>(vapi_msg_vxlan_gpe_ioam_vni_disable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>(vapi_msg_vxlan_gpe_ioam_vni_disable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_vni_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_vni_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_vni_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>(vapi_msg_id_vxlan_gpe_ioam_vni_disable_reply);
}

template class Msg<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>;

using Vxlan_gpe_ioam_vni_disable_reply = Msg<vapi_msg_vxlan_gpe_ioam_vni_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_transit_enable>(vapi_msg_vxlan_gpe_ioam_transit_enable *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_transit_enable>(vapi_msg_vxlan_gpe_ioam_transit_enable *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_transit_enable>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_transit_enable>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_transit_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_transit_enable>(vapi_msg_id_vxlan_gpe_ioam_transit_enable);
}

template <> inline vapi_msg_vxlan_gpe_ioam_transit_enable* vapi_alloc<vapi_msg_vxlan_gpe_ioam_transit_enable>(Connection &con)
{
  vapi_msg_vxlan_gpe_ioam_transit_enable* result = vapi_alloc_vxlan_gpe_ioam_transit_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_ioam_transit_enable>;

template class Request<vapi_msg_vxlan_gpe_ioam_transit_enable, vapi_msg_vxlan_gpe_ioam_transit_enable_reply>;

using Vxlan_gpe_ioam_transit_enable = Request<vapi_msg_vxlan_gpe_ioam_transit_enable, vapi_msg_vxlan_gpe_ioam_transit_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>(vapi_msg_vxlan_gpe_ioam_transit_enable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>(vapi_msg_vxlan_gpe_ioam_transit_enable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_transit_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>(vapi_msg_id_vxlan_gpe_ioam_transit_enable_reply);
}

template class Msg<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>;

using Vxlan_gpe_ioam_transit_enable_reply = Msg<vapi_msg_vxlan_gpe_ioam_transit_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_transit_disable>(vapi_msg_vxlan_gpe_ioam_transit_disable *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_transit_disable>(vapi_msg_vxlan_gpe_ioam_transit_disable *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_transit_disable>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_transit_disable>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_transit_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_transit_disable>(vapi_msg_id_vxlan_gpe_ioam_transit_disable);
}

template <> inline vapi_msg_vxlan_gpe_ioam_transit_disable* vapi_alloc<vapi_msg_vxlan_gpe_ioam_transit_disable>(Connection &con)
{
  vapi_msg_vxlan_gpe_ioam_transit_disable* result = vapi_alloc_vxlan_gpe_ioam_transit_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_vxlan_gpe_ioam_transit_disable>;

template class Request<vapi_msg_vxlan_gpe_ioam_transit_disable, vapi_msg_vxlan_gpe_ioam_transit_disable_reply>;

using Vxlan_gpe_ioam_transit_disable = Request<vapi_msg_vxlan_gpe_ioam_transit_disable, vapi_msg_vxlan_gpe_ioam_transit_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>(vapi_msg_vxlan_gpe_ioam_transit_disable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>(vapi_msg_vxlan_gpe_ioam_transit_disable_reply *msg)
{
  vapi_msg_vxlan_gpe_ioam_transit_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>>()
{
  return ::vapi_msg_id_vxlan_gpe_ioam_transit_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_vxlan_gpe_ioam_transit_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>(vapi_msg_id_vxlan_gpe_ioam_transit_disable_reply);
}

template class Msg<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>;

using Vxlan_gpe_ioam_transit_disable_reply = Msg<vapi_msg_vxlan_gpe_ioam_transit_disable_reply>;
}
#endif
