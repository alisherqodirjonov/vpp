#ifndef __included_hpp_lb_api_json
#define __included_hpp_lb_api_json

#include <vapi/vapi.hpp>
#include <vapi/lb.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_lb_conf>(vapi_msg_lb_conf *msg)
{
  vapi_msg_lb_conf_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_conf>(vapi_msg_lb_conf *msg)
{
  vapi_msg_lb_conf_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_conf>()
{
  return ::vapi_msg_id_lb_conf; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_conf>>()
{
  return ::vapi_msg_id_lb_conf; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_conf()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_conf>(vapi_msg_id_lb_conf);
}

template <> inline vapi_msg_lb_conf* vapi_alloc<vapi_msg_lb_conf>(Connection &con)
{
  vapi_msg_lb_conf* result = vapi_alloc_lb_conf(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_conf>;

template class Request<vapi_msg_lb_conf, vapi_msg_lb_conf_reply>;

using Lb_conf = Request<vapi_msg_lb_conf, vapi_msg_lb_conf_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_conf_reply>(vapi_msg_lb_conf_reply *msg)
{
  vapi_msg_lb_conf_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_conf_reply>(vapi_msg_lb_conf_reply *msg)
{
  vapi_msg_lb_conf_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_conf_reply>()
{
  return ::vapi_msg_id_lb_conf_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_conf_reply>>()
{
  return ::vapi_msg_id_lb_conf_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_conf_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_conf_reply>(vapi_msg_id_lb_conf_reply);
}

template class Msg<vapi_msg_lb_conf_reply>;

using Lb_conf_reply = Msg<vapi_msg_lb_conf_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_vip>(vapi_msg_lb_add_del_vip *msg)
{
  vapi_msg_lb_add_del_vip_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_vip>(vapi_msg_lb_add_del_vip *msg)
{
  vapi_msg_lb_add_del_vip_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_vip>()
{
  return ::vapi_msg_id_lb_add_del_vip; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_vip>>()
{
  return ::vapi_msg_id_lb_add_del_vip; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_vip()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_vip>(vapi_msg_id_lb_add_del_vip);
}

template <> inline vapi_msg_lb_add_del_vip* vapi_alloc<vapi_msg_lb_add_del_vip>(Connection &con)
{
  vapi_msg_lb_add_del_vip* result = vapi_alloc_lb_add_del_vip(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_add_del_vip>;

template class Request<vapi_msg_lb_add_del_vip, vapi_msg_lb_add_del_vip_reply>;

using Lb_add_del_vip = Request<vapi_msg_lb_add_del_vip, vapi_msg_lb_add_del_vip_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_vip_reply>(vapi_msg_lb_add_del_vip_reply *msg)
{
  vapi_msg_lb_add_del_vip_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_vip_reply>(vapi_msg_lb_add_del_vip_reply *msg)
{
  vapi_msg_lb_add_del_vip_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_vip_reply>()
{
  return ::vapi_msg_id_lb_add_del_vip_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_vip_reply>>()
{
  return ::vapi_msg_id_lb_add_del_vip_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_vip_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_vip_reply>(vapi_msg_id_lb_add_del_vip_reply);
}

template class Msg<vapi_msg_lb_add_del_vip_reply>;

using Lb_add_del_vip_reply = Msg<vapi_msg_lb_add_del_vip_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_vip_v2>(vapi_msg_lb_add_del_vip_v2 *msg)
{
  vapi_msg_lb_add_del_vip_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_vip_v2>(vapi_msg_lb_add_del_vip_v2 *msg)
{
  vapi_msg_lb_add_del_vip_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_vip_v2>()
{
  return ::vapi_msg_id_lb_add_del_vip_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_vip_v2>>()
{
  return ::vapi_msg_id_lb_add_del_vip_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_vip_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_vip_v2>(vapi_msg_id_lb_add_del_vip_v2);
}

template <> inline vapi_msg_lb_add_del_vip_v2* vapi_alloc<vapi_msg_lb_add_del_vip_v2>(Connection &con)
{
  vapi_msg_lb_add_del_vip_v2* result = vapi_alloc_lb_add_del_vip_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_add_del_vip_v2>;

template class Request<vapi_msg_lb_add_del_vip_v2, vapi_msg_lb_add_del_vip_v2_reply>;

using Lb_add_del_vip_v2 = Request<vapi_msg_lb_add_del_vip_v2, vapi_msg_lb_add_del_vip_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_vip_v2_reply>(vapi_msg_lb_add_del_vip_v2_reply *msg)
{
  vapi_msg_lb_add_del_vip_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_vip_v2_reply>(vapi_msg_lb_add_del_vip_v2_reply *msg)
{
  vapi_msg_lb_add_del_vip_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_vip_v2_reply>()
{
  return ::vapi_msg_id_lb_add_del_vip_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_vip_v2_reply>>()
{
  return ::vapi_msg_id_lb_add_del_vip_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_vip_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_vip_v2_reply>(vapi_msg_id_lb_add_del_vip_v2_reply);
}

template class Msg<vapi_msg_lb_add_del_vip_v2_reply>;

using Lb_add_del_vip_v2_reply = Msg<vapi_msg_lb_add_del_vip_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_as>(vapi_msg_lb_add_del_as *msg)
{
  vapi_msg_lb_add_del_as_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_as>(vapi_msg_lb_add_del_as *msg)
{
  vapi_msg_lb_add_del_as_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_as>()
{
  return ::vapi_msg_id_lb_add_del_as; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_as>>()
{
  return ::vapi_msg_id_lb_add_del_as; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_as()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_as>(vapi_msg_id_lb_add_del_as);
}

template <> inline vapi_msg_lb_add_del_as* vapi_alloc<vapi_msg_lb_add_del_as>(Connection &con)
{
  vapi_msg_lb_add_del_as* result = vapi_alloc_lb_add_del_as(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_add_del_as>;

template class Request<vapi_msg_lb_add_del_as, vapi_msg_lb_add_del_as_reply>;

using Lb_add_del_as = Request<vapi_msg_lb_add_del_as, vapi_msg_lb_add_del_as_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_as_reply>(vapi_msg_lb_add_del_as_reply *msg)
{
  vapi_msg_lb_add_del_as_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_as_reply>(vapi_msg_lb_add_del_as_reply *msg)
{
  vapi_msg_lb_add_del_as_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_as_reply>()
{
  return ::vapi_msg_id_lb_add_del_as_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_as_reply>>()
{
  return ::vapi_msg_id_lb_add_del_as_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_as_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_as_reply>(vapi_msg_id_lb_add_del_as_reply);
}

template class Msg<vapi_msg_lb_add_del_as_reply>;

using Lb_add_del_as_reply = Msg<vapi_msg_lb_add_del_as_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_flush_vip>(vapi_msg_lb_flush_vip *msg)
{
  vapi_msg_lb_flush_vip_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_flush_vip>(vapi_msg_lb_flush_vip *msg)
{
  vapi_msg_lb_flush_vip_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_flush_vip>()
{
  return ::vapi_msg_id_lb_flush_vip; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_flush_vip>>()
{
  return ::vapi_msg_id_lb_flush_vip; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_flush_vip()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_flush_vip>(vapi_msg_id_lb_flush_vip);
}

template <> inline vapi_msg_lb_flush_vip* vapi_alloc<vapi_msg_lb_flush_vip>(Connection &con)
{
  vapi_msg_lb_flush_vip* result = vapi_alloc_lb_flush_vip(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_flush_vip>;

template class Request<vapi_msg_lb_flush_vip, vapi_msg_lb_flush_vip_reply>;

using Lb_flush_vip = Request<vapi_msg_lb_flush_vip, vapi_msg_lb_flush_vip_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_flush_vip_reply>(vapi_msg_lb_flush_vip_reply *msg)
{
  vapi_msg_lb_flush_vip_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_flush_vip_reply>(vapi_msg_lb_flush_vip_reply *msg)
{
  vapi_msg_lb_flush_vip_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_flush_vip_reply>()
{
  return ::vapi_msg_id_lb_flush_vip_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_flush_vip_reply>>()
{
  return ::vapi_msg_id_lb_flush_vip_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_flush_vip_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_flush_vip_reply>(vapi_msg_id_lb_flush_vip_reply);
}

template class Msg<vapi_msg_lb_flush_vip_reply>;

using Lb_flush_vip_reply = Msg<vapi_msg_lb_flush_vip_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_vip_dump>(vapi_msg_lb_vip_dump *msg)
{
  vapi_msg_lb_vip_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_vip_dump>(vapi_msg_lb_vip_dump *msg)
{
  vapi_msg_lb_vip_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_vip_dump>()
{
  return ::vapi_msg_id_lb_vip_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_vip_dump>>()
{
  return ::vapi_msg_id_lb_vip_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_vip_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_vip_dump>(vapi_msg_id_lb_vip_dump);
}

template <> inline vapi_msg_lb_vip_dump* vapi_alloc<vapi_msg_lb_vip_dump>(Connection &con)
{
  vapi_msg_lb_vip_dump* result = vapi_alloc_lb_vip_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_vip_dump>;

template class Dump<vapi_msg_lb_vip_dump, vapi_msg_lb_vip_details>;

using Lb_vip_dump = Dump<vapi_msg_lb_vip_dump, vapi_msg_lb_vip_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_vip_details>(vapi_msg_lb_vip_details *msg)
{
  vapi_msg_lb_vip_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_vip_details>(vapi_msg_lb_vip_details *msg)
{
  vapi_msg_lb_vip_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_vip_details>()
{
  return ::vapi_msg_id_lb_vip_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_vip_details>>()
{
  return ::vapi_msg_id_lb_vip_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_vip_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_vip_details>(vapi_msg_id_lb_vip_details);
}

template class Msg<vapi_msg_lb_vip_details>;

using Lb_vip_details = Msg<vapi_msg_lb_vip_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_as_dump>(vapi_msg_lb_as_dump *msg)
{
  vapi_msg_lb_as_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_as_dump>(vapi_msg_lb_as_dump *msg)
{
  vapi_msg_lb_as_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_as_dump>()
{
  return ::vapi_msg_id_lb_as_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_as_dump>>()
{
  return ::vapi_msg_id_lb_as_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_as_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_as_dump>(vapi_msg_id_lb_as_dump);
}

template <> inline vapi_msg_lb_as_dump* vapi_alloc<vapi_msg_lb_as_dump>(Connection &con)
{
  vapi_msg_lb_as_dump* result = vapi_alloc_lb_as_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_as_dump>;

template class Dump<vapi_msg_lb_as_dump, vapi_msg_lb_as_details>;

using Lb_as_dump = Dump<vapi_msg_lb_as_dump, vapi_msg_lb_as_details>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_as_details>(vapi_msg_lb_as_details *msg)
{
  vapi_msg_lb_as_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_as_details>(vapi_msg_lb_as_details *msg)
{
  vapi_msg_lb_as_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_as_details>()
{
  return ::vapi_msg_id_lb_as_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_as_details>>()
{
  return ::vapi_msg_id_lb_as_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_as_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_as_details>(vapi_msg_id_lb_as_details);
}

template class Msg<vapi_msg_lb_as_details>;

using Lb_as_details = Msg<vapi_msg_lb_as_details>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_intf_nat4>(vapi_msg_lb_add_del_intf_nat4 *msg)
{
  vapi_msg_lb_add_del_intf_nat4_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_intf_nat4>(vapi_msg_lb_add_del_intf_nat4 *msg)
{
  vapi_msg_lb_add_del_intf_nat4_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_intf_nat4>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat4; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_intf_nat4>>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat4; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_intf_nat4()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_intf_nat4>(vapi_msg_id_lb_add_del_intf_nat4);
}

template <> inline vapi_msg_lb_add_del_intf_nat4* vapi_alloc<vapi_msg_lb_add_del_intf_nat4>(Connection &con)
{
  vapi_msg_lb_add_del_intf_nat4* result = vapi_alloc_lb_add_del_intf_nat4(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_add_del_intf_nat4>;

template class Request<vapi_msg_lb_add_del_intf_nat4, vapi_msg_lb_add_del_intf_nat4_reply>;

using Lb_add_del_intf_nat4 = Request<vapi_msg_lb_add_del_intf_nat4, vapi_msg_lb_add_del_intf_nat4_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_intf_nat4_reply>(vapi_msg_lb_add_del_intf_nat4_reply *msg)
{
  vapi_msg_lb_add_del_intf_nat4_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_intf_nat4_reply>(vapi_msg_lb_add_del_intf_nat4_reply *msg)
{
  vapi_msg_lb_add_del_intf_nat4_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_intf_nat4_reply>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat4_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_intf_nat4_reply>>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat4_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_intf_nat4_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_intf_nat4_reply>(vapi_msg_id_lb_add_del_intf_nat4_reply);
}

template class Msg<vapi_msg_lb_add_del_intf_nat4_reply>;

using Lb_add_del_intf_nat4_reply = Msg<vapi_msg_lb_add_del_intf_nat4_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_intf_nat6>(vapi_msg_lb_add_del_intf_nat6 *msg)
{
  vapi_msg_lb_add_del_intf_nat6_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_intf_nat6>(vapi_msg_lb_add_del_intf_nat6 *msg)
{
  vapi_msg_lb_add_del_intf_nat6_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_intf_nat6>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat6; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_intf_nat6>>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat6; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_intf_nat6()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_intf_nat6>(vapi_msg_id_lb_add_del_intf_nat6);
}

template <> inline vapi_msg_lb_add_del_intf_nat6* vapi_alloc<vapi_msg_lb_add_del_intf_nat6>(Connection &con)
{
  vapi_msg_lb_add_del_intf_nat6* result = vapi_alloc_lb_add_del_intf_nat6(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_lb_add_del_intf_nat6>;

template class Request<vapi_msg_lb_add_del_intf_nat6, vapi_msg_lb_add_del_intf_nat6_reply>;

using Lb_add_del_intf_nat6 = Request<vapi_msg_lb_add_del_intf_nat6, vapi_msg_lb_add_del_intf_nat6_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_lb_add_del_intf_nat6_reply>(vapi_msg_lb_add_del_intf_nat6_reply *msg)
{
  vapi_msg_lb_add_del_intf_nat6_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_lb_add_del_intf_nat6_reply>(vapi_msg_lb_add_del_intf_nat6_reply *msg)
{
  vapi_msg_lb_add_del_intf_nat6_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_lb_add_del_intf_nat6_reply>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat6_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_lb_add_del_intf_nat6_reply>>()
{
  return ::vapi_msg_id_lb_add_del_intf_nat6_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_lb_add_del_intf_nat6_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_lb_add_del_intf_nat6_reply>(vapi_msg_id_lb_add_del_intf_nat6_reply);
}

template class Msg<vapi_msg_lb_add_del_intf_nat6_reply>;

using Lb_add_del_intf_nat6_reply = Msg<vapi_msg_lb_add_del_intf_nat6_reply>;
}
#endif
