#ifndef __included_hpp_mpls_api_json
#define __included_hpp_mpls_api_json

#include <vapi/vapi.hpp>
#include <vapi/mpls.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_mpls_ip_bind_unbind>(vapi_msg_mpls_ip_bind_unbind *msg)
{
  vapi_msg_mpls_ip_bind_unbind_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_ip_bind_unbind>(vapi_msg_mpls_ip_bind_unbind *msg)
{
  vapi_msg_mpls_ip_bind_unbind_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_ip_bind_unbind>()
{
  return ::vapi_msg_id_mpls_ip_bind_unbind; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_ip_bind_unbind>>()
{
  return ::vapi_msg_id_mpls_ip_bind_unbind; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_ip_bind_unbind()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_ip_bind_unbind>(vapi_msg_id_mpls_ip_bind_unbind);
}

template <> inline vapi_msg_mpls_ip_bind_unbind* vapi_alloc<vapi_msg_mpls_ip_bind_unbind>(Connection &con)
{
  vapi_msg_mpls_ip_bind_unbind* result = vapi_alloc_mpls_ip_bind_unbind(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_ip_bind_unbind>;

template class Request<vapi_msg_mpls_ip_bind_unbind, vapi_msg_mpls_ip_bind_unbind_reply>;

using Mpls_ip_bind_unbind = Request<vapi_msg_mpls_ip_bind_unbind, vapi_msg_mpls_ip_bind_unbind_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_ip_bind_unbind_reply>(vapi_msg_mpls_ip_bind_unbind_reply *msg)
{
  vapi_msg_mpls_ip_bind_unbind_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_ip_bind_unbind_reply>(vapi_msg_mpls_ip_bind_unbind_reply *msg)
{
  vapi_msg_mpls_ip_bind_unbind_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_ip_bind_unbind_reply>()
{
  return ::vapi_msg_id_mpls_ip_bind_unbind_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_ip_bind_unbind_reply>>()
{
  return ::vapi_msg_id_mpls_ip_bind_unbind_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_ip_bind_unbind_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_ip_bind_unbind_reply>(vapi_msg_id_mpls_ip_bind_unbind_reply);
}

template class Msg<vapi_msg_mpls_ip_bind_unbind_reply>;

using Mpls_ip_bind_unbind_reply = Msg<vapi_msg_mpls_ip_bind_unbind_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_tunnel_add_del>(vapi_msg_mpls_tunnel_add_del *msg)
{
  vapi_msg_mpls_tunnel_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_tunnel_add_del>(vapi_msg_mpls_tunnel_add_del *msg)
{
  vapi_msg_mpls_tunnel_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_tunnel_add_del>()
{
  return ::vapi_msg_id_mpls_tunnel_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_tunnel_add_del>>()
{
  return ::vapi_msg_id_mpls_tunnel_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_tunnel_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_tunnel_add_del>(vapi_msg_id_mpls_tunnel_add_del);
}

template <> inline vapi_msg_mpls_tunnel_add_del* vapi_alloc<vapi_msg_mpls_tunnel_add_del, size_t>(Connection &con, size_t mt_tunnel_mt_paths_array_size)
{
  vapi_msg_mpls_tunnel_add_del* result = vapi_alloc_mpls_tunnel_add_del(con.vapi_ctx, mt_tunnel_mt_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_tunnel_add_del>;

template class Request<vapi_msg_mpls_tunnel_add_del, vapi_msg_mpls_tunnel_add_del_reply, size_t>;

using Mpls_tunnel_add_del = Request<vapi_msg_mpls_tunnel_add_del, vapi_msg_mpls_tunnel_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_tunnel_add_del_reply>(vapi_msg_mpls_tunnel_add_del_reply *msg)
{
  vapi_msg_mpls_tunnel_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_tunnel_add_del_reply>(vapi_msg_mpls_tunnel_add_del_reply *msg)
{
  vapi_msg_mpls_tunnel_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_tunnel_add_del_reply>()
{
  return ::vapi_msg_id_mpls_tunnel_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_tunnel_add_del_reply>>()
{
  return ::vapi_msg_id_mpls_tunnel_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_tunnel_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_tunnel_add_del_reply>(vapi_msg_id_mpls_tunnel_add_del_reply);
}

template class Msg<vapi_msg_mpls_tunnel_add_del_reply>;

using Mpls_tunnel_add_del_reply = Msg<vapi_msg_mpls_tunnel_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_tunnel_dump>(vapi_msg_mpls_tunnel_dump *msg)
{
  vapi_msg_mpls_tunnel_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_tunnel_dump>(vapi_msg_mpls_tunnel_dump *msg)
{
  vapi_msg_mpls_tunnel_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_tunnel_dump>()
{
  return ::vapi_msg_id_mpls_tunnel_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_tunnel_dump>>()
{
  return ::vapi_msg_id_mpls_tunnel_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_tunnel_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_tunnel_dump>(vapi_msg_id_mpls_tunnel_dump);
}

template <> inline vapi_msg_mpls_tunnel_dump* vapi_alloc<vapi_msg_mpls_tunnel_dump>(Connection &con)
{
  vapi_msg_mpls_tunnel_dump* result = vapi_alloc_mpls_tunnel_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_tunnel_dump>;

template class Dump<vapi_msg_mpls_tunnel_dump, vapi_msg_mpls_tunnel_details>;

using Mpls_tunnel_dump = Dump<vapi_msg_mpls_tunnel_dump, vapi_msg_mpls_tunnel_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_tunnel_details>(vapi_msg_mpls_tunnel_details *msg)
{
  vapi_msg_mpls_tunnel_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_tunnel_details>(vapi_msg_mpls_tunnel_details *msg)
{
  vapi_msg_mpls_tunnel_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_tunnel_details>()
{
  return ::vapi_msg_id_mpls_tunnel_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_tunnel_details>>()
{
  return ::vapi_msg_id_mpls_tunnel_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_tunnel_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_tunnel_details>(vapi_msg_id_mpls_tunnel_details);
}

template class Msg<vapi_msg_mpls_tunnel_details>;

using Mpls_tunnel_details = Msg<vapi_msg_mpls_tunnel_details>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_interface_dump>(vapi_msg_mpls_interface_dump *msg)
{
  vapi_msg_mpls_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_interface_dump>(vapi_msg_mpls_interface_dump *msg)
{
  vapi_msg_mpls_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_interface_dump>()
{
  return ::vapi_msg_id_mpls_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_interface_dump>>()
{
  return ::vapi_msg_id_mpls_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_interface_dump>(vapi_msg_id_mpls_interface_dump);
}

template <> inline vapi_msg_mpls_interface_dump* vapi_alloc<vapi_msg_mpls_interface_dump>(Connection &con)
{
  vapi_msg_mpls_interface_dump* result = vapi_alloc_mpls_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_interface_dump>;

template class Dump<vapi_msg_mpls_interface_dump, vapi_msg_mpls_interface_details>;

using Mpls_interface_dump = Dump<vapi_msg_mpls_interface_dump, vapi_msg_mpls_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_interface_details>(vapi_msg_mpls_interface_details *msg)
{
  vapi_msg_mpls_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_interface_details>(vapi_msg_mpls_interface_details *msg)
{
  vapi_msg_mpls_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_interface_details>()
{
  return ::vapi_msg_id_mpls_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_interface_details>>()
{
  return ::vapi_msg_id_mpls_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_interface_details>(vapi_msg_id_mpls_interface_details);
}

template class Msg<vapi_msg_mpls_interface_details>;

using Mpls_interface_details = Msg<vapi_msg_mpls_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_table_add_del>(vapi_msg_mpls_table_add_del *msg)
{
  vapi_msg_mpls_table_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_table_add_del>(vapi_msg_mpls_table_add_del *msg)
{
  vapi_msg_mpls_table_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_table_add_del>()
{
  return ::vapi_msg_id_mpls_table_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_table_add_del>>()
{
  return ::vapi_msg_id_mpls_table_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_table_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_table_add_del>(vapi_msg_id_mpls_table_add_del);
}

template <> inline vapi_msg_mpls_table_add_del* vapi_alloc<vapi_msg_mpls_table_add_del>(Connection &con)
{
  vapi_msg_mpls_table_add_del* result = vapi_alloc_mpls_table_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_table_add_del>;

template class Request<vapi_msg_mpls_table_add_del, vapi_msg_mpls_table_add_del_reply>;

using Mpls_table_add_del = Request<vapi_msg_mpls_table_add_del, vapi_msg_mpls_table_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_table_add_del_reply>(vapi_msg_mpls_table_add_del_reply *msg)
{
  vapi_msg_mpls_table_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_table_add_del_reply>(vapi_msg_mpls_table_add_del_reply *msg)
{
  vapi_msg_mpls_table_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_table_add_del_reply>()
{
  return ::vapi_msg_id_mpls_table_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_table_add_del_reply>>()
{
  return ::vapi_msg_id_mpls_table_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_table_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_table_add_del_reply>(vapi_msg_id_mpls_table_add_del_reply);
}

template class Msg<vapi_msg_mpls_table_add_del_reply>;

using Mpls_table_add_del_reply = Msg<vapi_msg_mpls_table_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_table_dump>(vapi_msg_mpls_table_dump *msg)
{
  vapi_msg_mpls_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_table_dump>(vapi_msg_mpls_table_dump *msg)
{
  vapi_msg_mpls_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_table_dump>()
{
  return ::vapi_msg_id_mpls_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_table_dump>>()
{
  return ::vapi_msg_id_mpls_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_table_dump>(vapi_msg_id_mpls_table_dump);
}

template <> inline vapi_msg_mpls_table_dump* vapi_alloc<vapi_msg_mpls_table_dump>(Connection &con)
{
  vapi_msg_mpls_table_dump* result = vapi_alloc_mpls_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_table_dump>;

template class Dump<vapi_msg_mpls_table_dump, vapi_msg_mpls_table_details>;

using Mpls_table_dump = Dump<vapi_msg_mpls_table_dump, vapi_msg_mpls_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_table_details>(vapi_msg_mpls_table_details *msg)
{
  vapi_msg_mpls_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_table_details>(vapi_msg_mpls_table_details *msg)
{
  vapi_msg_mpls_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_table_details>()
{
  return ::vapi_msg_id_mpls_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_table_details>>()
{
  return ::vapi_msg_id_mpls_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_table_details>(vapi_msg_id_mpls_table_details);
}

template class Msg<vapi_msg_mpls_table_details>;

using Mpls_table_details = Msg<vapi_msg_mpls_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_route_add_del>(vapi_msg_mpls_route_add_del *msg)
{
  vapi_msg_mpls_route_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_route_add_del>(vapi_msg_mpls_route_add_del *msg)
{
  vapi_msg_mpls_route_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_route_add_del>()
{
  return ::vapi_msg_id_mpls_route_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_route_add_del>>()
{
  return ::vapi_msg_id_mpls_route_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_route_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_route_add_del>(vapi_msg_id_mpls_route_add_del);
}

template <> inline vapi_msg_mpls_route_add_del* vapi_alloc<vapi_msg_mpls_route_add_del, size_t>(Connection &con, size_t mr_route_mr_paths_array_size)
{
  vapi_msg_mpls_route_add_del* result = vapi_alloc_mpls_route_add_del(con.vapi_ctx, mr_route_mr_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_route_add_del>;

template class Request<vapi_msg_mpls_route_add_del, vapi_msg_mpls_route_add_del_reply, size_t>;

using Mpls_route_add_del = Request<vapi_msg_mpls_route_add_del, vapi_msg_mpls_route_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_route_add_del_reply>(vapi_msg_mpls_route_add_del_reply *msg)
{
  vapi_msg_mpls_route_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_route_add_del_reply>(vapi_msg_mpls_route_add_del_reply *msg)
{
  vapi_msg_mpls_route_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_route_add_del_reply>()
{
  return ::vapi_msg_id_mpls_route_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_route_add_del_reply>>()
{
  return ::vapi_msg_id_mpls_route_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_route_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_route_add_del_reply>(vapi_msg_id_mpls_route_add_del_reply);
}

template class Msg<vapi_msg_mpls_route_add_del_reply>;

using Mpls_route_add_del_reply = Msg<vapi_msg_mpls_route_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_mpls_route_dump>(vapi_msg_mpls_route_dump *msg)
{
  vapi_msg_mpls_route_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_route_dump>(vapi_msg_mpls_route_dump *msg)
{
  vapi_msg_mpls_route_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_route_dump>()
{
  return ::vapi_msg_id_mpls_route_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_route_dump>>()
{
  return ::vapi_msg_id_mpls_route_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_route_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_route_dump>(vapi_msg_id_mpls_route_dump);
}

template <> inline vapi_msg_mpls_route_dump* vapi_alloc<vapi_msg_mpls_route_dump>(Connection &con)
{
  vapi_msg_mpls_route_dump* result = vapi_alloc_mpls_route_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mpls_route_dump>;

template class Dump<vapi_msg_mpls_route_dump, vapi_msg_mpls_route_details>;

using Mpls_route_dump = Dump<vapi_msg_mpls_route_dump, vapi_msg_mpls_route_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mpls_route_details>(vapi_msg_mpls_route_details *msg)
{
  vapi_msg_mpls_route_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mpls_route_details>(vapi_msg_mpls_route_details *msg)
{
  vapi_msg_mpls_route_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mpls_route_details>()
{
  return ::vapi_msg_id_mpls_route_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mpls_route_details>>()
{
  return ::vapi_msg_id_mpls_route_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mpls_route_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mpls_route_details>(vapi_msg_id_mpls_route_details);
}

template class Msg<vapi_msg_mpls_route_details>;

using Mpls_route_details = Msg<vapi_msg_mpls_route_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_mpls_enable>(vapi_msg_sw_interface_set_mpls_enable *msg)
{
  vapi_msg_sw_interface_set_mpls_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_mpls_enable>(vapi_msg_sw_interface_set_mpls_enable *msg)
{
  vapi_msg_sw_interface_set_mpls_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_mpls_enable>()
{
  return ::vapi_msg_id_sw_interface_set_mpls_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_mpls_enable>>()
{
  return ::vapi_msg_id_sw_interface_set_mpls_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_mpls_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_mpls_enable>(vapi_msg_id_sw_interface_set_mpls_enable);
}

template <> inline vapi_msg_sw_interface_set_mpls_enable* vapi_alloc<vapi_msg_sw_interface_set_mpls_enable>(Connection &con)
{
  vapi_msg_sw_interface_set_mpls_enable* result = vapi_alloc_sw_interface_set_mpls_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_mpls_enable>;

template class Request<vapi_msg_sw_interface_set_mpls_enable, vapi_msg_sw_interface_set_mpls_enable_reply>;

using Sw_interface_set_mpls_enable = Request<vapi_msg_sw_interface_set_mpls_enable, vapi_msg_sw_interface_set_mpls_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_mpls_enable_reply>(vapi_msg_sw_interface_set_mpls_enable_reply *msg)
{
  vapi_msg_sw_interface_set_mpls_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_mpls_enable_reply>(vapi_msg_sw_interface_set_mpls_enable_reply *msg)
{
  vapi_msg_sw_interface_set_mpls_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_mpls_enable_reply>()
{
  return ::vapi_msg_id_sw_interface_set_mpls_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_mpls_enable_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_mpls_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_mpls_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_mpls_enable_reply>(vapi_msg_id_sw_interface_set_mpls_enable_reply);
}

template class Msg<vapi_msg_sw_interface_set_mpls_enable_reply>;

using Sw_interface_set_mpls_enable_reply = Msg<vapi_msg_sw_interface_set_mpls_enable_reply>;
}
#endif
