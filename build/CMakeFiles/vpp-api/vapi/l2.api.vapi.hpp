#ifndef __included_hpp_l2_api_json
#define __included_hpp_l2_api_json

#include <vapi/vapi.hpp>
#include <vapi/l2.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_l2_xconnect_details>(vapi_msg_l2_xconnect_details *msg)
{
  vapi_msg_l2_xconnect_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_xconnect_details>(vapi_msg_l2_xconnect_details *msg)
{
  vapi_msg_l2_xconnect_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_xconnect_details>()
{
  return ::vapi_msg_id_l2_xconnect_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_xconnect_details>>()
{
  return ::vapi_msg_id_l2_xconnect_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_xconnect_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_xconnect_details>(vapi_msg_id_l2_xconnect_details);
}

template class Msg<vapi_msg_l2_xconnect_details>;

using L2_xconnect_details = Msg<vapi_msg_l2_xconnect_details>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_xconnect_dump>(vapi_msg_l2_xconnect_dump *msg)
{
  vapi_msg_l2_xconnect_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_xconnect_dump>(vapi_msg_l2_xconnect_dump *msg)
{
  vapi_msg_l2_xconnect_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_xconnect_dump>()
{
  return ::vapi_msg_id_l2_xconnect_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_xconnect_dump>>()
{
  return ::vapi_msg_id_l2_xconnect_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_xconnect_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_xconnect_dump>(vapi_msg_id_l2_xconnect_dump);
}

template <> inline vapi_msg_l2_xconnect_dump* vapi_alloc<vapi_msg_l2_xconnect_dump>(Connection &con)
{
  vapi_msg_l2_xconnect_dump* result = vapi_alloc_l2_xconnect_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_xconnect_dump>;

template class Dump<vapi_msg_l2_xconnect_dump, vapi_msg_l2_xconnect_details>;

using L2_xconnect_dump = Dump<vapi_msg_l2_xconnect_dump, vapi_msg_l2_xconnect_details>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_fib_table_details>(vapi_msg_l2_fib_table_details *msg)
{
  vapi_msg_l2_fib_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_fib_table_details>(vapi_msg_l2_fib_table_details *msg)
{
  vapi_msg_l2_fib_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_fib_table_details>()
{
  return ::vapi_msg_id_l2_fib_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_fib_table_details>>()
{
  return ::vapi_msg_id_l2_fib_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_fib_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_fib_table_details>(vapi_msg_id_l2_fib_table_details);
}

template class Msg<vapi_msg_l2_fib_table_details>;

using L2_fib_table_details = Msg<vapi_msg_l2_fib_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_fib_table_dump>(vapi_msg_l2_fib_table_dump *msg)
{
  vapi_msg_l2_fib_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_fib_table_dump>(vapi_msg_l2_fib_table_dump *msg)
{
  vapi_msg_l2_fib_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_fib_table_dump>()
{
  return ::vapi_msg_id_l2_fib_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_fib_table_dump>>()
{
  return ::vapi_msg_id_l2_fib_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_fib_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_fib_table_dump>(vapi_msg_id_l2_fib_table_dump);
}

template <> inline vapi_msg_l2_fib_table_dump* vapi_alloc<vapi_msg_l2_fib_table_dump>(Connection &con)
{
  vapi_msg_l2_fib_table_dump* result = vapi_alloc_l2_fib_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_fib_table_dump>;

template class Dump<vapi_msg_l2_fib_table_dump, vapi_msg_l2_fib_table_details>;

using L2_fib_table_dump = Dump<vapi_msg_l2_fib_table_dump, vapi_msg_l2_fib_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_fib_clear_table>(vapi_msg_l2_fib_clear_table *msg)
{
  vapi_msg_l2_fib_clear_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_fib_clear_table>(vapi_msg_l2_fib_clear_table *msg)
{
  vapi_msg_l2_fib_clear_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_fib_clear_table>()
{
  return ::vapi_msg_id_l2_fib_clear_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_fib_clear_table>>()
{
  return ::vapi_msg_id_l2_fib_clear_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_fib_clear_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_fib_clear_table>(vapi_msg_id_l2_fib_clear_table);
}

template <> inline vapi_msg_l2_fib_clear_table* vapi_alloc<vapi_msg_l2_fib_clear_table>(Connection &con)
{
  vapi_msg_l2_fib_clear_table* result = vapi_alloc_l2_fib_clear_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_fib_clear_table>;

template class Request<vapi_msg_l2_fib_clear_table, vapi_msg_l2_fib_clear_table_reply>;

using L2_fib_clear_table = Request<vapi_msg_l2_fib_clear_table, vapi_msg_l2_fib_clear_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_fib_clear_table_reply>(vapi_msg_l2_fib_clear_table_reply *msg)
{
  vapi_msg_l2_fib_clear_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_fib_clear_table_reply>(vapi_msg_l2_fib_clear_table_reply *msg)
{
  vapi_msg_l2_fib_clear_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_fib_clear_table_reply>()
{
  return ::vapi_msg_id_l2_fib_clear_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_fib_clear_table_reply>>()
{
  return ::vapi_msg_id_l2_fib_clear_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_fib_clear_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_fib_clear_table_reply>(vapi_msg_id_l2_fib_clear_table_reply);
}

template class Msg<vapi_msg_l2_fib_clear_table_reply>;

using L2_fib_clear_table_reply = Msg<vapi_msg_l2_fib_clear_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2fib_flush_all>(vapi_msg_l2fib_flush_all *msg)
{
  vapi_msg_l2fib_flush_all_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_flush_all>(vapi_msg_l2fib_flush_all *msg)
{
  vapi_msg_l2fib_flush_all_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_flush_all>()
{
  return ::vapi_msg_id_l2fib_flush_all; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_flush_all>>()
{
  return ::vapi_msg_id_l2fib_flush_all; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_flush_all()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_flush_all>(vapi_msg_id_l2fib_flush_all);
}

template <> inline vapi_msg_l2fib_flush_all* vapi_alloc<vapi_msg_l2fib_flush_all>(Connection &con)
{
  vapi_msg_l2fib_flush_all* result = vapi_alloc_l2fib_flush_all(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2fib_flush_all>;

template class Request<vapi_msg_l2fib_flush_all, vapi_msg_l2fib_flush_all_reply>;

using L2fib_flush_all = Request<vapi_msg_l2fib_flush_all, vapi_msg_l2fib_flush_all_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2fib_flush_all_reply>(vapi_msg_l2fib_flush_all_reply *msg)
{
  vapi_msg_l2fib_flush_all_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_flush_all_reply>(vapi_msg_l2fib_flush_all_reply *msg)
{
  vapi_msg_l2fib_flush_all_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_flush_all_reply>()
{
  return ::vapi_msg_id_l2fib_flush_all_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_flush_all_reply>>()
{
  return ::vapi_msg_id_l2fib_flush_all_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_flush_all_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_flush_all_reply>(vapi_msg_id_l2fib_flush_all_reply);
}

template class Msg<vapi_msg_l2fib_flush_all_reply>;

using L2fib_flush_all_reply = Msg<vapi_msg_l2fib_flush_all_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2fib_flush_bd>(vapi_msg_l2fib_flush_bd *msg)
{
  vapi_msg_l2fib_flush_bd_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_flush_bd>(vapi_msg_l2fib_flush_bd *msg)
{
  vapi_msg_l2fib_flush_bd_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_flush_bd>()
{
  return ::vapi_msg_id_l2fib_flush_bd; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_flush_bd>>()
{
  return ::vapi_msg_id_l2fib_flush_bd; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_flush_bd()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_flush_bd>(vapi_msg_id_l2fib_flush_bd);
}

template <> inline vapi_msg_l2fib_flush_bd* vapi_alloc<vapi_msg_l2fib_flush_bd>(Connection &con)
{
  vapi_msg_l2fib_flush_bd* result = vapi_alloc_l2fib_flush_bd(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2fib_flush_bd>;

template class Request<vapi_msg_l2fib_flush_bd, vapi_msg_l2fib_flush_bd_reply>;

using L2fib_flush_bd = Request<vapi_msg_l2fib_flush_bd, vapi_msg_l2fib_flush_bd_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2fib_flush_bd_reply>(vapi_msg_l2fib_flush_bd_reply *msg)
{
  vapi_msg_l2fib_flush_bd_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_flush_bd_reply>(vapi_msg_l2fib_flush_bd_reply *msg)
{
  vapi_msg_l2fib_flush_bd_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_flush_bd_reply>()
{
  return ::vapi_msg_id_l2fib_flush_bd_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_flush_bd_reply>>()
{
  return ::vapi_msg_id_l2fib_flush_bd_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_flush_bd_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_flush_bd_reply>(vapi_msg_id_l2fib_flush_bd_reply);
}

template class Msg<vapi_msg_l2fib_flush_bd_reply>;

using L2fib_flush_bd_reply = Msg<vapi_msg_l2fib_flush_bd_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2fib_flush_int>(vapi_msg_l2fib_flush_int *msg)
{
  vapi_msg_l2fib_flush_int_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_flush_int>(vapi_msg_l2fib_flush_int *msg)
{
  vapi_msg_l2fib_flush_int_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_flush_int>()
{
  return ::vapi_msg_id_l2fib_flush_int; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_flush_int>>()
{
  return ::vapi_msg_id_l2fib_flush_int; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_flush_int()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_flush_int>(vapi_msg_id_l2fib_flush_int);
}

template <> inline vapi_msg_l2fib_flush_int* vapi_alloc<vapi_msg_l2fib_flush_int>(Connection &con)
{
  vapi_msg_l2fib_flush_int* result = vapi_alloc_l2fib_flush_int(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2fib_flush_int>;

template class Request<vapi_msg_l2fib_flush_int, vapi_msg_l2fib_flush_int_reply>;

using L2fib_flush_int = Request<vapi_msg_l2fib_flush_int, vapi_msg_l2fib_flush_int_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2fib_flush_int_reply>(vapi_msg_l2fib_flush_int_reply *msg)
{
  vapi_msg_l2fib_flush_int_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_flush_int_reply>(vapi_msg_l2fib_flush_int_reply *msg)
{
  vapi_msg_l2fib_flush_int_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_flush_int_reply>()
{
  return ::vapi_msg_id_l2fib_flush_int_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_flush_int_reply>>()
{
  return ::vapi_msg_id_l2fib_flush_int_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_flush_int_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_flush_int_reply>(vapi_msg_id_l2fib_flush_int_reply);
}

template class Msg<vapi_msg_l2fib_flush_int_reply>;

using L2fib_flush_int_reply = Msg<vapi_msg_l2fib_flush_int_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2fib_add_del>(vapi_msg_l2fib_add_del *msg)
{
  vapi_msg_l2fib_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_add_del>(vapi_msg_l2fib_add_del *msg)
{
  vapi_msg_l2fib_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_add_del>()
{
  return ::vapi_msg_id_l2fib_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_add_del>>()
{
  return ::vapi_msg_id_l2fib_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_add_del>(vapi_msg_id_l2fib_add_del);
}

template <> inline vapi_msg_l2fib_add_del* vapi_alloc<vapi_msg_l2fib_add_del>(Connection &con)
{
  vapi_msg_l2fib_add_del* result = vapi_alloc_l2fib_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2fib_add_del>;

template class Request<vapi_msg_l2fib_add_del, vapi_msg_l2fib_add_del_reply>;

using L2fib_add_del = Request<vapi_msg_l2fib_add_del, vapi_msg_l2fib_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2fib_add_del_reply>(vapi_msg_l2fib_add_del_reply *msg)
{
  vapi_msg_l2fib_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_add_del_reply>(vapi_msg_l2fib_add_del_reply *msg)
{
  vapi_msg_l2fib_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_add_del_reply>()
{
  return ::vapi_msg_id_l2fib_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_add_del_reply>>()
{
  return ::vapi_msg_id_l2fib_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_add_del_reply>(vapi_msg_id_l2fib_add_del_reply);
}

template class Msg<vapi_msg_l2fib_add_del_reply>;

using L2fib_add_del_reply = Msg<vapi_msg_l2fib_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_l2_macs_events>(vapi_msg_want_l2_macs_events *msg)
{
  vapi_msg_want_l2_macs_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_l2_macs_events>(vapi_msg_want_l2_macs_events *msg)
{
  vapi_msg_want_l2_macs_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_l2_macs_events>()
{
  return ::vapi_msg_id_want_l2_macs_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_l2_macs_events>>()
{
  return ::vapi_msg_id_want_l2_macs_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_l2_macs_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_l2_macs_events>(vapi_msg_id_want_l2_macs_events);
}

template <> inline vapi_msg_want_l2_macs_events* vapi_alloc<vapi_msg_want_l2_macs_events>(Connection &con)
{
  vapi_msg_want_l2_macs_events* result = vapi_alloc_want_l2_macs_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_l2_macs_events>;

template class Request<vapi_msg_want_l2_macs_events, vapi_msg_want_l2_macs_events_reply>;

using Want_l2_macs_events = Request<vapi_msg_want_l2_macs_events, vapi_msg_want_l2_macs_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_l2_macs_events_reply>(vapi_msg_want_l2_macs_events_reply *msg)
{
  vapi_msg_want_l2_macs_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_l2_macs_events_reply>(vapi_msg_want_l2_macs_events_reply *msg)
{
  vapi_msg_want_l2_macs_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_l2_macs_events_reply>()
{
  return ::vapi_msg_id_want_l2_macs_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_l2_macs_events_reply>>()
{
  return ::vapi_msg_id_want_l2_macs_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_l2_macs_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_l2_macs_events_reply>(vapi_msg_id_want_l2_macs_events_reply);
}

template class Msg<vapi_msg_want_l2_macs_events_reply>;

using Want_l2_macs_events_reply = Msg<vapi_msg_want_l2_macs_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_l2_macs_events2>(vapi_msg_want_l2_macs_events2 *msg)
{
  vapi_msg_want_l2_macs_events2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_l2_macs_events2>(vapi_msg_want_l2_macs_events2 *msg)
{
  vapi_msg_want_l2_macs_events2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_l2_macs_events2>()
{
  return ::vapi_msg_id_want_l2_macs_events2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_l2_macs_events2>>()
{
  return ::vapi_msg_id_want_l2_macs_events2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_l2_macs_events2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_l2_macs_events2>(vapi_msg_id_want_l2_macs_events2);
}

template <> inline vapi_msg_want_l2_macs_events2* vapi_alloc<vapi_msg_want_l2_macs_events2>(Connection &con)
{
  vapi_msg_want_l2_macs_events2* result = vapi_alloc_want_l2_macs_events2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_l2_macs_events2>;

template class Request<vapi_msg_want_l2_macs_events2, vapi_msg_want_l2_macs_events2_reply>;

using Want_l2_macs_events2 = Request<vapi_msg_want_l2_macs_events2, vapi_msg_want_l2_macs_events2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_l2_macs_events2_reply>(vapi_msg_want_l2_macs_events2_reply *msg)
{
  vapi_msg_want_l2_macs_events2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_l2_macs_events2_reply>(vapi_msg_want_l2_macs_events2_reply *msg)
{
  vapi_msg_want_l2_macs_events2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_l2_macs_events2_reply>()
{
  return ::vapi_msg_id_want_l2_macs_events2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_l2_macs_events2_reply>>()
{
  return ::vapi_msg_id_want_l2_macs_events2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_l2_macs_events2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_l2_macs_events2_reply>(vapi_msg_id_want_l2_macs_events2_reply);
}

template class Msg<vapi_msg_want_l2_macs_events2_reply>;

using Want_l2_macs_events2_reply = Msg<vapi_msg_want_l2_macs_events2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2fib_set_scan_delay>(vapi_msg_l2fib_set_scan_delay *msg)
{
  vapi_msg_l2fib_set_scan_delay_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_set_scan_delay>(vapi_msg_l2fib_set_scan_delay *msg)
{
  vapi_msg_l2fib_set_scan_delay_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_set_scan_delay>()
{
  return ::vapi_msg_id_l2fib_set_scan_delay; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_set_scan_delay>>()
{
  return ::vapi_msg_id_l2fib_set_scan_delay; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_set_scan_delay()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_set_scan_delay>(vapi_msg_id_l2fib_set_scan_delay);
}

template <> inline vapi_msg_l2fib_set_scan_delay* vapi_alloc<vapi_msg_l2fib_set_scan_delay>(Connection &con)
{
  vapi_msg_l2fib_set_scan_delay* result = vapi_alloc_l2fib_set_scan_delay(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2fib_set_scan_delay>;

template class Request<vapi_msg_l2fib_set_scan_delay, vapi_msg_l2fib_set_scan_delay_reply>;

using L2fib_set_scan_delay = Request<vapi_msg_l2fib_set_scan_delay, vapi_msg_l2fib_set_scan_delay_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2fib_set_scan_delay_reply>(vapi_msg_l2fib_set_scan_delay_reply *msg)
{
  vapi_msg_l2fib_set_scan_delay_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2fib_set_scan_delay_reply>(vapi_msg_l2fib_set_scan_delay_reply *msg)
{
  vapi_msg_l2fib_set_scan_delay_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2fib_set_scan_delay_reply>()
{
  return ::vapi_msg_id_l2fib_set_scan_delay_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2fib_set_scan_delay_reply>>()
{
  return ::vapi_msg_id_l2fib_set_scan_delay_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2fib_set_scan_delay_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2fib_set_scan_delay_reply>(vapi_msg_id_l2fib_set_scan_delay_reply);
}

template class Msg<vapi_msg_l2fib_set_scan_delay_reply>;

using L2fib_set_scan_delay_reply = Msg<vapi_msg_l2fib_set_scan_delay_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_macs_event>(vapi_msg_l2_macs_event *msg)
{
  vapi_msg_l2_macs_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_macs_event>(vapi_msg_l2_macs_event *msg)
{
  vapi_msg_l2_macs_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_macs_event>()
{
  return ::vapi_msg_id_l2_macs_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_macs_event>>()
{
  return ::vapi_msg_id_l2_macs_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_macs_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_macs_event>(vapi_msg_id_l2_macs_event);
}

template class Msg<vapi_msg_l2_macs_event>;

using L2_macs_event = Msg<vapi_msg_l2_macs_event>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_flags>(vapi_msg_l2_flags *msg)
{
  vapi_msg_l2_flags_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_flags>(vapi_msg_l2_flags *msg)
{
  vapi_msg_l2_flags_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_flags>()
{
  return ::vapi_msg_id_l2_flags; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_flags>>()
{
  return ::vapi_msg_id_l2_flags; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_flags()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_flags>(vapi_msg_id_l2_flags);
}

template <> inline vapi_msg_l2_flags* vapi_alloc<vapi_msg_l2_flags>(Connection &con)
{
  vapi_msg_l2_flags* result = vapi_alloc_l2_flags(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_flags>;

template class Request<vapi_msg_l2_flags, vapi_msg_l2_flags_reply>;

using L2_flags = Request<vapi_msg_l2_flags, vapi_msg_l2_flags_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_flags_reply>(vapi_msg_l2_flags_reply *msg)
{
  vapi_msg_l2_flags_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_flags_reply>(vapi_msg_l2_flags_reply *msg)
{
  vapi_msg_l2_flags_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_flags_reply>()
{
  return ::vapi_msg_id_l2_flags_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_flags_reply>>()
{
  return ::vapi_msg_id_l2_flags_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_flags_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_flags_reply>(vapi_msg_id_l2_flags_reply);
}

template class Msg<vapi_msg_l2_flags_reply>;

using L2_flags_reply = Msg<vapi_msg_l2_flags_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_set_mac_age>(vapi_msg_bridge_domain_set_mac_age *msg)
{
  vapi_msg_bridge_domain_set_mac_age_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_set_mac_age>(vapi_msg_bridge_domain_set_mac_age *msg)
{
  vapi_msg_bridge_domain_set_mac_age_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_set_mac_age>()
{
  return ::vapi_msg_id_bridge_domain_set_mac_age; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_set_mac_age>>()
{
  return ::vapi_msg_id_bridge_domain_set_mac_age; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_set_mac_age()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_set_mac_age>(vapi_msg_id_bridge_domain_set_mac_age);
}

template <> inline vapi_msg_bridge_domain_set_mac_age* vapi_alloc<vapi_msg_bridge_domain_set_mac_age>(Connection &con)
{
  vapi_msg_bridge_domain_set_mac_age* result = vapi_alloc_bridge_domain_set_mac_age(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_domain_set_mac_age>;

template class Request<vapi_msg_bridge_domain_set_mac_age, vapi_msg_bridge_domain_set_mac_age_reply>;

using Bridge_domain_set_mac_age = Request<vapi_msg_bridge_domain_set_mac_age, vapi_msg_bridge_domain_set_mac_age_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_set_mac_age_reply>(vapi_msg_bridge_domain_set_mac_age_reply *msg)
{
  vapi_msg_bridge_domain_set_mac_age_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_set_mac_age_reply>(vapi_msg_bridge_domain_set_mac_age_reply *msg)
{
  vapi_msg_bridge_domain_set_mac_age_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_set_mac_age_reply>()
{
  return ::vapi_msg_id_bridge_domain_set_mac_age_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_set_mac_age_reply>>()
{
  return ::vapi_msg_id_bridge_domain_set_mac_age_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_set_mac_age_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_set_mac_age_reply>(vapi_msg_id_bridge_domain_set_mac_age_reply);
}

template class Msg<vapi_msg_bridge_domain_set_mac_age_reply>;

using Bridge_domain_set_mac_age_reply = Msg<vapi_msg_bridge_domain_set_mac_age_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_set_default_learn_limit>(vapi_msg_bridge_domain_set_default_learn_limit *msg)
{
  vapi_msg_bridge_domain_set_default_learn_limit_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_set_default_learn_limit>(vapi_msg_bridge_domain_set_default_learn_limit *msg)
{
  vapi_msg_bridge_domain_set_default_learn_limit_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_set_default_learn_limit>()
{
  return ::vapi_msg_id_bridge_domain_set_default_learn_limit; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_set_default_learn_limit>>()
{
  return ::vapi_msg_id_bridge_domain_set_default_learn_limit; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_set_default_learn_limit()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_set_default_learn_limit>(vapi_msg_id_bridge_domain_set_default_learn_limit);
}

template <> inline vapi_msg_bridge_domain_set_default_learn_limit* vapi_alloc<vapi_msg_bridge_domain_set_default_learn_limit>(Connection &con)
{
  vapi_msg_bridge_domain_set_default_learn_limit* result = vapi_alloc_bridge_domain_set_default_learn_limit(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_domain_set_default_learn_limit>;

template class Request<vapi_msg_bridge_domain_set_default_learn_limit, vapi_msg_bridge_domain_set_default_learn_limit_reply>;

using Bridge_domain_set_default_learn_limit = Request<vapi_msg_bridge_domain_set_default_learn_limit, vapi_msg_bridge_domain_set_default_learn_limit_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_set_default_learn_limit_reply>(vapi_msg_bridge_domain_set_default_learn_limit_reply *msg)
{
  vapi_msg_bridge_domain_set_default_learn_limit_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_set_default_learn_limit_reply>(vapi_msg_bridge_domain_set_default_learn_limit_reply *msg)
{
  vapi_msg_bridge_domain_set_default_learn_limit_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_set_default_learn_limit_reply>()
{
  return ::vapi_msg_id_bridge_domain_set_default_learn_limit_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_set_default_learn_limit_reply>>()
{
  return ::vapi_msg_id_bridge_domain_set_default_learn_limit_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_set_default_learn_limit_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_set_default_learn_limit_reply>(vapi_msg_id_bridge_domain_set_default_learn_limit_reply);
}

template class Msg<vapi_msg_bridge_domain_set_default_learn_limit_reply>;

using Bridge_domain_set_default_learn_limit_reply = Msg<vapi_msg_bridge_domain_set_default_learn_limit_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_set_learn_limit>(vapi_msg_bridge_domain_set_learn_limit *msg)
{
  vapi_msg_bridge_domain_set_learn_limit_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_set_learn_limit>(vapi_msg_bridge_domain_set_learn_limit *msg)
{
  vapi_msg_bridge_domain_set_learn_limit_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_set_learn_limit>()
{
  return ::vapi_msg_id_bridge_domain_set_learn_limit; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_set_learn_limit>>()
{
  return ::vapi_msg_id_bridge_domain_set_learn_limit; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_set_learn_limit()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_set_learn_limit>(vapi_msg_id_bridge_domain_set_learn_limit);
}

template <> inline vapi_msg_bridge_domain_set_learn_limit* vapi_alloc<vapi_msg_bridge_domain_set_learn_limit>(Connection &con)
{
  vapi_msg_bridge_domain_set_learn_limit* result = vapi_alloc_bridge_domain_set_learn_limit(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_domain_set_learn_limit>;

template class Request<vapi_msg_bridge_domain_set_learn_limit, vapi_msg_bridge_domain_set_learn_limit_reply>;

using Bridge_domain_set_learn_limit = Request<vapi_msg_bridge_domain_set_learn_limit, vapi_msg_bridge_domain_set_learn_limit_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_set_learn_limit_reply>(vapi_msg_bridge_domain_set_learn_limit_reply *msg)
{
  vapi_msg_bridge_domain_set_learn_limit_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_set_learn_limit_reply>(vapi_msg_bridge_domain_set_learn_limit_reply *msg)
{
  vapi_msg_bridge_domain_set_learn_limit_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_set_learn_limit_reply>()
{
  return ::vapi_msg_id_bridge_domain_set_learn_limit_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_set_learn_limit_reply>>()
{
  return ::vapi_msg_id_bridge_domain_set_learn_limit_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_set_learn_limit_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_set_learn_limit_reply>(vapi_msg_id_bridge_domain_set_learn_limit_reply);
}

template class Msg<vapi_msg_bridge_domain_set_learn_limit_reply>;

using Bridge_domain_set_learn_limit_reply = Msg<vapi_msg_bridge_domain_set_learn_limit_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_add_del>(vapi_msg_bridge_domain_add_del *msg)
{
  vapi_msg_bridge_domain_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_add_del>(vapi_msg_bridge_domain_add_del *msg)
{
  vapi_msg_bridge_domain_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_add_del>()
{
  return ::vapi_msg_id_bridge_domain_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_add_del>>()
{
  return ::vapi_msg_id_bridge_domain_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_add_del>(vapi_msg_id_bridge_domain_add_del);
}

template <> inline vapi_msg_bridge_domain_add_del* vapi_alloc<vapi_msg_bridge_domain_add_del>(Connection &con)
{
  vapi_msg_bridge_domain_add_del* result = vapi_alloc_bridge_domain_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_domain_add_del>;

template class Request<vapi_msg_bridge_domain_add_del, vapi_msg_bridge_domain_add_del_reply>;

using Bridge_domain_add_del = Request<vapi_msg_bridge_domain_add_del, vapi_msg_bridge_domain_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_add_del_reply>(vapi_msg_bridge_domain_add_del_reply *msg)
{
  vapi_msg_bridge_domain_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_add_del_reply>(vapi_msg_bridge_domain_add_del_reply *msg)
{
  vapi_msg_bridge_domain_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_add_del_reply>()
{
  return ::vapi_msg_id_bridge_domain_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_add_del_reply>>()
{
  return ::vapi_msg_id_bridge_domain_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_add_del_reply>(vapi_msg_id_bridge_domain_add_del_reply);
}

template class Msg<vapi_msg_bridge_domain_add_del_reply>;

using Bridge_domain_add_del_reply = Msg<vapi_msg_bridge_domain_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_add_del_v2>(vapi_msg_bridge_domain_add_del_v2 *msg)
{
  vapi_msg_bridge_domain_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_add_del_v2>(vapi_msg_bridge_domain_add_del_v2 *msg)
{
  vapi_msg_bridge_domain_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_add_del_v2>()
{
  return ::vapi_msg_id_bridge_domain_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_add_del_v2>>()
{
  return ::vapi_msg_id_bridge_domain_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_add_del_v2>(vapi_msg_id_bridge_domain_add_del_v2);
}

template <> inline vapi_msg_bridge_domain_add_del_v2* vapi_alloc<vapi_msg_bridge_domain_add_del_v2>(Connection &con)
{
  vapi_msg_bridge_domain_add_del_v2* result = vapi_alloc_bridge_domain_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_domain_add_del_v2>;

template class Request<vapi_msg_bridge_domain_add_del_v2, vapi_msg_bridge_domain_add_del_v2_reply>;

using Bridge_domain_add_del_v2 = Request<vapi_msg_bridge_domain_add_del_v2, vapi_msg_bridge_domain_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_add_del_v2_reply>(vapi_msg_bridge_domain_add_del_v2_reply *msg)
{
  vapi_msg_bridge_domain_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_add_del_v2_reply>(vapi_msg_bridge_domain_add_del_v2_reply *msg)
{
  vapi_msg_bridge_domain_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_add_del_v2_reply>()
{
  return ::vapi_msg_id_bridge_domain_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_add_del_v2_reply>>()
{
  return ::vapi_msg_id_bridge_domain_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_add_del_v2_reply>(vapi_msg_id_bridge_domain_add_del_v2_reply);
}

template class Msg<vapi_msg_bridge_domain_add_del_v2_reply>;

using Bridge_domain_add_del_v2_reply = Msg<vapi_msg_bridge_domain_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_dump>(vapi_msg_bridge_domain_dump *msg)
{
  vapi_msg_bridge_domain_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_dump>(vapi_msg_bridge_domain_dump *msg)
{
  vapi_msg_bridge_domain_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_dump>()
{
  return ::vapi_msg_id_bridge_domain_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_dump>>()
{
  return ::vapi_msg_id_bridge_domain_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_dump>(vapi_msg_id_bridge_domain_dump);
}

template <> inline vapi_msg_bridge_domain_dump* vapi_alloc<vapi_msg_bridge_domain_dump>(Connection &con)
{
  vapi_msg_bridge_domain_dump* result = vapi_alloc_bridge_domain_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_domain_dump>;

template class Dump<vapi_msg_bridge_domain_dump, vapi_msg_bridge_domain_details>;

using Bridge_domain_dump = Dump<vapi_msg_bridge_domain_dump, vapi_msg_bridge_domain_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_domain_details>(vapi_msg_bridge_domain_details *msg)
{
  vapi_msg_bridge_domain_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_domain_details>(vapi_msg_bridge_domain_details *msg)
{
  vapi_msg_bridge_domain_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_domain_details>()
{
  return ::vapi_msg_id_bridge_domain_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_domain_details>>()
{
  return ::vapi_msg_id_bridge_domain_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_domain_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_domain_details>(vapi_msg_id_bridge_domain_details);
}

template class Msg<vapi_msg_bridge_domain_details>;

using Bridge_domain_details = Msg<vapi_msg_bridge_domain_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bridge_flags>(vapi_msg_bridge_flags *msg)
{
  vapi_msg_bridge_flags_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_flags>(vapi_msg_bridge_flags *msg)
{
  vapi_msg_bridge_flags_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_flags>()
{
  return ::vapi_msg_id_bridge_flags; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_flags>>()
{
  return ::vapi_msg_id_bridge_flags; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_flags()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_flags>(vapi_msg_id_bridge_flags);
}

template <> inline vapi_msg_bridge_flags* vapi_alloc<vapi_msg_bridge_flags>(Connection &con)
{
  vapi_msg_bridge_flags* result = vapi_alloc_bridge_flags(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bridge_flags>;

template class Request<vapi_msg_bridge_flags, vapi_msg_bridge_flags_reply>;

using Bridge_flags = Request<vapi_msg_bridge_flags, vapi_msg_bridge_flags_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bridge_flags_reply>(vapi_msg_bridge_flags_reply *msg)
{
  vapi_msg_bridge_flags_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bridge_flags_reply>(vapi_msg_bridge_flags_reply *msg)
{
  vapi_msg_bridge_flags_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bridge_flags_reply>()
{
  return ::vapi_msg_id_bridge_flags_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bridge_flags_reply>>()
{
  return ::vapi_msg_id_bridge_flags_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bridge_flags_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bridge_flags_reply>(vapi_msg_id_bridge_flags_reply);
}

template class Msg<vapi_msg_bridge_flags_reply>;

using Bridge_flags_reply = Msg<vapi_msg_bridge_flags_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_interface_vlan_tag_rewrite>(vapi_msg_l2_interface_vlan_tag_rewrite *msg)
{
  vapi_msg_l2_interface_vlan_tag_rewrite_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_interface_vlan_tag_rewrite>(vapi_msg_l2_interface_vlan_tag_rewrite *msg)
{
  vapi_msg_l2_interface_vlan_tag_rewrite_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_interface_vlan_tag_rewrite>()
{
  return ::vapi_msg_id_l2_interface_vlan_tag_rewrite; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_interface_vlan_tag_rewrite>>()
{
  return ::vapi_msg_id_l2_interface_vlan_tag_rewrite; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_interface_vlan_tag_rewrite()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_interface_vlan_tag_rewrite>(vapi_msg_id_l2_interface_vlan_tag_rewrite);
}

template <> inline vapi_msg_l2_interface_vlan_tag_rewrite* vapi_alloc<vapi_msg_l2_interface_vlan_tag_rewrite>(Connection &con)
{
  vapi_msg_l2_interface_vlan_tag_rewrite* result = vapi_alloc_l2_interface_vlan_tag_rewrite(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_interface_vlan_tag_rewrite>;

template class Request<vapi_msg_l2_interface_vlan_tag_rewrite, vapi_msg_l2_interface_vlan_tag_rewrite_reply>;

using L2_interface_vlan_tag_rewrite = Request<vapi_msg_l2_interface_vlan_tag_rewrite, vapi_msg_l2_interface_vlan_tag_rewrite_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_interface_vlan_tag_rewrite_reply>(vapi_msg_l2_interface_vlan_tag_rewrite_reply *msg)
{
  vapi_msg_l2_interface_vlan_tag_rewrite_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_interface_vlan_tag_rewrite_reply>(vapi_msg_l2_interface_vlan_tag_rewrite_reply *msg)
{
  vapi_msg_l2_interface_vlan_tag_rewrite_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_interface_vlan_tag_rewrite_reply>()
{
  return ::vapi_msg_id_l2_interface_vlan_tag_rewrite_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_interface_vlan_tag_rewrite_reply>>()
{
  return ::vapi_msg_id_l2_interface_vlan_tag_rewrite_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_interface_vlan_tag_rewrite_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_interface_vlan_tag_rewrite_reply>(vapi_msg_id_l2_interface_vlan_tag_rewrite_reply);
}

template class Msg<vapi_msg_l2_interface_vlan_tag_rewrite_reply>;

using L2_interface_vlan_tag_rewrite_reply = Msg<vapi_msg_l2_interface_vlan_tag_rewrite_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_interface_pbb_tag_rewrite>(vapi_msg_l2_interface_pbb_tag_rewrite *msg)
{
  vapi_msg_l2_interface_pbb_tag_rewrite_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_interface_pbb_tag_rewrite>(vapi_msg_l2_interface_pbb_tag_rewrite *msg)
{
  vapi_msg_l2_interface_pbb_tag_rewrite_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_interface_pbb_tag_rewrite>()
{
  return ::vapi_msg_id_l2_interface_pbb_tag_rewrite; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_interface_pbb_tag_rewrite>>()
{
  return ::vapi_msg_id_l2_interface_pbb_tag_rewrite; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_interface_pbb_tag_rewrite()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_interface_pbb_tag_rewrite>(vapi_msg_id_l2_interface_pbb_tag_rewrite);
}

template <> inline vapi_msg_l2_interface_pbb_tag_rewrite* vapi_alloc<vapi_msg_l2_interface_pbb_tag_rewrite>(Connection &con)
{
  vapi_msg_l2_interface_pbb_tag_rewrite* result = vapi_alloc_l2_interface_pbb_tag_rewrite(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_interface_pbb_tag_rewrite>;

template class Request<vapi_msg_l2_interface_pbb_tag_rewrite, vapi_msg_l2_interface_pbb_tag_rewrite_reply>;

using L2_interface_pbb_tag_rewrite = Request<vapi_msg_l2_interface_pbb_tag_rewrite, vapi_msg_l2_interface_pbb_tag_rewrite_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_interface_pbb_tag_rewrite_reply>(vapi_msg_l2_interface_pbb_tag_rewrite_reply *msg)
{
  vapi_msg_l2_interface_pbb_tag_rewrite_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_interface_pbb_tag_rewrite_reply>(vapi_msg_l2_interface_pbb_tag_rewrite_reply *msg)
{
  vapi_msg_l2_interface_pbb_tag_rewrite_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_interface_pbb_tag_rewrite_reply>()
{
  return ::vapi_msg_id_l2_interface_pbb_tag_rewrite_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_interface_pbb_tag_rewrite_reply>>()
{
  return ::vapi_msg_id_l2_interface_pbb_tag_rewrite_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_interface_pbb_tag_rewrite_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_interface_pbb_tag_rewrite_reply>(vapi_msg_id_l2_interface_pbb_tag_rewrite_reply);
}

template class Msg<vapi_msg_l2_interface_pbb_tag_rewrite_reply>;

using L2_interface_pbb_tag_rewrite_reply = Msg<vapi_msg_l2_interface_pbb_tag_rewrite_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_patch_add_del>(vapi_msg_l2_patch_add_del *msg)
{
  vapi_msg_l2_patch_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_patch_add_del>(vapi_msg_l2_patch_add_del *msg)
{
  vapi_msg_l2_patch_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_patch_add_del>()
{
  return ::vapi_msg_id_l2_patch_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_patch_add_del>>()
{
  return ::vapi_msg_id_l2_patch_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_patch_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_patch_add_del>(vapi_msg_id_l2_patch_add_del);
}

template <> inline vapi_msg_l2_patch_add_del* vapi_alloc<vapi_msg_l2_patch_add_del>(Connection &con)
{
  vapi_msg_l2_patch_add_del* result = vapi_alloc_l2_patch_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_patch_add_del>;

template class Request<vapi_msg_l2_patch_add_del, vapi_msg_l2_patch_add_del_reply>;

using L2_patch_add_del = Request<vapi_msg_l2_patch_add_del, vapi_msg_l2_patch_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_patch_add_del_reply>(vapi_msg_l2_patch_add_del_reply *msg)
{
  vapi_msg_l2_patch_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_patch_add_del_reply>(vapi_msg_l2_patch_add_del_reply *msg)
{
  vapi_msg_l2_patch_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_patch_add_del_reply>()
{
  return ::vapi_msg_id_l2_patch_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_patch_add_del_reply>>()
{
  return ::vapi_msg_id_l2_patch_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_patch_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_patch_add_del_reply>(vapi_msg_id_l2_patch_add_del_reply);
}

template class Msg<vapi_msg_l2_patch_add_del_reply>;

using L2_patch_add_del_reply = Msg<vapi_msg_l2_patch_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_l2_xconnect>(vapi_msg_sw_interface_set_l2_xconnect *msg)
{
  vapi_msg_sw_interface_set_l2_xconnect_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_l2_xconnect>(vapi_msg_sw_interface_set_l2_xconnect *msg)
{
  vapi_msg_sw_interface_set_l2_xconnect_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_l2_xconnect>()
{
  return ::vapi_msg_id_sw_interface_set_l2_xconnect; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_l2_xconnect>>()
{
  return ::vapi_msg_id_sw_interface_set_l2_xconnect; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_l2_xconnect()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_l2_xconnect>(vapi_msg_id_sw_interface_set_l2_xconnect);
}

template <> inline vapi_msg_sw_interface_set_l2_xconnect* vapi_alloc<vapi_msg_sw_interface_set_l2_xconnect>(Connection &con)
{
  vapi_msg_sw_interface_set_l2_xconnect* result = vapi_alloc_sw_interface_set_l2_xconnect(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_l2_xconnect>;

template class Request<vapi_msg_sw_interface_set_l2_xconnect, vapi_msg_sw_interface_set_l2_xconnect_reply>;

using Sw_interface_set_l2_xconnect = Request<vapi_msg_sw_interface_set_l2_xconnect, vapi_msg_sw_interface_set_l2_xconnect_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_l2_xconnect_reply>(vapi_msg_sw_interface_set_l2_xconnect_reply *msg)
{
  vapi_msg_sw_interface_set_l2_xconnect_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_l2_xconnect_reply>(vapi_msg_sw_interface_set_l2_xconnect_reply *msg)
{
  vapi_msg_sw_interface_set_l2_xconnect_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_l2_xconnect_reply>()
{
  return ::vapi_msg_id_sw_interface_set_l2_xconnect_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_l2_xconnect_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_l2_xconnect_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_l2_xconnect_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_l2_xconnect_reply>(vapi_msg_id_sw_interface_set_l2_xconnect_reply);
}

template class Msg<vapi_msg_sw_interface_set_l2_xconnect_reply>;

using Sw_interface_set_l2_xconnect_reply = Msg<vapi_msg_sw_interface_set_l2_xconnect_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_l2_bridge>(vapi_msg_sw_interface_set_l2_bridge *msg)
{
  vapi_msg_sw_interface_set_l2_bridge_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_l2_bridge>(vapi_msg_sw_interface_set_l2_bridge *msg)
{
  vapi_msg_sw_interface_set_l2_bridge_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_l2_bridge>()
{
  return ::vapi_msg_id_sw_interface_set_l2_bridge; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_l2_bridge>>()
{
  return ::vapi_msg_id_sw_interface_set_l2_bridge; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_l2_bridge()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_l2_bridge>(vapi_msg_id_sw_interface_set_l2_bridge);
}

template <> inline vapi_msg_sw_interface_set_l2_bridge* vapi_alloc<vapi_msg_sw_interface_set_l2_bridge>(Connection &con)
{
  vapi_msg_sw_interface_set_l2_bridge* result = vapi_alloc_sw_interface_set_l2_bridge(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_l2_bridge>;

template class Request<vapi_msg_sw_interface_set_l2_bridge, vapi_msg_sw_interface_set_l2_bridge_reply>;

using Sw_interface_set_l2_bridge = Request<vapi_msg_sw_interface_set_l2_bridge, vapi_msg_sw_interface_set_l2_bridge_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_l2_bridge_reply>(vapi_msg_sw_interface_set_l2_bridge_reply *msg)
{
  vapi_msg_sw_interface_set_l2_bridge_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_l2_bridge_reply>(vapi_msg_sw_interface_set_l2_bridge_reply *msg)
{
  vapi_msg_sw_interface_set_l2_bridge_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_l2_bridge_reply>()
{
  return ::vapi_msg_id_sw_interface_set_l2_bridge_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_l2_bridge_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_l2_bridge_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_l2_bridge_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_l2_bridge_reply>(vapi_msg_id_sw_interface_set_l2_bridge_reply);
}

template class Msg<vapi_msg_sw_interface_set_l2_bridge_reply>;

using Sw_interface_set_l2_bridge_reply = Msg<vapi_msg_sw_interface_set_l2_bridge_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bd_ip_mac_add_del>(vapi_msg_bd_ip_mac_add_del *msg)
{
  vapi_msg_bd_ip_mac_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bd_ip_mac_add_del>(vapi_msg_bd_ip_mac_add_del *msg)
{
  vapi_msg_bd_ip_mac_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bd_ip_mac_add_del>()
{
  return ::vapi_msg_id_bd_ip_mac_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bd_ip_mac_add_del>>()
{
  return ::vapi_msg_id_bd_ip_mac_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bd_ip_mac_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bd_ip_mac_add_del>(vapi_msg_id_bd_ip_mac_add_del);
}

template <> inline vapi_msg_bd_ip_mac_add_del* vapi_alloc<vapi_msg_bd_ip_mac_add_del>(Connection &con)
{
  vapi_msg_bd_ip_mac_add_del* result = vapi_alloc_bd_ip_mac_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bd_ip_mac_add_del>;

template class Request<vapi_msg_bd_ip_mac_add_del, vapi_msg_bd_ip_mac_add_del_reply>;

using Bd_ip_mac_add_del = Request<vapi_msg_bd_ip_mac_add_del, vapi_msg_bd_ip_mac_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bd_ip_mac_add_del_reply>(vapi_msg_bd_ip_mac_add_del_reply *msg)
{
  vapi_msg_bd_ip_mac_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bd_ip_mac_add_del_reply>(vapi_msg_bd_ip_mac_add_del_reply *msg)
{
  vapi_msg_bd_ip_mac_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bd_ip_mac_add_del_reply>()
{
  return ::vapi_msg_id_bd_ip_mac_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bd_ip_mac_add_del_reply>>()
{
  return ::vapi_msg_id_bd_ip_mac_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bd_ip_mac_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bd_ip_mac_add_del_reply>(vapi_msg_id_bd_ip_mac_add_del_reply);
}

template class Msg<vapi_msg_bd_ip_mac_add_del_reply>;

using Bd_ip_mac_add_del_reply = Msg<vapi_msg_bd_ip_mac_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bd_ip_mac_flush>(vapi_msg_bd_ip_mac_flush *msg)
{
  vapi_msg_bd_ip_mac_flush_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bd_ip_mac_flush>(vapi_msg_bd_ip_mac_flush *msg)
{
  vapi_msg_bd_ip_mac_flush_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bd_ip_mac_flush>()
{
  return ::vapi_msg_id_bd_ip_mac_flush; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bd_ip_mac_flush>>()
{
  return ::vapi_msg_id_bd_ip_mac_flush; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bd_ip_mac_flush()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bd_ip_mac_flush>(vapi_msg_id_bd_ip_mac_flush);
}

template <> inline vapi_msg_bd_ip_mac_flush* vapi_alloc<vapi_msg_bd_ip_mac_flush>(Connection &con)
{
  vapi_msg_bd_ip_mac_flush* result = vapi_alloc_bd_ip_mac_flush(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bd_ip_mac_flush>;

template class Request<vapi_msg_bd_ip_mac_flush, vapi_msg_bd_ip_mac_flush_reply>;

using Bd_ip_mac_flush = Request<vapi_msg_bd_ip_mac_flush, vapi_msg_bd_ip_mac_flush_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bd_ip_mac_flush_reply>(vapi_msg_bd_ip_mac_flush_reply *msg)
{
  vapi_msg_bd_ip_mac_flush_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bd_ip_mac_flush_reply>(vapi_msg_bd_ip_mac_flush_reply *msg)
{
  vapi_msg_bd_ip_mac_flush_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bd_ip_mac_flush_reply>()
{
  return ::vapi_msg_id_bd_ip_mac_flush_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bd_ip_mac_flush_reply>>()
{
  return ::vapi_msg_id_bd_ip_mac_flush_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bd_ip_mac_flush_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bd_ip_mac_flush_reply>(vapi_msg_id_bd_ip_mac_flush_reply);
}

template class Msg<vapi_msg_bd_ip_mac_flush_reply>;

using Bd_ip_mac_flush_reply = Msg<vapi_msg_bd_ip_mac_flush_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bd_ip_mac_details>(vapi_msg_bd_ip_mac_details *msg)
{
  vapi_msg_bd_ip_mac_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bd_ip_mac_details>(vapi_msg_bd_ip_mac_details *msg)
{
  vapi_msg_bd_ip_mac_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bd_ip_mac_details>()
{
  return ::vapi_msg_id_bd_ip_mac_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bd_ip_mac_details>>()
{
  return ::vapi_msg_id_bd_ip_mac_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bd_ip_mac_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bd_ip_mac_details>(vapi_msg_id_bd_ip_mac_details);
}

template class Msg<vapi_msg_bd_ip_mac_details>;

using Bd_ip_mac_details = Msg<vapi_msg_bd_ip_mac_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bd_ip_mac_dump>(vapi_msg_bd_ip_mac_dump *msg)
{
  vapi_msg_bd_ip_mac_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bd_ip_mac_dump>(vapi_msg_bd_ip_mac_dump *msg)
{
  vapi_msg_bd_ip_mac_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bd_ip_mac_dump>()
{
  return ::vapi_msg_id_bd_ip_mac_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bd_ip_mac_dump>>()
{
  return ::vapi_msg_id_bd_ip_mac_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bd_ip_mac_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bd_ip_mac_dump>(vapi_msg_id_bd_ip_mac_dump);
}

template <> inline vapi_msg_bd_ip_mac_dump* vapi_alloc<vapi_msg_bd_ip_mac_dump>(Connection &con)
{
  vapi_msg_bd_ip_mac_dump* result = vapi_alloc_bd_ip_mac_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bd_ip_mac_dump>;

template class Dump<vapi_msg_bd_ip_mac_dump, vapi_msg_bd_ip_mac_details>;

using Bd_ip_mac_dump = Dump<vapi_msg_bd_ip_mac_dump, vapi_msg_bd_ip_mac_details>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_interface_efp_filter>(vapi_msg_l2_interface_efp_filter *msg)
{
  vapi_msg_l2_interface_efp_filter_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_interface_efp_filter>(vapi_msg_l2_interface_efp_filter *msg)
{
  vapi_msg_l2_interface_efp_filter_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_interface_efp_filter>()
{
  return ::vapi_msg_id_l2_interface_efp_filter; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_interface_efp_filter>>()
{
  return ::vapi_msg_id_l2_interface_efp_filter; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_interface_efp_filter()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_interface_efp_filter>(vapi_msg_id_l2_interface_efp_filter);
}

template <> inline vapi_msg_l2_interface_efp_filter* vapi_alloc<vapi_msg_l2_interface_efp_filter>(Connection &con)
{
  vapi_msg_l2_interface_efp_filter* result = vapi_alloc_l2_interface_efp_filter(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_l2_interface_efp_filter>;

template class Request<vapi_msg_l2_interface_efp_filter, vapi_msg_l2_interface_efp_filter_reply>;

using L2_interface_efp_filter = Request<vapi_msg_l2_interface_efp_filter, vapi_msg_l2_interface_efp_filter_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_l2_interface_efp_filter_reply>(vapi_msg_l2_interface_efp_filter_reply *msg)
{
  vapi_msg_l2_interface_efp_filter_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_interface_efp_filter_reply>(vapi_msg_l2_interface_efp_filter_reply *msg)
{
  vapi_msg_l2_interface_efp_filter_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_interface_efp_filter_reply>()
{
  return ::vapi_msg_id_l2_interface_efp_filter_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_interface_efp_filter_reply>>()
{
  return ::vapi_msg_id_l2_interface_efp_filter_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_interface_efp_filter_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_interface_efp_filter_reply>(vapi_msg_id_l2_interface_efp_filter_reply);
}

template class Msg<vapi_msg_l2_interface_efp_filter_reply>;

using L2_interface_efp_filter_reply = Msg<vapi_msg_l2_interface_efp_filter_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_vpath>(vapi_msg_sw_interface_set_vpath *msg)
{
  vapi_msg_sw_interface_set_vpath_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_vpath>(vapi_msg_sw_interface_set_vpath *msg)
{
  vapi_msg_sw_interface_set_vpath_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_vpath>()
{
  return ::vapi_msg_id_sw_interface_set_vpath; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_vpath>>()
{
  return ::vapi_msg_id_sw_interface_set_vpath; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_vpath()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_vpath>(vapi_msg_id_sw_interface_set_vpath);
}

template <> inline vapi_msg_sw_interface_set_vpath* vapi_alloc<vapi_msg_sw_interface_set_vpath>(Connection &con)
{
  vapi_msg_sw_interface_set_vpath* result = vapi_alloc_sw_interface_set_vpath(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_set_vpath>;

template class Request<vapi_msg_sw_interface_set_vpath, vapi_msg_sw_interface_set_vpath_reply>;

using Sw_interface_set_vpath = Request<vapi_msg_sw_interface_set_vpath, vapi_msg_sw_interface_set_vpath_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_set_vpath_reply>(vapi_msg_sw_interface_set_vpath_reply *msg)
{
  vapi_msg_sw_interface_set_vpath_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_set_vpath_reply>(vapi_msg_sw_interface_set_vpath_reply *msg)
{
  vapi_msg_sw_interface_set_vpath_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_set_vpath_reply>()
{
  return ::vapi_msg_id_sw_interface_set_vpath_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_set_vpath_reply>>()
{
  return ::vapi_msg_id_sw_interface_set_vpath_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_set_vpath_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_set_vpath_reply>(vapi_msg_id_sw_interface_set_vpath_reply);
}

template class Msg<vapi_msg_sw_interface_set_vpath_reply>;

using Sw_interface_set_vpath_reply = Msg<vapi_msg_sw_interface_set_vpath_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bvi_create>(vapi_msg_bvi_create *msg)
{
  vapi_msg_bvi_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bvi_create>(vapi_msg_bvi_create *msg)
{
  vapi_msg_bvi_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bvi_create>()
{
  return ::vapi_msg_id_bvi_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bvi_create>>()
{
  return ::vapi_msg_id_bvi_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bvi_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bvi_create>(vapi_msg_id_bvi_create);
}

template <> inline vapi_msg_bvi_create* vapi_alloc<vapi_msg_bvi_create>(Connection &con)
{
  vapi_msg_bvi_create* result = vapi_alloc_bvi_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bvi_create>;

template class Request<vapi_msg_bvi_create, vapi_msg_bvi_create_reply>;

using Bvi_create = Request<vapi_msg_bvi_create, vapi_msg_bvi_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bvi_create_reply>(vapi_msg_bvi_create_reply *msg)
{
  vapi_msg_bvi_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bvi_create_reply>(vapi_msg_bvi_create_reply *msg)
{
  vapi_msg_bvi_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bvi_create_reply>()
{
  return ::vapi_msg_id_bvi_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bvi_create_reply>>()
{
  return ::vapi_msg_id_bvi_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bvi_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bvi_create_reply>(vapi_msg_id_bvi_create_reply);
}

template class Msg<vapi_msg_bvi_create_reply>;

using Bvi_create_reply = Msg<vapi_msg_bvi_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bvi_delete>(vapi_msg_bvi_delete *msg)
{
  vapi_msg_bvi_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bvi_delete>(vapi_msg_bvi_delete *msg)
{
  vapi_msg_bvi_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bvi_delete>()
{
  return ::vapi_msg_id_bvi_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bvi_delete>>()
{
  return ::vapi_msg_id_bvi_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bvi_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bvi_delete>(vapi_msg_id_bvi_delete);
}

template <> inline vapi_msg_bvi_delete* vapi_alloc<vapi_msg_bvi_delete>(Connection &con)
{
  vapi_msg_bvi_delete* result = vapi_alloc_bvi_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bvi_delete>;

template class Request<vapi_msg_bvi_delete, vapi_msg_bvi_delete_reply>;

using Bvi_delete = Request<vapi_msg_bvi_delete, vapi_msg_bvi_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bvi_delete_reply>(vapi_msg_bvi_delete_reply *msg)
{
  vapi_msg_bvi_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bvi_delete_reply>(vapi_msg_bvi_delete_reply *msg)
{
  vapi_msg_bvi_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bvi_delete_reply>()
{
  return ::vapi_msg_id_bvi_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bvi_delete_reply>>()
{
  return ::vapi_msg_id_bvi_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bvi_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bvi_delete_reply>(vapi_msg_id_bvi_delete_reply);
}

template class Msg<vapi_msg_bvi_delete_reply>;

using Bvi_delete_reply = Msg<vapi_msg_bvi_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_l2_arp_term_events>(vapi_msg_want_l2_arp_term_events *msg)
{
  vapi_msg_want_l2_arp_term_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_l2_arp_term_events>(vapi_msg_want_l2_arp_term_events *msg)
{
  vapi_msg_want_l2_arp_term_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_l2_arp_term_events>()
{
  return ::vapi_msg_id_want_l2_arp_term_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_l2_arp_term_events>>()
{
  return ::vapi_msg_id_want_l2_arp_term_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_l2_arp_term_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_l2_arp_term_events>(vapi_msg_id_want_l2_arp_term_events);
}

template <> inline vapi_msg_want_l2_arp_term_events* vapi_alloc<vapi_msg_want_l2_arp_term_events>(Connection &con)
{
  vapi_msg_want_l2_arp_term_events* result = vapi_alloc_want_l2_arp_term_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_l2_arp_term_events>;

template class Request<vapi_msg_want_l2_arp_term_events, vapi_msg_want_l2_arp_term_events_reply>;

using Want_l2_arp_term_events = Request<vapi_msg_want_l2_arp_term_events, vapi_msg_want_l2_arp_term_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_l2_arp_term_events_reply>(vapi_msg_want_l2_arp_term_events_reply *msg)
{
  vapi_msg_want_l2_arp_term_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_l2_arp_term_events_reply>(vapi_msg_want_l2_arp_term_events_reply *msg)
{
  vapi_msg_want_l2_arp_term_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_l2_arp_term_events_reply>()
{
  return ::vapi_msg_id_want_l2_arp_term_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_l2_arp_term_events_reply>>()
{
  return ::vapi_msg_id_want_l2_arp_term_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_l2_arp_term_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_l2_arp_term_events_reply>(vapi_msg_id_want_l2_arp_term_events_reply);
}

template class Msg<vapi_msg_want_l2_arp_term_events_reply>;

using Want_l2_arp_term_events_reply = Msg<vapi_msg_want_l2_arp_term_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_l2_arp_term_event>(vapi_msg_l2_arp_term_event *msg)
{
  vapi_msg_l2_arp_term_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_l2_arp_term_event>(vapi_msg_l2_arp_term_event *msg)
{
  vapi_msg_l2_arp_term_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_l2_arp_term_event>()
{
  return ::vapi_msg_id_l2_arp_term_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_l2_arp_term_event>>()
{
  return ::vapi_msg_id_l2_arp_term_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_l2_arp_term_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_l2_arp_term_event>(vapi_msg_id_l2_arp_term_event);
}

template class Msg<vapi_msg_l2_arp_term_event>;

using L2_arp_term_event = Msg<vapi_msg_l2_arp_term_event>;
}
#endif
