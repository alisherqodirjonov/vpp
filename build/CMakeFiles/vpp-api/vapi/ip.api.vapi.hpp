#ifndef __included_hpp_ip_api_json
#define __included_hpp_ip_api_json

#include <vapi/vapi.hpp>
#include <vapi/ip.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_add_del>(vapi_msg_ip_table_add_del *msg)
{
  vapi_msg_ip_table_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_add_del>(vapi_msg_ip_table_add_del *msg)
{
  vapi_msg_ip_table_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_add_del>()
{
  return ::vapi_msg_id_ip_table_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_add_del>>()
{
  return ::vapi_msg_id_ip_table_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_add_del>(vapi_msg_id_ip_table_add_del);
}

template <> inline vapi_msg_ip_table_add_del* vapi_alloc<vapi_msg_ip_table_add_del>(Connection &con)
{
  vapi_msg_ip_table_add_del* result = vapi_alloc_ip_table_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_add_del>;

template class Request<vapi_msg_ip_table_add_del, vapi_msg_ip_table_add_del_reply>;

using Ip_table_add_del = Request<vapi_msg_ip_table_add_del, vapi_msg_ip_table_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_add_del_reply>(vapi_msg_ip_table_add_del_reply *msg)
{
  vapi_msg_ip_table_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_add_del_reply>(vapi_msg_ip_table_add_del_reply *msg)
{
  vapi_msg_ip_table_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_add_del_reply>()
{
  return ::vapi_msg_id_ip_table_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_add_del_reply>>()
{
  return ::vapi_msg_id_ip_table_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_add_del_reply>(vapi_msg_id_ip_table_add_del_reply);
}

template class Msg<vapi_msg_ip_table_add_del_reply>;

using Ip_table_add_del_reply = Msg<vapi_msg_ip_table_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_table_add_del_v2>(vapi_msg_ip_table_add_del_v2 *msg)
{
  vapi_msg_ip_table_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_add_del_v2>(vapi_msg_ip_table_add_del_v2 *msg)
{
  vapi_msg_ip_table_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_add_del_v2>()
{
  return ::vapi_msg_id_ip_table_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_add_del_v2>>()
{
  return ::vapi_msg_id_ip_table_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_add_del_v2>(vapi_msg_id_ip_table_add_del_v2);
}

template <> inline vapi_msg_ip_table_add_del_v2* vapi_alloc<vapi_msg_ip_table_add_del_v2>(Connection &con)
{
  vapi_msg_ip_table_add_del_v2* result = vapi_alloc_ip_table_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_add_del_v2>;

template class Request<vapi_msg_ip_table_add_del_v2, vapi_msg_ip_table_add_del_v2_reply>;

using Ip_table_add_del_v2 = Request<vapi_msg_ip_table_add_del_v2, vapi_msg_ip_table_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_add_del_v2_reply>(vapi_msg_ip_table_add_del_v2_reply *msg)
{
  vapi_msg_ip_table_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_add_del_v2_reply>(vapi_msg_ip_table_add_del_v2_reply *msg)
{
  vapi_msg_ip_table_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_add_del_v2_reply>()
{
  return ::vapi_msg_id_ip_table_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_add_del_v2_reply>>()
{
  return ::vapi_msg_id_ip_table_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_add_del_v2_reply>(vapi_msg_id_ip_table_add_del_v2_reply);
}

template class Msg<vapi_msg_ip_table_add_del_v2_reply>;

using Ip_table_add_del_v2_reply = Msg<vapi_msg_ip_table_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_table_allocate>(vapi_msg_ip_table_allocate *msg)
{
  vapi_msg_ip_table_allocate_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_allocate>(vapi_msg_ip_table_allocate *msg)
{
  vapi_msg_ip_table_allocate_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_allocate>()
{
  return ::vapi_msg_id_ip_table_allocate; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_allocate>>()
{
  return ::vapi_msg_id_ip_table_allocate; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_allocate()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_allocate>(vapi_msg_id_ip_table_allocate);
}

template <> inline vapi_msg_ip_table_allocate* vapi_alloc<vapi_msg_ip_table_allocate>(Connection &con)
{
  vapi_msg_ip_table_allocate* result = vapi_alloc_ip_table_allocate(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_allocate>;

template class Request<vapi_msg_ip_table_allocate, vapi_msg_ip_table_allocate_reply>;

using Ip_table_allocate = Request<vapi_msg_ip_table_allocate, vapi_msg_ip_table_allocate_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_allocate_reply>(vapi_msg_ip_table_allocate_reply *msg)
{
  vapi_msg_ip_table_allocate_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_allocate_reply>(vapi_msg_ip_table_allocate_reply *msg)
{
  vapi_msg_ip_table_allocate_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_allocate_reply>()
{
  return ::vapi_msg_id_ip_table_allocate_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_allocate_reply>>()
{
  return ::vapi_msg_id_ip_table_allocate_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_allocate_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_allocate_reply>(vapi_msg_id_ip_table_allocate_reply);
}

template class Msg<vapi_msg_ip_table_allocate_reply>;

using Ip_table_allocate_reply = Msg<vapi_msg_ip_table_allocate_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_table_dump>(vapi_msg_ip_table_dump *msg)
{
  vapi_msg_ip_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_dump>(vapi_msg_ip_table_dump *msg)
{
  vapi_msg_ip_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_dump>()
{
  return ::vapi_msg_id_ip_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_dump>>()
{
  return ::vapi_msg_id_ip_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_dump>(vapi_msg_id_ip_table_dump);
}

template <> inline vapi_msg_ip_table_dump* vapi_alloc<vapi_msg_ip_table_dump>(Connection &con)
{
  vapi_msg_ip_table_dump* result = vapi_alloc_ip_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_dump>;

template class Dump<vapi_msg_ip_table_dump, vapi_msg_ip_table_details>;

using Ip_table_dump = Dump<vapi_msg_ip_table_dump, vapi_msg_ip_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_replace_begin>(vapi_msg_ip_table_replace_begin *msg)
{
  vapi_msg_ip_table_replace_begin_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_replace_begin>(vapi_msg_ip_table_replace_begin *msg)
{
  vapi_msg_ip_table_replace_begin_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_replace_begin>()
{
  return ::vapi_msg_id_ip_table_replace_begin; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_replace_begin>>()
{
  return ::vapi_msg_id_ip_table_replace_begin; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_replace_begin()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_replace_begin>(vapi_msg_id_ip_table_replace_begin);
}

template <> inline vapi_msg_ip_table_replace_begin* vapi_alloc<vapi_msg_ip_table_replace_begin>(Connection &con)
{
  vapi_msg_ip_table_replace_begin* result = vapi_alloc_ip_table_replace_begin(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_replace_begin>;

template class Request<vapi_msg_ip_table_replace_begin, vapi_msg_ip_table_replace_begin_reply>;

using Ip_table_replace_begin = Request<vapi_msg_ip_table_replace_begin, vapi_msg_ip_table_replace_begin_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_replace_begin_reply>(vapi_msg_ip_table_replace_begin_reply *msg)
{
  vapi_msg_ip_table_replace_begin_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_replace_begin_reply>(vapi_msg_ip_table_replace_begin_reply *msg)
{
  vapi_msg_ip_table_replace_begin_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_replace_begin_reply>()
{
  return ::vapi_msg_id_ip_table_replace_begin_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_replace_begin_reply>>()
{
  return ::vapi_msg_id_ip_table_replace_begin_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_replace_begin_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_replace_begin_reply>(vapi_msg_id_ip_table_replace_begin_reply);
}

template class Msg<vapi_msg_ip_table_replace_begin_reply>;

using Ip_table_replace_begin_reply = Msg<vapi_msg_ip_table_replace_begin_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_table_replace_end>(vapi_msg_ip_table_replace_end *msg)
{
  vapi_msg_ip_table_replace_end_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_replace_end>(vapi_msg_ip_table_replace_end *msg)
{
  vapi_msg_ip_table_replace_end_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_replace_end>()
{
  return ::vapi_msg_id_ip_table_replace_end; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_replace_end>>()
{
  return ::vapi_msg_id_ip_table_replace_end; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_replace_end()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_replace_end>(vapi_msg_id_ip_table_replace_end);
}

template <> inline vapi_msg_ip_table_replace_end* vapi_alloc<vapi_msg_ip_table_replace_end>(Connection &con)
{
  vapi_msg_ip_table_replace_end* result = vapi_alloc_ip_table_replace_end(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_replace_end>;

template class Request<vapi_msg_ip_table_replace_end, vapi_msg_ip_table_replace_end_reply>;

using Ip_table_replace_end = Request<vapi_msg_ip_table_replace_end, vapi_msg_ip_table_replace_end_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_replace_end_reply>(vapi_msg_ip_table_replace_end_reply *msg)
{
  vapi_msg_ip_table_replace_end_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_replace_end_reply>(vapi_msg_ip_table_replace_end_reply *msg)
{
  vapi_msg_ip_table_replace_end_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_replace_end_reply>()
{
  return ::vapi_msg_id_ip_table_replace_end_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_replace_end_reply>>()
{
  return ::vapi_msg_id_ip_table_replace_end_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_replace_end_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_replace_end_reply>(vapi_msg_id_ip_table_replace_end_reply);
}

template class Msg<vapi_msg_ip_table_replace_end_reply>;

using Ip_table_replace_end_reply = Msg<vapi_msg_ip_table_replace_end_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_table_flush>(vapi_msg_ip_table_flush *msg)
{
  vapi_msg_ip_table_flush_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_flush>(vapi_msg_ip_table_flush *msg)
{
  vapi_msg_ip_table_flush_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_flush>()
{
  return ::vapi_msg_id_ip_table_flush; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_flush>>()
{
  return ::vapi_msg_id_ip_table_flush; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_flush()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_flush>(vapi_msg_id_ip_table_flush);
}

template <> inline vapi_msg_ip_table_flush* vapi_alloc<vapi_msg_ip_table_flush>(Connection &con)
{
  vapi_msg_ip_table_flush* result = vapi_alloc_ip_table_flush(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_table_flush>;

template class Request<vapi_msg_ip_table_flush, vapi_msg_ip_table_flush_reply>;

using Ip_table_flush = Request<vapi_msg_ip_table_flush, vapi_msg_ip_table_flush_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_table_flush_reply>(vapi_msg_ip_table_flush_reply *msg)
{
  vapi_msg_ip_table_flush_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_flush_reply>(vapi_msg_ip_table_flush_reply *msg)
{
  vapi_msg_ip_table_flush_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_flush_reply>()
{
  return ::vapi_msg_id_ip_table_flush_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_flush_reply>>()
{
  return ::vapi_msg_id_ip_table_flush_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_flush_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_flush_reply>(vapi_msg_id_ip_table_flush_reply);
}

template class Msg<vapi_msg_ip_table_flush_reply>;

using Ip_table_flush_reply = Msg<vapi_msg_ip_table_flush_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_table_details>(vapi_msg_ip_table_details *msg)
{
  vapi_msg_ip_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_table_details>(vapi_msg_ip_table_details *msg)
{
  vapi_msg_ip_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_table_details>()
{
  return ::vapi_msg_id_ip_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_table_details>>()
{
  return ::vapi_msg_id_ip_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_table_details>(vapi_msg_id_ip_table_details);
}

template class Msg<vapi_msg_ip_table_details>;

using Ip_table_details = Msg<vapi_msg_ip_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_route_add_del>(vapi_msg_ip_route_add_del *msg)
{
  vapi_msg_ip_route_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_add_del>(vapi_msg_ip_route_add_del *msg)
{
  vapi_msg_ip_route_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_add_del>()
{
  return ::vapi_msg_id_ip_route_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_add_del>>()
{
  return ::vapi_msg_id_ip_route_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_add_del>(vapi_msg_id_ip_route_add_del);
}

template <> inline vapi_msg_ip_route_add_del* vapi_alloc<vapi_msg_ip_route_add_del, size_t>(Connection &con, size_t route_paths_array_size)
{
  vapi_msg_ip_route_add_del* result = vapi_alloc_ip_route_add_del(con.vapi_ctx, route_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_route_add_del>;

template class Request<vapi_msg_ip_route_add_del, vapi_msg_ip_route_add_del_reply, size_t>;

using Ip_route_add_del = Request<vapi_msg_ip_route_add_del, vapi_msg_ip_route_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_route_add_del_v2>(vapi_msg_ip_route_add_del_v2 *msg)
{
  vapi_msg_ip_route_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_add_del_v2>(vapi_msg_ip_route_add_del_v2 *msg)
{
  vapi_msg_ip_route_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_add_del_v2>()
{
  return ::vapi_msg_id_ip_route_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_add_del_v2>>()
{
  return ::vapi_msg_id_ip_route_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_add_del_v2>(vapi_msg_id_ip_route_add_del_v2);
}

template <> inline vapi_msg_ip_route_add_del_v2* vapi_alloc<vapi_msg_ip_route_add_del_v2, size_t>(Connection &con, size_t route_paths_array_size)
{
  vapi_msg_ip_route_add_del_v2* result = vapi_alloc_ip_route_add_del_v2(con.vapi_ctx, route_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_route_add_del_v2>;

template class Request<vapi_msg_ip_route_add_del_v2, vapi_msg_ip_route_add_del_v2_reply, size_t>;

using Ip_route_add_del_v2 = Request<vapi_msg_ip_route_add_del_v2, vapi_msg_ip_route_add_del_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_route_add_del_reply>(vapi_msg_ip_route_add_del_reply *msg)
{
  vapi_msg_ip_route_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_add_del_reply>(vapi_msg_ip_route_add_del_reply *msg)
{
  vapi_msg_ip_route_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_add_del_reply>()
{
  return ::vapi_msg_id_ip_route_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_add_del_reply>>()
{
  return ::vapi_msg_id_ip_route_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_add_del_reply>(vapi_msg_id_ip_route_add_del_reply);
}

template class Msg<vapi_msg_ip_route_add_del_reply>;

using Ip_route_add_del_reply = Msg<vapi_msg_ip_route_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_route_add_del_v2_reply>(vapi_msg_ip_route_add_del_v2_reply *msg)
{
  vapi_msg_ip_route_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_add_del_v2_reply>(vapi_msg_ip_route_add_del_v2_reply *msg)
{
  vapi_msg_ip_route_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_add_del_v2_reply>()
{
  return ::vapi_msg_id_ip_route_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_add_del_v2_reply>>()
{
  return ::vapi_msg_id_ip_route_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_add_del_v2_reply>(vapi_msg_id_ip_route_add_del_v2_reply);
}

template class Msg<vapi_msg_ip_route_add_del_v2_reply>;

using Ip_route_add_del_v2_reply = Msg<vapi_msg_ip_route_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_route_dump>(vapi_msg_ip_route_dump *msg)
{
  vapi_msg_ip_route_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_dump>(vapi_msg_ip_route_dump *msg)
{
  vapi_msg_ip_route_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_dump>()
{
  return ::vapi_msg_id_ip_route_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_dump>>()
{
  return ::vapi_msg_id_ip_route_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_dump>(vapi_msg_id_ip_route_dump);
}

template <> inline vapi_msg_ip_route_dump* vapi_alloc<vapi_msg_ip_route_dump>(Connection &con)
{
  vapi_msg_ip_route_dump* result = vapi_alloc_ip_route_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_route_dump>;

template class Dump<vapi_msg_ip_route_dump, vapi_msg_ip_route_details>;

using Ip_route_dump = Dump<vapi_msg_ip_route_dump, vapi_msg_ip_route_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_route_v2_dump>(vapi_msg_ip_route_v2_dump *msg)
{
  vapi_msg_ip_route_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_v2_dump>(vapi_msg_ip_route_v2_dump *msg)
{
  vapi_msg_ip_route_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_v2_dump>()
{
  return ::vapi_msg_id_ip_route_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_v2_dump>>()
{
  return ::vapi_msg_id_ip_route_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_v2_dump>(vapi_msg_id_ip_route_v2_dump);
}

template <> inline vapi_msg_ip_route_v2_dump* vapi_alloc<vapi_msg_ip_route_v2_dump>(Connection &con)
{
  vapi_msg_ip_route_v2_dump* result = vapi_alloc_ip_route_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_route_v2_dump>;

template class Dump<vapi_msg_ip_route_v2_dump, vapi_msg_ip_route_v2_details>;

using Ip_route_v2_dump = Dump<vapi_msg_ip_route_v2_dump, vapi_msg_ip_route_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_route_details>(vapi_msg_ip_route_details *msg)
{
  vapi_msg_ip_route_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_details>(vapi_msg_ip_route_details *msg)
{
  vapi_msg_ip_route_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_details>()
{
  return ::vapi_msg_id_ip_route_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_details>>()
{
  return ::vapi_msg_id_ip_route_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_details>(vapi_msg_id_ip_route_details);
}

template class Msg<vapi_msg_ip_route_details>;

using Ip_route_details = Msg<vapi_msg_ip_route_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_route_v2_details>(vapi_msg_ip_route_v2_details *msg)
{
  vapi_msg_ip_route_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_v2_details>(vapi_msg_ip_route_v2_details *msg)
{
  vapi_msg_ip_route_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_v2_details>()
{
  return ::vapi_msg_id_ip_route_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_v2_details>>()
{
  return ::vapi_msg_id_ip_route_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_v2_details>(vapi_msg_id_ip_route_v2_details);
}

template class Msg<vapi_msg_ip_route_v2_details>;

using Ip_route_v2_details = Msg<vapi_msg_ip_route_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_route_lookup>(vapi_msg_ip_route_lookup *msg)
{
  vapi_msg_ip_route_lookup_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_lookup>(vapi_msg_ip_route_lookup *msg)
{
  vapi_msg_ip_route_lookup_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_lookup>()
{
  return ::vapi_msg_id_ip_route_lookup; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_lookup>>()
{
  return ::vapi_msg_id_ip_route_lookup; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_lookup()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_lookup>(vapi_msg_id_ip_route_lookup);
}

template <> inline vapi_msg_ip_route_lookup* vapi_alloc<vapi_msg_ip_route_lookup>(Connection &con)
{
  vapi_msg_ip_route_lookup* result = vapi_alloc_ip_route_lookup(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_route_lookup>;

template class Request<vapi_msg_ip_route_lookup, vapi_msg_ip_route_lookup_reply>;

using Ip_route_lookup = Request<vapi_msg_ip_route_lookup, vapi_msg_ip_route_lookup_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_route_lookup_v2>(vapi_msg_ip_route_lookup_v2 *msg)
{
  vapi_msg_ip_route_lookup_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_lookup_v2>(vapi_msg_ip_route_lookup_v2 *msg)
{
  vapi_msg_ip_route_lookup_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_lookup_v2>()
{
  return ::vapi_msg_id_ip_route_lookup_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_lookup_v2>>()
{
  return ::vapi_msg_id_ip_route_lookup_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_lookup_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_lookup_v2>(vapi_msg_id_ip_route_lookup_v2);
}

template <> inline vapi_msg_ip_route_lookup_v2* vapi_alloc<vapi_msg_ip_route_lookup_v2>(Connection &con)
{
  vapi_msg_ip_route_lookup_v2* result = vapi_alloc_ip_route_lookup_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_route_lookup_v2>;

template class Request<vapi_msg_ip_route_lookup_v2, vapi_msg_ip_route_lookup_v2_reply>;

using Ip_route_lookup_v2 = Request<vapi_msg_ip_route_lookup_v2, vapi_msg_ip_route_lookup_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_route_lookup_reply>(vapi_msg_ip_route_lookup_reply *msg)
{
  vapi_msg_ip_route_lookup_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_lookup_reply>(vapi_msg_ip_route_lookup_reply *msg)
{
  vapi_msg_ip_route_lookup_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_lookup_reply>()
{
  return ::vapi_msg_id_ip_route_lookup_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_lookup_reply>>()
{
  return ::vapi_msg_id_ip_route_lookup_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_lookup_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_lookup_reply>(vapi_msg_id_ip_route_lookup_reply);
}

template class Msg<vapi_msg_ip_route_lookup_reply>;

using Ip_route_lookup_reply = Msg<vapi_msg_ip_route_lookup_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_route_lookup_v2_reply>(vapi_msg_ip_route_lookup_v2_reply *msg)
{
  vapi_msg_ip_route_lookup_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_route_lookup_v2_reply>(vapi_msg_ip_route_lookup_v2_reply *msg)
{
  vapi_msg_ip_route_lookup_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_route_lookup_v2_reply>()
{
  return ::vapi_msg_id_ip_route_lookup_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_route_lookup_v2_reply>>()
{
  return ::vapi_msg_id_ip_route_lookup_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_route_lookup_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_route_lookup_v2_reply>(vapi_msg_id_ip_route_lookup_v2_reply);
}

template class Msg<vapi_msg_ip_route_lookup_v2_reply>;

using Ip_route_lookup_v2_reply = Msg<vapi_msg_ip_route_lookup_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash>(vapi_msg_set_ip_flow_hash *msg)
{
  vapi_msg_set_ip_flow_hash_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash>(vapi_msg_set_ip_flow_hash *msg)
{
  vapi_msg_set_ip_flow_hash_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash>()
{
  return ::vapi_msg_id_set_ip_flow_hash; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash>>()
{
  return ::vapi_msg_id_set_ip_flow_hash; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash>(vapi_msg_id_set_ip_flow_hash);
}

template <> inline vapi_msg_set_ip_flow_hash* vapi_alloc<vapi_msg_set_ip_flow_hash>(Connection &con)
{
  vapi_msg_set_ip_flow_hash* result = vapi_alloc_set_ip_flow_hash(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_ip_flow_hash>;

template class Request<vapi_msg_set_ip_flow_hash, vapi_msg_set_ip_flow_hash_reply>;

using Set_ip_flow_hash = Request<vapi_msg_set_ip_flow_hash, vapi_msg_set_ip_flow_hash_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_reply>(vapi_msg_set_ip_flow_hash_reply *msg)
{
  vapi_msg_set_ip_flow_hash_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_reply>(vapi_msg_set_ip_flow_hash_reply *msg)
{
  vapi_msg_set_ip_flow_hash_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_reply>()
{
  return ::vapi_msg_id_set_ip_flow_hash_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_reply>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_reply>(vapi_msg_id_set_ip_flow_hash_reply);
}

template class Msg<vapi_msg_set_ip_flow_hash_reply>;

using Set_ip_flow_hash_reply = Msg<vapi_msg_set_ip_flow_hash_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_v2>(vapi_msg_set_ip_flow_hash_v2 *msg)
{
  vapi_msg_set_ip_flow_hash_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_v2>(vapi_msg_set_ip_flow_hash_v2 *msg)
{
  vapi_msg_set_ip_flow_hash_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_v2>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_v2>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_v2>(vapi_msg_id_set_ip_flow_hash_v2);
}

template <> inline vapi_msg_set_ip_flow_hash_v2* vapi_alloc<vapi_msg_set_ip_flow_hash_v2>(Connection &con)
{
  vapi_msg_set_ip_flow_hash_v2* result = vapi_alloc_set_ip_flow_hash_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_ip_flow_hash_v2>;

template class Request<vapi_msg_set_ip_flow_hash_v2, vapi_msg_set_ip_flow_hash_v2_reply>;

using Set_ip_flow_hash_v2 = Request<vapi_msg_set_ip_flow_hash_v2, vapi_msg_set_ip_flow_hash_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_v2_reply>(vapi_msg_set_ip_flow_hash_v2_reply *msg)
{
  vapi_msg_set_ip_flow_hash_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_v2_reply>(vapi_msg_set_ip_flow_hash_v2_reply *msg)
{
  vapi_msg_set_ip_flow_hash_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_v2_reply>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_v2_reply>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_v2_reply>(vapi_msg_id_set_ip_flow_hash_v2_reply);
}

template class Msg<vapi_msg_set_ip_flow_hash_v2_reply>;

using Set_ip_flow_hash_v2_reply = Msg<vapi_msg_set_ip_flow_hash_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_v3>(vapi_msg_set_ip_flow_hash_v3 *msg)
{
  vapi_msg_set_ip_flow_hash_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_v3>(vapi_msg_set_ip_flow_hash_v3 *msg)
{
  vapi_msg_set_ip_flow_hash_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_v3>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_v3>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_v3>(vapi_msg_id_set_ip_flow_hash_v3);
}

template <> inline vapi_msg_set_ip_flow_hash_v3* vapi_alloc<vapi_msg_set_ip_flow_hash_v3>(Connection &con)
{
  vapi_msg_set_ip_flow_hash_v3* result = vapi_alloc_set_ip_flow_hash_v3(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_ip_flow_hash_v3>;

template class Request<vapi_msg_set_ip_flow_hash_v3, vapi_msg_set_ip_flow_hash_v3_reply>;

using Set_ip_flow_hash_v3 = Request<vapi_msg_set_ip_flow_hash_v3, vapi_msg_set_ip_flow_hash_v3_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_v3_reply>(vapi_msg_set_ip_flow_hash_v3_reply *msg)
{
  vapi_msg_set_ip_flow_hash_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_v3_reply>(vapi_msg_set_ip_flow_hash_v3_reply *msg)
{
  vapi_msg_set_ip_flow_hash_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_v3_reply>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_v3_reply>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_v3_reply>(vapi_msg_id_set_ip_flow_hash_v3_reply);
}

template class Msg<vapi_msg_set_ip_flow_hash_v3_reply>;

using Set_ip_flow_hash_v3_reply = Msg<vapi_msg_set_ip_flow_hash_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_router_id>(vapi_msg_set_ip_flow_hash_router_id *msg)
{
  vapi_msg_set_ip_flow_hash_router_id_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_router_id>(vapi_msg_set_ip_flow_hash_router_id *msg)
{
  vapi_msg_set_ip_flow_hash_router_id_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_router_id>()
{
  return ::vapi_msg_id_set_ip_flow_hash_router_id; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_router_id>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_router_id; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_router_id()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_router_id>(vapi_msg_id_set_ip_flow_hash_router_id);
}

template <> inline vapi_msg_set_ip_flow_hash_router_id* vapi_alloc<vapi_msg_set_ip_flow_hash_router_id>(Connection &con)
{
  vapi_msg_set_ip_flow_hash_router_id* result = vapi_alloc_set_ip_flow_hash_router_id(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_ip_flow_hash_router_id>;

template class Request<vapi_msg_set_ip_flow_hash_router_id, vapi_msg_set_ip_flow_hash_router_id_reply>;

using Set_ip_flow_hash_router_id = Request<vapi_msg_set_ip_flow_hash_router_id, vapi_msg_set_ip_flow_hash_router_id_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ip_flow_hash_router_id_reply>(vapi_msg_set_ip_flow_hash_router_id_reply *msg)
{
  vapi_msg_set_ip_flow_hash_router_id_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ip_flow_hash_router_id_reply>(vapi_msg_set_ip_flow_hash_router_id_reply *msg)
{
  vapi_msg_set_ip_flow_hash_router_id_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ip_flow_hash_router_id_reply>()
{
  return ::vapi_msg_id_set_ip_flow_hash_router_id_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ip_flow_hash_router_id_reply>>()
{
  return ::vapi_msg_id_set_ip_flow_hash_router_id_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ip_flow_hash_router_id_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ip_flow_hash_router_id_reply>(vapi_msg_id_set_ip_flow_hash_router_id_reply);
}

template class Msg<vapi_msg_set_ip_flow_hash_router_id_reply>;

using Set_ip_flow_hash_router_id_reply = Msg<vapi_msg_set_ip_flow_hash_router_id_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6_enable_disable>(vapi_msg_sw_interface_ip6_enable_disable *msg)
{
  vapi_msg_sw_interface_ip6_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6_enable_disable>(vapi_msg_sw_interface_ip6_enable_disable *msg)
{
  vapi_msg_sw_interface_ip6_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6_enable_disable>()
{
  return ::vapi_msg_id_sw_interface_ip6_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6_enable_disable>>()
{
  return ::vapi_msg_id_sw_interface_ip6_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6_enable_disable>(vapi_msg_id_sw_interface_ip6_enable_disable);
}

template <> inline vapi_msg_sw_interface_ip6_enable_disable* vapi_alloc<vapi_msg_sw_interface_ip6_enable_disable>(Connection &con)
{
  vapi_msg_sw_interface_ip6_enable_disable* result = vapi_alloc_sw_interface_ip6_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip6_enable_disable>;

template class Request<vapi_msg_sw_interface_ip6_enable_disable, vapi_msg_sw_interface_ip6_enable_disable_reply>;

using Sw_interface_ip6_enable_disable = Request<vapi_msg_sw_interface_ip6_enable_disable, vapi_msg_sw_interface_ip6_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6_enable_disable_reply>(vapi_msg_sw_interface_ip6_enable_disable_reply *msg)
{
  vapi_msg_sw_interface_ip6_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6_enable_disable_reply>(vapi_msg_sw_interface_ip6_enable_disable_reply *msg)
{
  vapi_msg_sw_interface_ip6_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6_enable_disable_reply>()
{
  return ::vapi_msg_id_sw_interface_ip6_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6_enable_disable_reply>>()
{
  return ::vapi_msg_id_sw_interface_ip6_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6_enable_disable_reply>(vapi_msg_id_sw_interface_ip6_enable_disable_reply);
}

template class Msg<vapi_msg_sw_interface_ip6_enable_disable_reply>;

using Sw_interface_ip6_enable_disable_reply = Msg<vapi_msg_sw_interface_ip6_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip4_enable_disable>(vapi_msg_sw_interface_ip4_enable_disable *msg)
{
  vapi_msg_sw_interface_ip4_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip4_enable_disable>(vapi_msg_sw_interface_ip4_enable_disable *msg)
{
  vapi_msg_sw_interface_ip4_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip4_enable_disable>()
{
  return ::vapi_msg_id_sw_interface_ip4_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip4_enable_disable>>()
{
  return ::vapi_msg_id_sw_interface_ip4_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip4_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip4_enable_disable>(vapi_msg_id_sw_interface_ip4_enable_disable);
}

template <> inline vapi_msg_sw_interface_ip4_enable_disable* vapi_alloc<vapi_msg_sw_interface_ip4_enable_disable>(Connection &con)
{
  vapi_msg_sw_interface_ip4_enable_disable* result = vapi_alloc_sw_interface_ip4_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip4_enable_disable>;

template class Request<vapi_msg_sw_interface_ip4_enable_disable, vapi_msg_sw_interface_ip4_enable_disable_reply>;

using Sw_interface_ip4_enable_disable = Request<vapi_msg_sw_interface_ip4_enable_disable, vapi_msg_sw_interface_ip4_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip4_enable_disable_reply>(vapi_msg_sw_interface_ip4_enable_disable_reply *msg)
{
  vapi_msg_sw_interface_ip4_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip4_enable_disable_reply>(vapi_msg_sw_interface_ip4_enable_disable_reply *msg)
{
  vapi_msg_sw_interface_ip4_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip4_enable_disable_reply>()
{
  return ::vapi_msg_id_sw_interface_ip4_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip4_enable_disable_reply>>()
{
  return ::vapi_msg_id_sw_interface_ip4_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip4_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip4_enable_disable_reply>(vapi_msg_id_sw_interface_ip4_enable_disable_reply);
}

template class Msg<vapi_msg_sw_interface_ip4_enable_disable_reply>;

using Sw_interface_ip4_enable_disable_reply = Msg<vapi_msg_sw_interface_ip4_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_mtable_dump>(vapi_msg_ip_mtable_dump *msg)
{
  vapi_msg_ip_mtable_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_mtable_dump>(vapi_msg_ip_mtable_dump *msg)
{
  vapi_msg_ip_mtable_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_mtable_dump>()
{
  return ::vapi_msg_id_ip_mtable_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_mtable_dump>>()
{
  return ::vapi_msg_id_ip_mtable_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_mtable_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_mtable_dump>(vapi_msg_id_ip_mtable_dump);
}

template <> inline vapi_msg_ip_mtable_dump* vapi_alloc<vapi_msg_ip_mtable_dump>(Connection &con)
{
  vapi_msg_ip_mtable_dump* result = vapi_alloc_ip_mtable_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_mtable_dump>;

template class Dump<vapi_msg_ip_mtable_dump, vapi_msg_ip_mtable_details>;

using Ip_mtable_dump = Dump<vapi_msg_ip_mtable_dump, vapi_msg_ip_mtable_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_mtable_details>(vapi_msg_ip_mtable_details *msg)
{
  vapi_msg_ip_mtable_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_mtable_details>(vapi_msg_ip_mtable_details *msg)
{
  vapi_msg_ip_mtable_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_mtable_details>()
{
  return ::vapi_msg_id_ip_mtable_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_mtable_details>>()
{
  return ::vapi_msg_id_ip_mtable_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_mtable_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_mtable_details>(vapi_msg_id_ip_mtable_details);
}

template class Msg<vapi_msg_ip_mtable_details>;

using Ip_mtable_details = Msg<vapi_msg_ip_mtable_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_mroute_add_del>(vapi_msg_ip_mroute_add_del *msg)
{
  vapi_msg_ip_mroute_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_mroute_add_del>(vapi_msg_ip_mroute_add_del *msg)
{
  vapi_msg_ip_mroute_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_mroute_add_del>()
{
  return ::vapi_msg_id_ip_mroute_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_mroute_add_del>>()
{
  return ::vapi_msg_id_ip_mroute_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_mroute_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_mroute_add_del>(vapi_msg_id_ip_mroute_add_del);
}

template <> inline vapi_msg_ip_mroute_add_del* vapi_alloc<vapi_msg_ip_mroute_add_del, size_t>(Connection &con, size_t route_paths_array_size)
{
  vapi_msg_ip_mroute_add_del* result = vapi_alloc_ip_mroute_add_del(con.vapi_ctx, route_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_mroute_add_del>;

template class Request<vapi_msg_ip_mroute_add_del, vapi_msg_ip_mroute_add_del_reply, size_t>;

using Ip_mroute_add_del = Request<vapi_msg_ip_mroute_add_del, vapi_msg_ip_mroute_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_mroute_add_del_reply>(vapi_msg_ip_mroute_add_del_reply *msg)
{
  vapi_msg_ip_mroute_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_mroute_add_del_reply>(vapi_msg_ip_mroute_add_del_reply *msg)
{
  vapi_msg_ip_mroute_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_mroute_add_del_reply>()
{
  return ::vapi_msg_id_ip_mroute_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_mroute_add_del_reply>>()
{
  return ::vapi_msg_id_ip_mroute_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_mroute_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_mroute_add_del_reply>(vapi_msg_id_ip_mroute_add_del_reply);
}

template class Msg<vapi_msg_ip_mroute_add_del_reply>;

using Ip_mroute_add_del_reply = Msg<vapi_msg_ip_mroute_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_mroute_dump>(vapi_msg_ip_mroute_dump *msg)
{
  vapi_msg_ip_mroute_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_mroute_dump>(vapi_msg_ip_mroute_dump *msg)
{
  vapi_msg_ip_mroute_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_mroute_dump>()
{
  return ::vapi_msg_id_ip_mroute_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_mroute_dump>>()
{
  return ::vapi_msg_id_ip_mroute_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_mroute_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_mroute_dump>(vapi_msg_id_ip_mroute_dump);
}

template <> inline vapi_msg_ip_mroute_dump* vapi_alloc<vapi_msg_ip_mroute_dump>(Connection &con)
{
  vapi_msg_ip_mroute_dump* result = vapi_alloc_ip_mroute_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_mroute_dump>;

template class Dump<vapi_msg_ip_mroute_dump, vapi_msg_ip_mroute_details>;

using Ip_mroute_dump = Dump<vapi_msg_ip_mroute_dump, vapi_msg_ip_mroute_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_mroute_details>(vapi_msg_ip_mroute_details *msg)
{
  vapi_msg_ip_mroute_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_mroute_details>(vapi_msg_ip_mroute_details *msg)
{
  vapi_msg_ip_mroute_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_mroute_details>()
{
  return ::vapi_msg_id_ip_mroute_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_mroute_details>>()
{
  return ::vapi_msg_id_ip_mroute_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_mroute_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_mroute_details>(vapi_msg_id_ip_mroute_details);
}

template class Msg<vapi_msg_ip_mroute_details>;

using Ip_mroute_details = Msg<vapi_msg_ip_mroute_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_address_details>(vapi_msg_ip_address_details *msg)
{
  vapi_msg_ip_address_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_address_details>(vapi_msg_ip_address_details *msg)
{
  vapi_msg_ip_address_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_address_details>()
{
  return ::vapi_msg_id_ip_address_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_address_details>>()
{
  return ::vapi_msg_id_ip_address_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_address_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_address_details>(vapi_msg_id_ip_address_details);
}

template class Msg<vapi_msg_ip_address_details>;

using Ip_address_details = Msg<vapi_msg_ip_address_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_address_dump>(vapi_msg_ip_address_dump *msg)
{
  vapi_msg_ip_address_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_address_dump>(vapi_msg_ip_address_dump *msg)
{
  vapi_msg_ip_address_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_address_dump>()
{
  return ::vapi_msg_id_ip_address_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_address_dump>>()
{
  return ::vapi_msg_id_ip_address_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_address_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_address_dump>(vapi_msg_id_ip_address_dump);
}

template <> inline vapi_msg_ip_address_dump* vapi_alloc<vapi_msg_ip_address_dump>(Connection &con)
{
  vapi_msg_ip_address_dump* result = vapi_alloc_ip_address_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_address_dump>;

template class Dump<vapi_msg_ip_address_dump, vapi_msg_ip_address_details>;

using Ip_address_dump = Dump<vapi_msg_ip_address_dump, vapi_msg_ip_address_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_unnumbered_details>(vapi_msg_ip_unnumbered_details *msg)
{
  vapi_msg_ip_unnumbered_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_unnumbered_details>(vapi_msg_ip_unnumbered_details *msg)
{
  vapi_msg_ip_unnumbered_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_unnumbered_details>()
{
  return ::vapi_msg_id_ip_unnumbered_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_unnumbered_details>>()
{
  return ::vapi_msg_id_ip_unnumbered_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_unnumbered_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_unnumbered_details>(vapi_msg_id_ip_unnumbered_details);
}

template class Msg<vapi_msg_ip_unnumbered_details>;

using Ip_unnumbered_details = Msg<vapi_msg_ip_unnumbered_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_unnumbered_dump>(vapi_msg_ip_unnumbered_dump *msg)
{
  vapi_msg_ip_unnumbered_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_unnumbered_dump>(vapi_msg_ip_unnumbered_dump *msg)
{
  vapi_msg_ip_unnumbered_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_unnumbered_dump>()
{
  return ::vapi_msg_id_ip_unnumbered_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_unnumbered_dump>>()
{
  return ::vapi_msg_id_ip_unnumbered_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_unnumbered_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_unnumbered_dump>(vapi_msg_id_ip_unnumbered_dump);
}

template <> inline vapi_msg_ip_unnumbered_dump* vapi_alloc<vapi_msg_ip_unnumbered_dump>(Connection &con)
{
  vapi_msg_ip_unnumbered_dump* result = vapi_alloc_ip_unnumbered_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_unnumbered_dump>;

template class Dump<vapi_msg_ip_unnumbered_dump, vapi_msg_ip_unnumbered_details>;

using Ip_unnumbered_dump = Dump<vapi_msg_ip_unnumbered_dump, vapi_msg_ip_unnumbered_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_details>(vapi_msg_ip_details *msg)
{
  vapi_msg_ip_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_details>(vapi_msg_ip_details *msg)
{
  vapi_msg_ip_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_details>()
{
  return ::vapi_msg_id_ip_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_details>>()
{
  return ::vapi_msg_id_ip_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_details>(vapi_msg_id_ip_details);
}

template class Msg<vapi_msg_ip_details>;

using Ip_details = Msg<vapi_msg_ip_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_dump>(vapi_msg_ip_dump *msg)
{
  vapi_msg_ip_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_dump>(vapi_msg_ip_dump *msg)
{
  vapi_msg_ip_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_dump>()
{
  return ::vapi_msg_id_ip_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_dump>>()
{
  return ::vapi_msg_id_ip_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_dump>(vapi_msg_id_ip_dump);
}

template <> inline vapi_msg_ip_dump* vapi_alloc<vapi_msg_ip_dump>(Connection &con)
{
  vapi_msg_ip_dump* result = vapi_alloc_ip_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_dump>;

template class Dump<vapi_msg_ip_dump, vapi_msg_ip_details>;

using Ip_dump = Dump<vapi_msg_ip_dump, vapi_msg_ip_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mfib_signal_dump>(vapi_msg_mfib_signal_dump *msg)
{
  vapi_msg_mfib_signal_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mfib_signal_dump>(vapi_msg_mfib_signal_dump *msg)
{
  vapi_msg_mfib_signal_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mfib_signal_dump>()
{
  return ::vapi_msg_id_mfib_signal_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mfib_signal_dump>>()
{
  return ::vapi_msg_id_mfib_signal_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mfib_signal_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mfib_signal_dump>(vapi_msg_id_mfib_signal_dump);
}

template <> inline vapi_msg_mfib_signal_dump* vapi_alloc<vapi_msg_mfib_signal_dump>(Connection &con)
{
  vapi_msg_mfib_signal_dump* result = vapi_alloc_mfib_signal_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_mfib_signal_dump>;

template class Dump<vapi_msg_mfib_signal_dump, vapi_msg_mfib_signal_details>;

using Mfib_signal_dump = Dump<vapi_msg_mfib_signal_dump, vapi_msg_mfib_signal_details>;

template <> inline void vapi_swap_to_be<vapi_msg_mfib_signal_details>(vapi_msg_mfib_signal_details *msg)
{
  vapi_msg_mfib_signal_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_mfib_signal_details>(vapi_msg_mfib_signal_details *msg)
{
  vapi_msg_mfib_signal_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_mfib_signal_details>()
{
  return ::vapi_msg_id_mfib_signal_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_mfib_signal_details>>()
{
  return ::vapi_msg_id_mfib_signal_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_mfib_signal_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_mfib_signal_details>(vapi_msg_id_mfib_signal_details);
}

template class Msg<vapi_msg_mfib_signal_details>;

using Mfib_signal_details = Msg<vapi_msg_mfib_signal_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_police>(vapi_msg_ip_punt_police *msg)
{
  vapi_msg_ip_punt_police_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_police>(vapi_msg_ip_punt_police *msg)
{
  vapi_msg_ip_punt_police_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_police>()
{
  return ::vapi_msg_id_ip_punt_police; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_police>>()
{
  return ::vapi_msg_id_ip_punt_police; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_police()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_police>(vapi_msg_id_ip_punt_police);
}

template <> inline vapi_msg_ip_punt_police* vapi_alloc<vapi_msg_ip_punt_police>(Connection &con)
{
  vapi_msg_ip_punt_police* result = vapi_alloc_ip_punt_police(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_punt_police>;

template class Request<vapi_msg_ip_punt_police, vapi_msg_ip_punt_police_reply>;

using Ip_punt_police = Request<vapi_msg_ip_punt_police, vapi_msg_ip_punt_police_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_police_reply>(vapi_msg_ip_punt_police_reply *msg)
{
  vapi_msg_ip_punt_police_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_police_reply>(vapi_msg_ip_punt_police_reply *msg)
{
  vapi_msg_ip_punt_police_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_police_reply>()
{
  return ::vapi_msg_id_ip_punt_police_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_police_reply>>()
{
  return ::vapi_msg_id_ip_punt_police_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_police_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_police_reply>(vapi_msg_id_ip_punt_police_reply);
}

template class Msg<vapi_msg_ip_punt_police_reply>;

using Ip_punt_police_reply = Msg<vapi_msg_ip_punt_police_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_redirect>(vapi_msg_ip_punt_redirect *msg)
{
  vapi_msg_ip_punt_redirect_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_redirect>(vapi_msg_ip_punt_redirect *msg)
{
  vapi_msg_ip_punt_redirect_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_redirect>()
{
  return ::vapi_msg_id_ip_punt_redirect; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_redirect>>()
{
  return ::vapi_msg_id_ip_punt_redirect; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_redirect()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_redirect>(vapi_msg_id_ip_punt_redirect);
}

template <> inline vapi_msg_ip_punt_redirect* vapi_alloc<vapi_msg_ip_punt_redirect>(Connection &con)
{
  vapi_msg_ip_punt_redirect* result = vapi_alloc_ip_punt_redirect(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_punt_redirect>;

template class Request<vapi_msg_ip_punt_redirect, vapi_msg_ip_punt_redirect_reply>;

using Ip_punt_redirect = Request<vapi_msg_ip_punt_redirect, vapi_msg_ip_punt_redirect_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_redirect_reply>(vapi_msg_ip_punt_redirect_reply *msg)
{
  vapi_msg_ip_punt_redirect_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_redirect_reply>(vapi_msg_ip_punt_redirect_reply *msg)
{
  vapi_msg_ip_punt_redirect_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_redirect_reply>()
{
  return ::vapi_msg_id_ip_punt_redirect_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_redirect_reply>>()
{
  return ::vapi_msg_id_ip_punt_redirect_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_redirect_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_redirect_reply>(vapi_msg_id_ip_punt_redirect_reply);
}

template class Msg<vapi_msg_ip_punt_redirect_reply>;

using Ip_punt_redirect_reply = Msg<vapi_msg_ip_punt_redirect_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_redirect_dump>(vapi_msg_ip_punt_redirect_dump *msg)
{
  vapi_msg_ip_punt_redirect_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_redirect_dump>(vapi_msg_ip_punt_redirect_dump *msg)
{
  vapi_msg_ip_punt_redirect_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_redirect_dump>()
{
  return ::vapi_msg_id_ip_punt_redirect_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_redirect_dump>>()
{
  return ::vapi_msg_id_ip_punt_redirect_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_redirect_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_redirect_dump>(vapi_msg_id_ip_punt_redirect_dump);
}

template <> inline vapi_msg_ip_punt_redirect_dump* vapi_alloc<vapi_msg_ip_punt_redirect_dump>(Connection &con)
{
  vapi_msg_ip_punt_redirect_dump* result = vapi_alloc_ip_punt_redirect_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_punt_redirect_dump>;

template class Dump<vapi_msg_ip_punt_redirect_dump, vapi_msg_ip_punt_redirect_details>;

using Ip_punt_redirect_dump = Dump<vapi_msg_ip_punt_redirect_dump, vapi_msg_ip_punt_redirect_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_redirect_details>(vapi_msg_ip_punt_redirect_details *msg)
{
  vapi_msg_ip_punt_redirect_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_redirect_details>(vapi_msg_ip_punt_redirect_details *msg)
{
  vapi_msg_ip_punt_redirect_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_redirect_details>()
{
  return ::vapi_msg_id_ip_punt_redirect_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_redirect_details>>()
{
  return ::vapi_msg_id_ip_punt_redirect_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_redirect_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_redirect_details>(vapi_msg_id_ip_punt_redirect_details);
}

template class Msg<vapi_msg_ip_punt_redirect_details>;

using Ip_punt_redirect_details = Msg<vapi_msg_ip_punt_redirect_details>;
template <> inline void vapi_swap_to_be<vapi_msg_add_del_ip_punt_redirect_v2>(vapi_msg_add_del_ip_punt_redirect_v2 *msg)
{
  vapi_msg_add_del_ip_punt_redirect_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_add_del_ip_punt_redirect_v2>(vapi_msg_add_del_ip_punt_redirect_v2 *msg)
{
  vapi_msg_add_del_ip_punt_redirect_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_add_del_ip_punt_redirect_v2>()
{
  return ::vapi_msg_id_add_del_ip_punt_redirect_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_add_del_ip_punt_redirect_v2>>()
{
  return ::vapi_msg_id_add_del_ip_punt_redirect_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_add_del_ip_punt_redirect_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_add_del_ip_punt_redirect_v2>(vapi_msg_id_add_del_ip_punt_redirect_v2);
}

template <> inline vapi_msg_add_del_ip_punt_redirect_v2* vapi_alloc<vapi_msg_add_del_ip_punt_redirect_v2, size_t>(Connection &con, size_t punt_paths_array_size)
{
  vapi_msg_add_del_ip_punt_redirect_v2* result = vapi_alloc_add_del_ip_punt_redirect_v2(con.vapi_ctx, punt_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_add_del_ip_punt_redirect_v2>;

template class Request<vapi_msg_add_del_ip_punt_redirect_v2, vapi_msg_add_del_ip_punt_redirect_v2_reply, size_t>;

using Add_del_ip_punt_redirect_v2 = Request<vapi_msg_add_del_ip_punt_redirect_v2, vapi_msg_add_del_ip_punt_redirect_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_add_del_ip_punt_redirect_v2_reply>(vapi_msg_add_del_ip_punt_redirect_v2_reply *msg)
{
  vapi_msg_add_del_ip_punt_redirect_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_add_del_ip_punt_redirect_v2_reply>(vapi_msg_add_del_ip_punt_redirect_v2_reply *msg)
{
  vapi_msg_add_del_ip_punt_redirect_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_add_del_ip_punt_redirect_v2_reply>()
{
  return ::vapi_msg_id_add_del_ip_punt_redirect_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_add_del_ip_punt_redirect_v2_reply>>()
{
  return ::vapi_msg_id_add_del_ip_punt_redirect_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_add_del_ip_punt_redirect_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_add_del_ip_punt_redirect_v2_reply>(vapi_msg_id_add_del_ip_punt_redirect_v2_reply);
}

template class Msg<vapi_msg_add_del_ip_punt_redirect_v2_reply>;

using Add_del_ip_punt_redirect_v2_reply = Msg<vapi_msg_add_del_ip_punt_redirect_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_redirect_v2_dump>(vapi_msg_ip_punt_redirect_v2_dump *msg)
{
  vapi_msg_ip_punt_redirect_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_redirect_v2_dump>(vapi_msg_ip_punt_redirect_v2_dump *msg)
{
  vapi_msg_ip_punt_redirect_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_redirect_v2_dump>()
{
  return ::vapi_msg_id_ip_punt_redirect_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_redirect_v2_dump>>()
{
  return ::vapi_msg_id_ip_punt_redirect_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_redirect_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_redirect_v2_dump>(vapi_msg_id_ip_punt_redirect_v2_dump);
}

template <> inline vapi_msg_ip_punt_redirect_v2_dump* vapi_alloc<vapi_msg_ip_punt_redirect_v2_dump>(Connection &con)
{
  vapi_msg_ip_punt_redirect_v2_dump* result = vapi_alloc_ip_punt_redirect_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_punt_redirect_v2_dump>;

template class Dump<vapi_msg_ip_punt_redirect_v2_dump, vapi_msg_ip_punt_redirect_v2_details>;

using Ip_punt_redirect_v2_dump = Dump<vapi_msg_ip_punt_redirect_v2_dump, vapi_msg_ip_punt_redirect_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_punt_redirect_v2_details>(vapi_msg_ip_punt_redirect_v2_details *msg)
{
  vapi_msg_ip_punt_redirect_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_punt_redirect_v2_details>(vapi_msg_ip_punt_redirect_v2_details *msg)
{
  vapi_msg_ip_punt_redirect_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_punt_redirect_v2_details>()
{
  return ::vapi_msg_id_ip_punt_redirect_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_punt_redirect_v2_details>>()
{
  return ::vapi_msg_id_ip_punt_redirect_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_punt_redirect_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_punt_redirect_v2_details>(vapi_msg_id_ip_punt_redirect_v2_details);
}

template class Msg<vapi_msg_ip_punt_redirect_v2_details>;

using Ip_punt_redirect_v2_details = Msg<vapi_msg_ip_punt_redirect_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_container_proxy_add_del>(vapi_msg_ip_container_proxy_add_del *msg)
{
  vapi_msg_ip_container_proxy_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_container_proxy_add_del>(vapi_msg_ip_container_proxy_add_del *msg)
{
  vapi_msg_ip_container_proxy_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_container_proxy_add_del>()
{
  return ::vapi_msg_id_ip_container_proxy_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_container_proxy_add_del>>()
{
  return ::vapi_msg_id_ip_container_proxy_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_container_proxy_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_container_proxy_add_del>(vapi_msg_id_ip_container_proxy_add_del);
}

template <> inline vapi_msg_ip_container_proxy_add_del* vapi_alloc<vapi_msg_ip_container_proxy_add_del>(Connection &con)
{
  vapi_msg_ip_container_proxy_add_del* result = vapi_alloc_ip_container_proxy_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_container_proxy_add_del>;

template class Request<vapi_msg_ip_container_proxy_add_del, vapi_msg_ip_container_proxy_add_del_reply>;

using Ip_container_proxy_add_del = Request<vapi_msg_ip_container_proxy_add_del, vapi_msg_ip_container_proxy_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_container_proxy_add_del_reply>(vapi_msg_ip_container_proxy_add_del_reply *msg)
{
  vapi_msg_ip_container_proxy_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_container_proxy_add_del_reply>(vapi_msg_ip_container_proxy_add_del_reply *msg)
{
  vapi_msg_ip_container_proxy_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_container_proxy_add_del_reply>()
{
  return ::vapi_msg_id_ip_container_proxy_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_container_proxy_add_del_reply>>()
{
  return ::vapi_msg_id_ip_container_proxy_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_container_proxy_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_container_proxy_add_del_reply>(vapi_msg_id_ip_container_proxy_add_del_reply);
}

template class Msg<vapi_msg_ip_container_proxy_add_del_reply>;

using Ip_container_proxy_add_del_reply = Msg<vapi_msg_ip_container_proxy_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_container_proxy_dump>(vapi_msg_ip_container_proxy_dump *msg)
{
  vapi_msg_ip_container_proxy_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_container_proxy_dump>(vapi_msg_ip_container_proxy_dump *msg)
{
  vapi_msg_ip_container_proxy_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_container_proxy_dump>()
{
  return ::vapi_msg_id_ip_container_proxy_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_container_proxy_dump>>()
{
  return ::vapi_msg_id_ip_container_proxy_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_container_proxy_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_container_proxy_dump>(vapi_msg_id_ip_container_proxy_dump);
}

template <> inline vapi_msg_ip_container_proxy_dump* vapi_alloc<vapi_msg_ip_container_proxy_dump>(Connection &con)
{
  vapi_msg_ip_container_proxy_dump* result = vapi_alloc_ip_container_proxy_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_container_proxy_dump>;

template class Dump<vapi_msg_ip_container_proxy_dump, vapi_msg_ip_container_proxy_details>;

using Ip_container_proxy_dump = Dump<vapi_msg_ip_container_proxy_dump, vapi_msg_ip_container_proxy_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_container_proxy_details>(vapi_msg_ip_container_proxy_details *msg)
{
  vapi_msg_ip_container_proxy_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_container_proxy_details>(vapi_msg_ip_container_proxy_details *msg)
{
  vapi_msg_ip_container_proxy_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_container_proxy_details>()
{
  return ::vapi_msg_id_ip_container_proxy_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_container_proxy_details>>()
{
  return ::vapi_msg_id_ip_container_proxy_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_container_proxy_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_container_proxy_details>(vapi_msg_id_ip_container_proxy_details);
}

template class Msg<vapi_msg_ip_container_proxy_details>;

using Ip_container_proxy_details = Msg<vapi_msg_ip_container_proxy_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_source_and_port_range_check_add_del>(vapi_msg_ip_source_and_port_range_check_add_del *msg)
{
  vapi_msg_ip_source_and_port_range_check_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_source_and_port_range_check_add_del>(vapi_msg_ip_source_and_port_range_check_add_del *msg)
{
  vapi_msg_ip_source_and_port_range_check_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_source_and_port_range_check_add_del>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_source_and_port_range_check_add_del>>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_source_and_port_range_check_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_source_and_port_range_check_add_del>(vapi_msg_id_ip_source_and_port_range_check_add_del);
}

template <> inline vapi_msg_ip_source_and_port_range_check_add_del* vapi_alloc<vapi_msg_ip_source_and_port_range_check_add_del>(Connection &con)
{
  vapi_msg_ip_source_and_port_range_check_add_del* result = vapi_alloc_ip_source_and_port_range_check_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_source_and_port_range_check_add_del>;

template class Request<vapi_msg_ip_source_and_port_range_check_add_del, vapi_msg_ip_source_and_port_range_check_add_del_reply>;

using Ip_source_and_port_range_check_add_del = Request<vapi_msg_ip_source_and_port_range_check_add_del, vapi_msg_ip_source_and_port_range_check_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_source_and_port_range_check_add_del_reply>(vapi_msg_ip_source_and_port_range_check_add_del_reply *msg)
{
  vapi_msg_ip_source_and_port_range_check_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_source_and_port_range_check_add_del_reply>(vapi_msg_ip_source_and_port_range_check_add_del_reply *msg)
{
  vapi_msg_ip_source_and_port_range_check_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_source_and_port_range_check_add_del_reply>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_source_and_port_range_check_add_del_reply>>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_source_and_port_range_check_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_source_and_port_range_check_add_del_reply>(vapi_msg_id_ip_source_and_port_range_check_add_del_reply);
}

template class Msg<vapi_msg_ip_source_and_port_range_check_add_del_reply>;

using Ip_source_and_port_range_check_add_del_reply = Msg<vapi_msg_ip_source_and_port_range_check_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_source_and_port_range_check_interface_add_del>(vapi_msg_ip_source_and_port_range_check_interface_add_del *msg)
{
  vapi_msg_ip_source_and_port_range_check_interface_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_source_and_port_range_check_interface_add_del>(vapi_msg_ip_source_and_port_range_check_interface_add_del *msg)
{
  vapi_msg_ip_source_and_port_range_check_interface_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_source_and_port_range_check_interface_add_del>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_interface_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_source_and_port_range_check_interface_add_del>>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_interface_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_source_and_port_range_check_interface_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_source_and_port_range_check_interface_add_del>(vapi_msg_id_ip_source_and_port_range_check_interface_add_del);
}

template <> inline vapi_msg_ip_source_and_port_range_check_interface_add_del* vapi_alloc<vapi_msg_ip_source_and_port_range_check_interface_add_del>(Connection &con)
{
  vapi_msg_ip_source_and_port_range_check_interface_add_del* result = vapi_alloc_ip_source_and_port_range_check_interface_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_source_and_port_range_check_interface_add_del>;

template class Request<vapi_msg_ip_source_and_port_range_check_interface_add_del, vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>;

using Ip_source_and_port_range_check_interface_add_del = Request<vapi_msg_ip_source_and_port_range_check_interface_add_del, vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply *msg)
{
  vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>(vapi_msg_ip_source_and_port_range_check_interface_add_del_reply *msg)
{
  vapi_msg_ip_source_and_port_range_check_interface_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>>()
{
  return ::vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_source_and_port_range_check_interface_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>(vapi_msg_id_ip_source_and_port_range_check_interface_add_del_reply);
}

template class Msg<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>;

using Ip_source_and_port_range_check_interface_add_del_reply = Msg<vapi_msg_ip_source_and_port_range_check_interface_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6_set_link_local_address>(vapi_msg_sw_interface_ip6_set_link_local_address *msg)
{
  vapi_msg_sw_interface_ip6_set_link_local_address_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6_set_link_local_address>(vapi_msg_sw_interface_ip6_set_link_local_address *msg)
{
  vapi_msg_sw_interface_ip6_set_link_local_address_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6_set_link_local_address>()
{
  return ::vapi_msg_id_sw_interface_ip6_set_link_local_address; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6_set_link_local_address>>()
{
  return ::vapi_msg_id_sw_interface_ip6_set_link_local_address; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6_set_link_local_address()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6_set_link_local_address>(vapi_msg_id_sw_interface_ip6_set_link_local_address);
}

template <> inline vapi_msg_sw_interface_ip6_set_link_local_address* vapi_alloc<vapi_msg_sw_interface_ip6_set_link_local_address>(Connection &con)
{
  vapi_msg_sw_interface_ip6_set_link_local_address* result = vapi_alloc_sw_interface_ip6_set_link_local_address(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip6_set_link_local_address>;

template class Request<vapi_msg_sw_interface_ip6_set_link_local_address, vapi_msg_sw_interface_ip6_set_link_local_address_reply>;

using Sw_interface_ip6_set_link_local_address = Request<vapi_msg_sw_interface_ip6_set_link_local_address, vapi_msg_sw_interface_ip6_set_link_local_address_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6_set_link_local_address_reply>(vapi_msg_sw_interface_ip6_set_link_local_address_reply *msg)
{
  vapi_msg_sw_interface_ip6_set_link_local_address_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6_set_link_local_address_reply>(vapi_msg_sw_interface_ip6_set_link_local_address_reply *msg)
{
  vapi_msg_sw_interface_ip6_set_link_local_address_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6_set_link_local_address_reply>()
{
  return ::vapi_msg_id_sw_interface_ip6_set_link_local_address_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6_set_link_local_address_reply>>()
{
  return ::vapi_msg_id_sw_interface_ip6_set_link_local_address_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6_set_link_local_address_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6_set_link_local_address_reply>(vapi_msg_id_sw_interface_ip6_set_link_local_address_reply);
}

template class Msg<vapi_msg_sw_interface_ip6_set_link_local_address_reply>;

using Sw_interface_ip6_set_link_local_address_reply = Msg<vapi_msg_sw_interface_ip6_set_link_local_address_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6_get_link_local_address>(vapi_msg_sw_interface_ip6_get_link_local_address *msg)
{
  vapi_msg_sw_interface_ip6_get_link_local_address_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6_get_link_local_address>(vapi_msg_sw_interface_ip6_get_link_local_address *msg)
{
  vapi_msg_sw_interface_ip6_get_link_local_address_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6_get_link_local_address>()
{
  return ::vapi_msg_id_sw_interface_ip6_get_link_local_address; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6_get_link_local_address>>()
{
  return ::vapi_msg_id_sw_interface_ip6_get_link_local_address; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6_get_link_local_address()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6_get_link_local_address>(vapi_msg_id_sw_interface_ip6_get_link_local_address);
}

template <> inline vapi_msg_sw_interface_ip6_get_link_local_address* vapi_alloc<vapi_msg_sw_interface_ip6_get_link_local_address>(Connection &con)
{
  vapi_msg_sw_interface_ip6_get_link_local_address* result = vapi_alloc_sw_interface_ip6_get_link_local_address(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_ip6_get_link_local_address>;

template class Request<vapi_msg_sw_interface_ip6_get_link_local_address, vapi_msg_sw_interface_ip6_get_link_local_address_reply>;

using Sw_interface_ip6_get_link_local_address = Request<vapi_msg_sw_interface_ip6_get_link_local_address, vapi_msg_sw_interface_ip6_get_link_local_address_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_ip6_get_link_local_address_reply>(vapi_msg_sw_interface_ip6_get_link_local_address_reply *msg)
{
  vapi_msg_sw_interface_ip6_get_link_local_address_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_ip6_get_link_local_address_reply>(vapi_msg_sw_interface_ip6_get_link_local_address_reply *msg)
{
  vapi_msg_sw_interface_ip6_get_link_local_address_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_ip6_get_link_local_address_reply>()
{
  return ::vapi_msg_id_sw_interface_ip6_get_link_local_address_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_ip6_get_link_local_address_reply>>()
{
  return ::vapi_msg_id_sw_interface_ip6_get_link_local_address_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_ip6_get_link_local_address_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_ip6_get_link_local_address_reply>(vapi_msg_id_sw_interface_ip6_get_link_local_address_reply);
}

template class Msg<vapi_msg_sw_interface_ip6_get_link_local_address_reply>;

using Sw_interface_ip6_get_link_local_address_reply = Msg<vapi_msg_sw_interface_ip6_get_link_local_address_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ioam_enable>(vapi_msg_ioam_enable *msg)
{
  vapi_msg_ioam_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ioam_enable>(vapi_msg_ioam_enable *msg)
{
  vapi_msg_ioam_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ioam_enable>()
{
  return ::vapi_msg_id_ioam_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ioam_enable>>()
{
  return ::vapi_msg_id_ioam_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ioam_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ioam_enable>(vapi_msg_id_ioam_enable);
}

template <> inline vapi_msg_ioam_enable* vapi_alloc<vapi_msg_ioam_enable>(Connection &con)
{
  vapi_msg_ioam_enable* result = vapi_alloc_ioam_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ioam_enable>;

template class Request<vapi_msg_ioam_enable, vapi_msg_ioam_enable_reply>;

using Ioam_enable = Request<vapi_msg_ioam_enable, vapi_msg_ioam_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ioam_enable_reply>(vapi_msg_ioam_enable_reply *msg)
{
  vapi_msg_ioam_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ioam_enable_reply>(vapi_msg_ioam_enable_reply *msg)
{
  vapi_msg_ioam_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ioam_enable_reply>()
{
  return ::vapi_msg_id_ioam_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ioam_enable_reply>>()
{
  return ::vapi_msg_id_ioam_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ioam_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ioam_enable_reply>(vapi_msg_id_ioam_enable_reply);
}

template class Msg<vapi_msg_ioam_enable_reply>;

using Ioam_enable_reply = Msg<vapi_msg_ioam_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ioam_disable>(vapi_msg_ioam_disable *msg)
{
  vapi_msg_ioam_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ioam_disable>(vapi_msg_ioam_disable *msg)
{
  vapi_msg_ioam_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ioam_disable>()
{
  return ::vapi_msg_id_ioam_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ioam_disable>>()
{
  return ::vapi_msg_id_ioam_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ioam_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ioam_disable>(vapi_msg_id_ioam_disable);
}

template <> inline vapi_msg_ioam_disable* vapi_alloc<vapi_msg_ioam_disable>(Connection &con)
{
  vapi_msg_ioam_disable* result = vapi_alloc_ioam_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ioam_disable>;

template class Request<vapi_msg_ioam_disable, vapi_msg_ioam_disable_reply>;

using Ioam_disable = Request<vapi_msg_ioam_disable, vapi_msg_ioam_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ioam_disable_reply>(vapi_msg_ioam_disable_reply *msg)
{
  vapi_msg_ioam_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ioam_disable_reply>(vapi_msg_ioam_disable_reply *msg)
{
  vapi_msg_ioam_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ioam_disable_reply>()
{
  return ::vapi_msg_id_ioam_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ioam_disable_reply>>()
{
  return ::vapi_msg_id_ioam_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ioam_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ioam_disable_reply>(vapi_msg_id_ioam_disable_reply);
}

template class Msg<vapi_msg_ioam_disable_reply>;

using Ioam_disable_reply = Msg<vapi_msg_ioam_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_reassembly_set>(vapi_msg_ip_reassembly_set *msg)
{
  vapi_msg_ip_reassembly_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_reassembly_set>(vapi_msg_ip_reassembly_set *msg)
{
  vapi_msg_ip_reassembly_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_reassembly_set>()
{
  return ::vapi_msg_id_ip_reassembly_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_reassembly_set>>()
{
  return ::vapi_msg_id_ip_reassembly_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_reassembly_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_reassembly_set>(vapi_msg_id_ip_reassembly_set);
}

template <> inline vapi_msg_ip_reassembly_set* vapi_alloc<vapi_msg_ip_reassembly_set>(Connection &con)
{
  vapi_msg_ip_reassembly_set* result = vapi_alloc_ip_reassembly_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_reassembly_set>;

template class Request<vapi_msg_ip_reassembly_set, vapi_msg_ip_reassembly_set_reply>;

using Ip_reassembly_set = Request<vapi_msg_ip_reassembly_set, vapi_msg_ip_reassembly_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_reassembly_set_reply>(vapi_msg_ip_reassembly_set_reply *msg)
{
  vapi_msg_ip_reassembly_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_reassembly_set_reply>(vapi_msg_ip_reassembly_set_reply *msg)
{
  vapi_msg_ip_reassembly_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_reassembly_set_reply>()
{
  return ::vapi_msg_id_ip_reassembly_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_reassembly_set_reply>>()
{
  return ::vapi_msg_id_ip_reassembly_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_reassembly_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_reassembly_set_reply>(vapi_msg_id_ip_reassembly_set_reply);
}

template class Msg<vapi_msg_ip_reassembly_set_reply>;

using Ip_reassembly_set_reply = Msg<vapi_msg_ip_reassembly_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_reassembly_get>(vapi_msg_ip_reassembly_get *msg)
{
  vapi_msg_ip_reassembly_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_reassembly_get>(vapi_msg_ip_reassembly_get *msg)
{
  vapi_msg_ip_reassembly_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_reassembly_get>()
{
  return ::vapi_msg_id_ip_reassembly_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_reassembly_get>>()
{
  return ::vapi_msg_id_ip_reassembly_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_reassembly_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_reassembly_get>(vapi_msg_id_ip_reassembly_get);
}

template <> inline vapi_msg_ip_reassembly_get* vapi_alloc<vapi_msg_ip_reassembly_get>(Connection &con)
{
  vapi_msg_ip_reassembly_get* result = vapi_alloc_ip_reassembly_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_reassembly_get>;

template class Request<vapi_msg_ip_reassembly_get, vapi_msg_ip_reassembly_get_reply>;

using Ip_reassembly_get = Request<vapi_msg_ip_reassembly_get, vapi_msg_ip_reassembly_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_reassembly_get_reply>(vapi_msg_ip_reassembly_get_reply *msg)
{
  vapi_msg_ip_reassembly_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_reassembly_get_reply>(vapi_msg_ip_reassembly_get_reply *msg)
{
  vapi_msg_ip_reassembly_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_reassembly_get_reply>()
{
  return ::vapi_msg_id_ip_reassembly_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_reassembly_get_reply>>()
{
  return ::vapi_msg_id_ip_reassembly_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_reassembly_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_reassembly_get_reply>(vapi_msg_id_ip_reassembly_get_reply);
}

template class Msg<vapi_msg_ip_reassembly_get_reply>;

using Ip_reassembly_get_reply = Msg<vapi_msg_ip_reassembly_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_reassembly_enable_disable>(vapi_msg_ip_reassembly_enable_disable *msg)
{
  vapi_msg_ip_reassembly_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_reassembly_enable_disable>(vapi_msg_ip_reassembly_enable_disable *msg)
{
  vapi_msg_ip_reassembly_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_reassembly_enable_disable>()
{
  return ::vapi_msg_id_ip_reassembly_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_reassembly_enable_disable>>()
{
  return ::vapi_msg_id_ip_reassembly_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_reassembly_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_reassembly_enable_disable>(vapi_msg_id_ip_reassembly_enable_disable);
}

template <> inline vapi_msg_ip_reassembly_enable_disable* vapi_alloc<vapi_msg_ip_reassembly_enable_disable>(Connection &con)
{
  vapi_msg_ip_reassembly_enable_disable* result = vapi_alloc_ip_reassembly_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_reassembly_enable_disable>;

template class Request<vapi_msg_ip_reassembly_enable_disable, vapi_msg_ip_reassembly_enable_disable_reply>;

using Ip_reassembly_enable_disable = Request<vapi_msg_ip_reassembly_enable_disable, vapi_msg_ip_reassembly_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_reassembly_enable_disable_reply>(vapi_msg_ip_reassembly_enable_disable_reply *msg)
{
  vapi_msg_ip_reassembly_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_reassembly_enable_disable_reply>(vapi_msg_ip_reassembly_enable_disable_reply *msg)
{
  vapi_msg_ip_reassembly_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_reassembly_enable_disable_reply>()
{
  return ::vapi_msg_id_ip_reassembly_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_reassembly_enable_disable_reply>>()
{
  return ::vapi_msg_id_ip_reassembly_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_reassembly_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_reassembly_enable_disable_reply>(vapi_msg_id_ip_reassembly_enable_disable_reply);
}

template class Msg<vapi_msg_ip_reassembly_enable_disable_reply>;

using Ip_reassembly_enable_disable_reply = Msg<vapi_msg_ip_reassembly_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_local_reass_enable_disable>(vapi_msg_ip_local_reass_enable_disable *msg)
{
  vapi_msg_ip_local_reass_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_local_reass_enable_disable>(vapi_msg_ip_local_reass_enable_disable *msg)
{
  vapi_msg_ip_local_reass_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_local_reass_enable_disable>()
{
  return ::vapi_msg_id_ip_local_reass_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_local_reass_enable_disable>>()
{
  return ::vapi_msg_id_ip_local_reass_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_local_reass_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_local_reass_enable_disable>(vapi_msg_id_ip_local_reass_enable_disable);
}

template <> inline vapi_msg_ip_local_reass_enable_disable* vapi_alloc<vapi_msg_ip_local_reass_enable_disable>(Connection &con)
{
  vapi_msg_ip_local_reass_enable_disable* result = vapi_alloc_ip_local_reass_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_local_reass_enable_disable>;

template class Request<vapi_msg_ip_local_reass_enable_disable, vapi_msg_ip_local_reass_enable_disable_reply>;

using Ip_local_reass_enable_disable = Request<vapi_msg_ip_local_reass_enable_disable, vapi_msg_ip_local_reass_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_local_reass_enable_disable_reply>(vapi_msg_ip_local_reass_enable_disable_reply *msg)
{
  vapi_msg_ip_local_reass_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_local_reass_enable_disable_reply>(vapi_msg_ip_local_reass_enable_disable_reply *msg)
{
  vapi_msg_ip_local_reass_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_local_reass_enable_disable_reply>()
{
  return ::vapi_msg_id_ip_local_reass_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_local_reass_enable_disable_reply>>()
{
  return ::vapi_msg_id_ip_local_reass_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_local_reass_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_local_reass_enable_disable_reply>(vapi_msg_id_ip_local_reass_enable_disable_reply);
}

template class Msg<vapi_msg_ip_local_reass_enable_disable_reply>;

using Ip_local_reass_enable_disable_reply = Msg<vapi_msg_ip_local_reass_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_local_reass_get>(vapi_msg_ip_local_reass_get *msg)
{
  vapi_msg_ip_local_reass_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_local_reass_get>(vapi_msg_ip_local_reass_get *msg)
{
  vapi_msg_ip_local_reass_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_local_reass_get>()
{
  return ::vapi_msg_id_ip_local_reass_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_local_reass_get>>()
{
  return ::vapi_msg_id_ip_local_reass_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_local_reass_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_local_reass_get>(vapi_msg_id_ip_local_reass_get);
}

template <> inline vapi_msg_ip_local_reass_get* vapi_alloc<vapi_msg_ip_local_reass_get>(Connection &con)
{
  vapi_msg_ip_local_reass_get* result = vapi_alloc_ip_local_reass_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_local_reass_get>;

template class Request<vapi_msg_ip_local_reass_get, vapi_msg_ip_local_reass_get_reply>;

using Ip_local_reass_get = Request<vapi_msg_ip_local_reass_get, vapi_msg_ip_local_reass_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_local_reass_get_reply>(vapi_msg_ip_local_reass_get_reply *msg)
{
  vapi_msg_ip_local_reass_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_local_reass_get_reply>(vapi_msg_ip_local_reass_get_reply *msg)
{
  vapi_msg_ip_local_reass_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_local_reass_get_reply>()
{
  return ::vapi_msg_id_ip_local_reass_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_local_reass_get_reply>>()
{
  return ::vapi_msg_id_ip_local_reass_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_local_reass_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_local_reass_get_reply>(vapi_msg_id_ip_local_reass_get_reply);
}

template class Msg<vapi_msg_ip_local_reass_get_reply>;

using Ip_local_reass_get_reply = Msg<vapi_msg_ip_local_reass_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_update>(vapi_msg_ip_path_mtu_update *msg)
{
  vapi_msg_ip_path_mtu_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_update>(vapi_msg_ip_path_mtu_update *msg)
{
  vapi_msg_ip_path_mtu_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_update>()
{
  return ::vapi_msg_id_ip_path_mtu_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_update>>()
{
  return ::vapi_msg_id_ip_path_mtu_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_update>(vapi_msg_id_ip_path_mtu_update);
}

template <> inline vapi_msg_ip_path_mtu_update* vapi_alloc<vapi_msg_ip_path_mtu_update>(Connection &con)
{
  vapi_msg_ip_path_mtu_update* result = vapi_alloc_ip_path_mtu_update(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_path_mtu_update>;

template class Request<vapi_msg_ip_path_mtu_update, vapi_msg_ip_path_mtu_update_reply>;

using Ip_path_mtu_update = Request<vapi_msg_ip_path_mtu_update, vapi_msg_ip_path_mtu_update_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_update_reply>(vapi_msg_ip_path_mtu_update_reply *msg)
{
  vapi_msg_ip_path_mtu_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_update_reply>(vapi_msg_ip_path_mtu_update_reply *msg)
{
  vapi_msg_ip_path_mtu_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_update_reply>()
{
  return ::vapi_msg_id_ip_path_mtu_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_update_reply>>()
{
  return ::vapi_msg_id_ip_path_mtu_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_update_reply>(vapi_msg_id_ip_path_mtu_update_reply);
}

template class Msg<vapi_msg_ip_path_mtu_update_reply>;

using Ip_path_mtu_update_reply = Msg<vapi_msg_ip_path_mtu_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_get>(vapi_msg_ip_path_mtu_get *msg)
{
  vapi_msg_ip_path_mtu_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_get>(vapi_msg_ip_path_mtu_get *msg)
{
  vapi_msg_ip_path_mtu_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_get>()
{
  return ::vapi_msg_id_ip_path_mtu_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_get>>()
{
  return ::vapi_msg_id_ip_path_mtu_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_get>(vapi_msg_id_ip_path_mtu_get);
}

template <> inline vapi_msg_ip_path_mtu_get* vapi_alloc<vapi_msg_ip_path_mtu_get>(Connection &con)
{
  vapi_msg_ip_path_mtu_get* result = vapi_alloc_ip_path_mtu_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_path_mtu_get>;

template class Stream<vapi_msg_ip_path_mtu_get, vapi_msg_ip_path_mtu_get_reply, vapi_msg_ip_path_mtu_details>;

using Ip_path_mtu_get = Stream<vapi_msg_ip_path_mtu_get, vapi_msg_ip_path_mtu_get_reply, vapi_msg_ip_path_mtu_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_get_reply>(vapi_msg_ip_path_mtu_get_reply *msg)
{
  vapi_msg_ip_path_mtu_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_get_reply>(vapi_msg_ip_path_mtu_get_reply *msg)
{
  vapi_msg_ip_path_mtu_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_get_reply>()
{
  return ::vapi_msg_id_ip_path_mtu_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_get_reply>>()
{
  return ::vapi_msg_id_ip_path_mtu_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_get_reply>(vapi_msg_id_ip_path_mtu_get_reply);
}

template class Msg<vapi_msg_ip_path_mtu_get_reply>;

using Ip_path_mtu_get_reply = Msg<vapi_msg_ip_path_mtu_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_details>(vapi_msg_ip_path_mtu_details *msg)
{
  vapi_msg_ip_path_mtu_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_details>(vapi_msg_ip_path_mtu_details *msg)
{
  vapi_msg_ip_path_mtu_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_details>()
{
  return ::vapi_msg_id_ip_path_mtu_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_details>>()
{
  return ::vapi_msg_id_ip_path_mtu_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_details>(vapi_msg_id_ip_path_mtu_details);
}

template class Msg<vapi_msg_ip_path_mtu_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_replace_begin>(vapi_msg_ip_path_mtu_replace_begin *msg)
{
  vapi_msg_ip_path_mtu_replace_begin_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_replace_begin>(vapi_msg_ip_path_mtu_replace_begin *msg)
{
  vapi_msg_ip_path_mtu_replace_begin_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_replace_begin>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_begin; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_replace_begin>>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_begin; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_replace_begin()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_replace_begin>(vapi_msg_id_ip_path_mtu_replace_begin);
}

template <> inline vapi_msg_ip_path_mtu_replace_begin* vapi_alloc<vapi_msg_ip_path_mtu_replace_begin>(Connection &con)
{
  vapi_msg_ip_path_mtu_replace_begin* result = vapi_alloc_ip_path_mtu_replace_begin(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_path_mtu_replace_begin>;

template class Request<vapi_msg_ip_path_mtu_replace_begin, vapi_msg_ip_path_mtu_replace_begin_reply>;

using Ip_path_mtu_replace_begin = Request<vapi_msg_ip_path_mtu_replace_begin, vapi_msg_ip_path_mtu_replace_begin_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_replace_begin_reply>(vapi_msg_ip_path_mtu_replace_begin_reply *msg)
{
  vapi_msg_ip_path_mtu_replace_begin_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_replace_begin_reply>(vapi_msg_ip_path_mtu_replace_begin_reply *msg)
{
  vapi_msg_ip_path_mtu_replace_begin_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_replace_begin_reply>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_begin_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_replace_begin_reply>>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_begin_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_replace_begin_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_replace_begin_reply>(vapi_msg_id_ip_path_mtu_replace_begin_reply);
}

template class Msg<vapi_msg_ip_path_mtu_replace_begin_reply>;

using Ip_path_mtu_replace_begin_reply = Msg<vapi_msg_ip_path_mtu_replace_begin_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_replace_end>(vapi_msg_ip_path_mtu_replace_end *msg)
{
  vapi_msg_ip_path_mtu_replace_end_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_replace_end>(vapi_msg_ip_path_mtu_replace_end *msg)
{
  vapi_msg_ip_path_mtu_replace_end_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_replace_end>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_end; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_replace_end>>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_end; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_replace_end()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_replace_end>(vapi_msg_id_ip_path_mtu_replace_end);
}

template <> inline vapi_msg_ip_path_mtu_replace_end* vapi_alloc<vapi_msg_ip_path_mtu_replace_end>(Connection &con)
{
  vapi_msg_ip_path_mtu_replace_end* result = vapi_alloc_ip_path_mtu_replace_end(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ip_path_mtu_replace_end>;

template class Request<vapi_msg_ip_path_mtu_replace_end, vapi_msg_ip_path_mtu_replace_end_reply>;

using Ip_path_mtu_replace_end = Request<vapi_msg_ip_path_mtu_replace_end, vapi_msg_ip_path_mtu_replace_end_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ip_path_mtu_replace_end_reply>(vapi_msg_ip_path_mtu_replace_end_reply *msg)
{
  vapi_msg_ip_path_mtu_replace_end_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ip_path_mtu_replace_end_reply>(vapi_msg_ip_path_mtu_replace_end_reply *msg)
{
  vapi_msg_ip_path_mtu_replace_end_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ip_path_mtu_replace_end_reply>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_end_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ip_path_mtu_replace_end_reply>>()
{
  return ::vapi_msg_id_ip_path_mtu_replace_end_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ip_path_mtu_replace_end_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ip_path_mtu_replace_end_reply>(vapi_msg_id_ip_path_mtu_replace_end_reply);
}

template class Msg<vapi_msg_ip_path_mtu_replace_end_reply>;

using Ip_path_mtu_replace_end_reply = Msg<vapi_msg_ip_path_mtu_replace_end_reply>;
}
#endif
