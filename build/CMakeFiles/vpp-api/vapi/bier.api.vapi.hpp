#ifndef __included_hpp_bier_api_json
#define __included_hpp_bier_api_json

#include <vapi/vapi.hpp>
#include <vapi/bier.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_bier_table_add_del>(vapi_msg_bier_table_add_del *msg)
{
  vapi_msg_bier_table_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_table_add_del>(vapi_msg_bier_table_add_del *msg)
{
  vapi_msg_bier_table_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_table_add_del>()
{
  return ::vapi_msg_id_bier_table_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_table_add_del>>()
{
  return ::vapi_msg_id_bier_table_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_table_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_table_add_del>(vapi_msg_id_bier_table_add_del);
}

template <> inline vapi_msg_bier_table_add_del* vapi_alloc<vapi_msg_bier_table_add_del>(Connection &con)
{
  vapi_msg_bier_table_add_del* result = vapi_alloc_bier_table_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_table_add_del>;

template class Request<vapi_msg_bier_table_add_del, vapi_msg_bier_table_add_del_reply>;

using Bier_table_add_del = Request<vapi_msg_bier_table_add_del, vapi_msg_bier_table_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_table_add_del_reply>(vapi_msg_bier_table_add_del_reply *msg)
{
  vapi_msg_bier_table_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_table_add_del_reply>(vapi_msg_bier_table_add_del_reply *msg)
{
  vapi_msg_bier_table_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_table_add_del_reply>()
{
  return ::vapi_msg_id_bier_table_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_table_add_del_reply>>()
{
  return ::vapi_msg_id_bier_table_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_table_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_table_add_del_reply>(vapi_msg_id_bier_table_add_del_reply);
}

template class Msg<vapi_msg_bier_table_add_del_reply>;

using Bier_table_add_del_reply = Msg<vapi_msg_bier_table_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_table_dump>(vapi_msg_bier_table_dump *msg)
{
  vapi_msg_bier_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_table_dump>(vapi_msg_bier_table_dump *msg)
{
  vapi_msg_bier_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_table_dump>()
{
  return ::vapi_msg_id_bier_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_table_dump>>()
{
  return ::vapi_msg_id_bier_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_table_dump>(vapi_msg_id_bier_table_dump);
}

template <> inline vapi_msg_bier_table_dump* vapi_alloc<vapi_msg_bier_table_dump>(Connection &con)
{
  vapi_msg_bier_table_dump* result = vapi_alloc_bier_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_table_dump>;

template class Dump<vapi_msg_bier_table_dump, vapi_msg_bier_table_details>;

using Bier_table_dump = Dump<vapi_msg_bier_table_dump, vapi_msg_bier_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_table_details>(vapi_msg_bier_table_details *msg)
{
  vapi_msg_bier_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_table_details>(vapi_msg_bier_table_details *msg)
{
  vapi_msg_bier_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_table_details>()
{
  return ::vapi_msg_id_bier_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_table_details>>()
{
  return ::vapi_msg_id_bier_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_table_details>(vapi_msg_id_bier_table_details);
}

template class Msg<vapi_msg_bier_table_details>;

using Bier_table_details = Msg<vapi_msg_bier_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_route_add_del>(vapi_msg_bier_route_add_del *msg)
{
  vapi_msg_bier_route_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_route_add_del>(vapi_msg_bier_route_add_del *msg)
{
  vapi_msg_bier_route_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_route_add_del>()
{
  return ::vapi_msg_id_bier_route_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_route_add_del>>()
{
  return ::vapi_msg_id_bier_route_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_route_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_route_add_del>(vapi_msg_id_bier_route_add_del);
}

template <> inline vapi_msg_bier_route_add_del* vapi_alloc<vapi_msg_bier_route_add_del, size_t>(Connection &con, size_t br_route_br_paths_array_size)
{
  vapi_msg_bier_route_add_del* result = vapi_alloc_bier_route_add_del(con.vapi_ctx, br_route_br_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_route_add_del>;

template class Request<vapi_msg_bier_route_add_del, vapi_msg_bier_route_add_del_reply, size_t>;

using Bier_route_add_del = Request<vapi_msg_bier_route_add_del, vapi_msg_bier_route_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_route_add_del_reply>(vapi_msg_bier_route_add_del_reply *msg)
{
  vapi_msg_bier_route_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_route_add_del_reply>(vapi_msg_bier_route_add_del_reply *msg)
{
  vapi_msg_bier_route_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_route_add_del_reply>()
{
  return ::vapi_msg_id_bier_route_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_route_add_del_reply>>()
{
  return ::vapi_msg_id_bier_route_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_route_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_route_add_del_reply>(vapi_msg_id_bier_route_add_del_reply);
}

template class Msg<vapi_msg_bier_route_add_del_reply>;

using Bier_route_add_del_reply = Msg<vapi_msg_bier_route_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_route_dump>(vapi_msg_bier_route_dump *msg)
{
  vapi_msg_bier_route_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_route_dump>(vapi_msg_bier_route_dump *msg)
{
  vapi_msg_bier_route_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_route_dump>()
{
  return ::vapi_msg_id_bier_route_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_route_dump>>()
{
  return ::vapi_msg_id_bier_route_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_route_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_route_dump>(vapi_msg_id_bier_route_dump);
}

template <> inline vapi_msg_bier_route_dump* vapi_alloc<vapi_msg_bier_route_dump>(Connection &con)
{
  vapi_msg_bier_route_dump* result = vapi_alloc_bier_route_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_route_dump>;

template class Dump<vapi_msg_bier_route_dump, vapi_msg_bier_route_details>;

using Bier_route_dump = Dump<vapi_msg_bier_route_dump, vapi_msg_bier_route_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_route_details>(vapi_msg_bier_route_details *msg)
{
  vapi_msg_bier_route_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_route_details>(vapi_msg_bier_route_details *msg)
{
  vapi_msg_bier_route_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_route_details>()
{
  return ::vapi_msg_id_bier_route_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_route_details>>()
{
  return ::vapi_msg_id_bier_route_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_route_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_route_details>(vapi_msg_id_bier_route_details);
}

template class Msg<vapi_msg_bier_route_details>;

using Bier_route_details = Msg<vapi_msg_bier_route_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_imp_add>(vapi_msg_bier_imp_add *msg)
{
  vapi_msg_bier_imp_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_imp_add>(vapi_msg_bier_imp_add *msg)
{
  vapi_msg_bier_imp_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_imp_add>()
{
  return ::vapi_msg_id_bier_imp_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_imp_add>>()
{
  return ::vapi_msg_id_bier_imp_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_imp_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_imp_add>(vapi_msg_id_bier_imp_add);
}

template <> inline vapi_msg_bier_imp_add* vapi_alloc<vapi_msg_bier_imp_add, size_t>(Connection &con, size_t _bi_bytes_array_size)
{
  vapi_msg_bier_imp_add* result = vapi_alloc_bier_imp_add(con.vapi_ctx, _bi_bytes_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_imp_add>;

template class Request<vapi_msg_bier_imp_add, vapi_msg_bier_imp_add_reply, size_t>;

using Bier_imp_add = Request<vapi_msg_bier_imp_add, vapi_msg_bier_imp_add_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_imp_add_reply>(vapi_msg_bier_imp_add_reply *msg)
{
  vapi_msg_bier_imp_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_imp_add_reply>(vapi_msg_bier_imp_add_reply *msg)
{
  vapi_msg_bier_imp_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_imp_add_reply>()
{
  return ::vapi_msg_id_bier_imp_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_imp_add_reply>>()
{
  return ::vapi_msg_id_bier_imp_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_imp_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_imp_add_reply>(vapi_msg_id_bier_imp_add_reply);
}

template class Msg<vapi_msg_bier_imp_add_reply>;

using Bier_imp_add_reply = Msg<vapi_msg_bier_imp_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_imp_del>(vapi_msg_bier_imp_del *msg)
{
  vapi_msg_bier_imp_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_imp_del>(vapi_msg_bier_imp_del *msg)
{
  vapi_msg_bier_imp_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_imp_del>()
{
  return ::vapi_msg_id_bier_imp_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_imp_del>>()
{
  return ::vapi_msg_id_bier_imp_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_imp_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_imp_del>(vapi_msg_id_bier_imp_del);
}

template <> inline vapi_msg_bier_imp_del* vapi_alloc<vapi_msg_bier_imp_del>(Connection &con)
{
  vapi_msg_bier_imp_del* result = vapi_alloc_bier_imp_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_imp_del>;

template class Request<vapi_msg_bier_imp_del, vapi_msg_bier_imp_del_reply>;

using Bier_imp_del = Request<vapi_msg_bier_imp_del, vapi_msg_bier_imp_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_imp_del_reply>(vapi_msg_bier_imp_del_reply *msg)
{
  vapi_msg_bier_imp_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_imp_del_reply>(vapi_msg_bier_imp_del_reply *msg)
{
  vapi_msg_bier_imp_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_imp_del_reply>()
{
  return ::vapi_msg_id_bier_imp_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_imp_del_reply>>()
{
  return ::vapi_msg_id_bier_imp_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_imp_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_imp_del_reply>(vapi_msg_id_bier_imp_del_reply);
}

template class Msg<vapi_msg_bier_imp_del_reply>;

using Bier_imp_del_reply = Msg<vapi_msg_bier_imp_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_imp_dump>(vapi_msg_bier_imp_dump *msg)
{
  vapi_msg_bier_imp_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_imp_dump>(vapi_msg_bier_imp_dump *msg)
{
  vapi_msg_bier_imp_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_imp_dump>()
{
  return ::vapi_msg_id_bier_imp_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_imp_dump>>()
{
  return ::vapi_msg_id_bier_imp_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_imp_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_imp_dump>(vapi_msg_id_bier_imp_dump);
}

template <> inline vapi_msg_bier_imp_dump* vapi_alloc<vapi_msg_bier_imp_dump>(Connection &con)
{
  vapi_msg_bier_imp_dump* result = vapi_alloc_bier_imp_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_imp_dump>;

template class Dump<vapi_msg_bier_imp_dump, vapi_msg_bier_imp_details>;

using Bier_imp_dump = Dump<vapi_msg_bier_imp_dump, vapi_msg_bier_imp_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_imp_details>(vapi_msg_bier_imp_details *msg)
{
  vapi_msg_bier_imp_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_imp_details>(vapi_msg_bier_imp_details *msg)
{
  vapi_msg_bier_imp_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_imp_details>()
{
  return ::vapi_msg_id_bier_imp_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_imp_details>>()
{
  return ::vapi_msg_id_bier_imp_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_imp_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_imp_details>(vapi_msg_id_bier_imp_details);
}

template class Msg<vapi_msg_bier_imp_details>;

using Bier_imp_details = Msg<vapi_msg_bier_imp_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_table_add_del>(vapi_msg_bier_disp_table_add_del *msg)
{
  vapi_msg_bier_disp_table_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_table_add_del>(vapi_msg_bier_disp_table_add_del *msg)
{
  vapi_msg_bier_disp_table_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_table_add_del>()
{
  return ::vapi_msg_id_bier_disp_table_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_table_add_del>>()
{
  return ::vapi_msg_id_bier_disp_table_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_table_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_table_add_del>(vapi_msg_id_bier_disp_table_add_del);
}

template <> inline vapi_msg_bier_disp_table_add_del* vapi_alloc<vapi_msg_bier_disp_table_add_del>(Connection &con)
{
  vapi_msg_bier_disp_table_add_del* result = vapi_alloc_bier_disp_table_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_disp_table_add_del>;

template class Request<vapi_msg_bier_disp_table_add_del, vapi_msg_bier_disp_table_add_del_reply>;

using Bier_disp_table_add_del = Request<vapi_msg_bier_disp_table_add_del, vapi_msg_bier_disp_table_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_table_add_del_reply>(vapi_msg_bier_disp_table_add_del_reply *msg)
{
  vapi_msg_bier_disp_table_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_table_add_del_reply>(vapi_msg_bier_disp_table_add_del_reply *msg)
{
  vapi_msg_bier_disp_table_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_table_add_del_reply>()
{
  return ::vapi_msg_id_bier_disp_table_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_table_add_del_reply>>()
{
  return ::vapi_msg_id_bier_disp_table_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_table_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_table_add_del_reply>(vapi_msg_id_bier_disp_table_add_del_reply);
}

template class Msg<vapi_msg_bier_disp_table_add_del_reply>;

using Bier_disp_table_add_del_reply = Msg<vapi_msg_bier_disp_table_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_table_dump>(vapi_msg_bier_disp_table_dump *msg)
{
  vapi_msg_bier_disp_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_table_dump>(vapi_msg_bier_disp_table_dump *msg)
{
  vapi_msg_bier_disp_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_table_dump>()
{
  return ::vapi_msg_id_bier_disp_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_table_dump>>()
{
  return ::vapi_msg_id_bier_disp_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_table_dump>(vapi_msg_id_bier_disp_table_dump);
}

template <> inline vapi_msg_bier_disp_table_dump* vapi_alloc<vapi_msg_bier_disp_table_dump>(Connection &con)
{
  vapi_msg_bier_disp_table_dump* result = vapi_alloc_bier_disp_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_disp_table_dump>;

template class Dump<vapi_msg_bier_disp_table_dump, vapi_msg_bier_disp_table_details>;

using Bier_disp_table_dump = Dump<vapi_msg_bier_disp_table_dump, vapi_msg_bier_disp_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_table_details>(vapi_msg_bier_disp_table_details *msg)
{
  vapi_msg_bier_disp_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_table_details>(vapi_msg_bier_disp_table_details *msg)
{
  vapi_msg_bier_disp_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_table_details>()
{
  return ::vapi_msg_id_bier_disp_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_table_details>>()
{
  return ::vapi_msg_id_bier_disp_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_table_details>(vapi_msg_id_bier_disp_table_details);
}

template class Msg<vapi_msg_bier_disp_table_details>;

using Bier_disp_table_details = Msg<vapi_msg_bier_disp_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_entry_add_del>(vapi_msg_bier_disp_entry_add_del *msg)
{
  vapi_msg_bier_disp_entry_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_entry_add_del>(vapi_msg_bier_disp_entry_add_del *msg)
{
  vapi_msg_bier_disp_entry_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_entry_add_del>()
{
  return ::vapi_msg_id_bier_disp_entry_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_entry_add_del>>()
{
  return ::vapi_msg_id_bier_disp_entry_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_entry_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_entry_add_del>(vapi_msg_id_bier_disp_entry_add_del);
}

template <> inline vapi_msg_bier_disp_entry_add_del* vapi_alloc<vapi_msg_bier_disp_entry_add_del, size_t>(Connection &con, size_t _bde_paths_array_size)
{
  vapi_msg_bier_disp_entry_add_del* result = vapi_alloc_bier_disp_entry_add_del(con.vapi_ctx, _bde_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_disp_entry_add_del>;

template class Request<vapi_msg_bier_disp_entry_add_del, vapi_msg_bier_disp_entry_add_del_reply, size_t>;

using Bier_disp_entry_add_del = Request<vapi_msg_bier_disp_entry_add_del, vapi_msg_bier_disp_entry_add_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_entry_add_del_reply>(vapi_msg_bier_disp_entry_add_del_reply *msg)
{
  vapi_msg_bier_disp_entry_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_entry_add_del_reply>(vapi_msg_bier_disp_entry_add_del_reply *msg)
{
  vapi_msg_bier_disp_entry_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_entry_add_del_reply>()
{
  return ::vapi_msg_id_bier_disp_entry_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_entry_add_del_reply>>()
{
  return ::vapi_msg_id_bier_disp_entry_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_entry_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_entry_add_del_reply>(vapi_msg_id_bier_disp_entry_add_del_reply);
}

template class Msg<vapi_msg_bier_disp_entry_add_del_reply>;

using Bier_disp_entry_add_del_reply = Msg<vapi_msg_bier_disp_entry_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_entry_dump>(vapi_msg_bier_disp_entry_dump *msg)
{
  vapi_msg_bier_disp_entry_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_entry_dump>(vapi_msg_bier_disp_entry_dump *msg)
{
  vapi_msg_bier_disp_entry_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_entry_dump>()
{
  return ::vapi_msg_id_bier_disp_entry_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_entry_dump>>()
{
  return ::vapi_msg_id_bier_disp_entry_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_entry_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_entry_dump>(vapi_msg_id_bier_disp_entry_dump);
}

template <> inline vapi_msg_bier_disp_entry_dump* vapi_alloc<vapi_msg_bier_disp_entry_dump>(Connection &con)
{
  vapi_msg_bier_disp_entry_dump* result = vapi_alloc_bier_disp_entry_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bier_disp_entry_dump>;

template class Dump<vapi_msg_bier_disp_entry_dump, vapi_msg_bier_disp_entry_details>;

using Bier_disp_entry_dump = Dump<vapi_msg_bier_disp_entry_dump, vapi_msg_bier_disp_entry_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bier_disp_entry_details>(vapi_msg_bier_disp_entry_details *msg)
{
  vapi_msg_bier_disp_entry_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bier_disp_entry_details>(vapi_msg_bier_disp_entry_details *msg)
{
  vapi_msg_bier_disp_entry_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bier_disp_entry_details>()
{
  return ::vapi_msg_id_bier_disp_entry_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bier_disp_entry_details>>()
{
  return ::vapi_msg_id_bier_disp_entry_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bier_disp_entry_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bier_disp_entry_details>(vapi_msg_id_bier_disp_entry_details);
}

template class Msg<vapi_msg_bier_disp_entry_details>;

using Bier_disp_entry_details = Msg<vapi_msg_bier_disp_entry_details>;
}
#endif
