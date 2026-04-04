#ifndef __included_hpp_memif_api_json
#define __included_hpp_memif_api_json

#include <vapi/vapi.hpp>
#include <vapi/memif.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_memif_socket_filename_add_del>(vapi_msg_memif_socket_filename_add_del *msg)
{
  vapi_msg_memif_socket_filename_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_socket_filename_add_del>(vapi_msg_memif_socket_filename_add_del *msg)
{
  vapi_msg_memif_socket_filename_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_socket_filename_add_del>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_socket_filename_add_del>>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_socket_filename_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_socket_filename_add_del>(vapi_msg_id_memif_socket_filename_add_del);
}

template <> inline vapi_msg_memif_socket_filename_add_del* vapi_alloc<vapi_msg_memif_socket_filename_add_del>(Connection &con)
{
  vapi_msg_memif_socket_filename_add_del* result = vapi_alloc_memif_socket_filename_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_socket_filename_add_del>;

template class Request<vapi_msg_memif_socket_filename_add_del, vapi_msg_memif_socket_filename_add_del_reply>;

using Memif_socket_filename_add_del = Request<vapi_msg_memif_socket_filename_add_del, vapi_msg_memif_socket_filename_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memif_socket_filename_add_del_reply>(vapi_msg_memif_socket_filename_add_del_reply *msg)
{
  vapi_msg_memif_socket_filename_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_socket_filename_add_del_reply>(vapi_msg_memif_socket_filename_add_del_reply *msg)
{
  vapi_msg_memif_socket_filename_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_socket_filename_add_del_reply>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_socket_filename_add_del_reply>>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_socket_filename_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_socket_filename_add_del_reply>(vapi_msg_id_memif_socket_filename_add_del_reply);
}

template class Msg<vapi_msg_memif_socket_filename_add_del_reply>;

using Memif_socket_filename_add_del_reply = Msg<vapi_msg_memif_socket_filename_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_socket_filename_add_del_v2>(vapi_msg_memif_socket_filename_add_del_v2 *msg)
{
  vapi_msg_memif_socket_filename_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_socket_filename_add_del_v2>(vapi_msg_memif_socket_filename_add_del_v2 *msg)
{
  vapi_msg_memif_socket_filename_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_socket_filename_add_del_v2>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_socket_filename_add_del_v2>>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_socket_filename_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_socket_filename_add_del_v2>(vapi_msg_id_memif_socket_filename_add_del_v2);
}

template <> inline vapi_msg_memif_socket_filename_add_del_v2* vapi_alloc<vapi_msg_memif_socket_filename_add_del_v2, size_t>(Connection &con, size_t socket_filename_buf_array_size)
{
  vapi_msg_memif_socket_filename_add_del_v2* result = vapi_alloc_memif_socket_filename_add_del_v2(con.vapi_ctx, socket_filename_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_socket_filename_add_del_v2>;

template class Request<vapi_msg_memif_socket_filename_add_del_v2, vapi_msg_memif_socket_filename_add_del_v2_reply, size_t>;

using Memif_socket_filename_add_del_v2 = Request<vapi_msg_memif_socket_filename_add_del_v2, vapi_msg_memif_socket_filename_add_del_v2_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_memif_socket_filename_add_del_v2_reply>(vapi_msg_memif_socket_filename_add_del_v2_reply *msg)
{
  vapi_msg_memif_socket_filename_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_socket_filename_add_del_v2_reply>(vapi_msg_memif_socket_filename_add_del_v2_reply *msg)
{
  vapi_msg_memif_socket_filename_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_socket_filename_add_del_v2_reply>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_socket_filename_add_del_v2_reply>>()
{
  return ::vapi_msg_id_memif_socket_filename_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_socket_filename_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_socket_filename_add_del_v2_reply>(vapi_msg_id_memif_socket_filename_add_del_v2_reply);
}

template class Msg<vapi_msg_memif_socket_filename_add_del_v2_reply>;

using Memif_socket_filename_add_del_v2_reply = Msg<vapi_msg_memif_socket_filename_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_create>(vapi_msg_memif_create *msg)
{
  vapi_msg_memif_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_create>(vapi_msg_memif_create *msg)
{
  vapi_msg_memif_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_create>()
{
  return ::vapi_msg_id_memif_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_create>>()
{
  return ::vapi_msg_id_memif_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_create>(vapi_msg_id_memif_create);
}

template <> inline vapi_msg_memif_create* vapi_alloc<vapi_msg_memif_create>(Connection &con)
{
  vapi_msg_memif_create* result = vapi_alloc_memif_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_create>;

template class Request<vapi_msg_memif_create, vapi_msg_memif_create_reply>;

using Memif_create = Request<vapi_msg_memif_create, vapi_msg_memif_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memif_create_reply>(vapi_msg_memif_create_reply *msg)
{
  vapi_msg_memif_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_create_reply>(vapi_msg_memif_create_reply *msg)
{
  vapi_msg_memif_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_create_reply>()
{
  return ::vapi_msg_id_memif_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_create_reply>>()
{
  return ::vapi_msg_id_memif_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_create_reply>(vapi_msg_id_memif_create_reply);
}

template class Msg<vapi_msg_memif_create_reply>;

using Memif_create_reply = Msg<vapi_msg_memif_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_create_v2>(vapi_msg_memif_create_v2 *msg)
{
  vapi_msg_memif_create_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_create_v2>(vapi_msg_memif_create_v2 *msg)
{
  vapi_msg_memif_create_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_create_v2>()
{
  return ::vapi_msg_id_memif_create_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_create_v2>>()
{
  return ::vapi_msg_id_memif_create_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_create_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_create_v2>(vapi_msg_id_memif_create_v2);
}

template <> inline vapi_msg_memif_create_v2* vapi_alloc<vapi_msg_memif_create_v2>(Connection &con)
{
  vapi_msg_memif_create_v2* result = vapi_alloc_memif_create_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_create_v2>;

template class Request<vapi_msg_memif_create_v2, vapi_msg_memif_create_v2_reply>;

using Memif_create_v2 = Request<vapi_msg_memif_create_v2, vapi_msg_memif_create_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memif_create_v2_reply>(vapi_msg_memif_create_v2_reply *msg)
{
  vapi_msg_memif_create_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_create_v2_reply>(vapi_msg_memif_create_v2_reply *msg)
{
  vapi_msg_memif_create_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_create_v2_reply>()
{
  return ::vapi_msg_id_memif_create_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_create_v2_reply>>()
{
  return ::vapi_msg_id_memif_create_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_create_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_create_v2_reply>(vapi_msg_id_memif_create_v2_reply);
}

template class Msg<vapi_msg_memif_create_v2_reply>;

using Memif_create_v2_reply = Msg<vapi_msg_memif_create_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_delete>(vapi_msg_memif_delete *msg)
{
  vapi_msg_memif_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_delete>(vapi_msg_memif_delete *msg)
{
  vapi_msg_memif_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_delete>()
{
  return ::vapi_msg_id_memif_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_delete>>()
{
  return ::vapi_msg_id_memif_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_delete>(vapi_msg_id_memif_delete);
}

template <> inline vapi_msg_memif_delete* vapi_alloc<vapi_msg_memif_delete>(Connection &con)
{
  vapi_msg_memif_delete* result = vapi_alloc_memif_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_delete>;

template class Request<vapi_msg_memif_delete, vapi_msg_memif_delete_reply>;

using Memif_delete = Request<vapi_msg_memif_delete, vapi_msg_memif_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_memif_delete_reply>(vapi_msg_memif_delete_reply *msg)
{
  vapi_msg_memif_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_delete_reply>(vapi_msg_memif_delete_reply *msg)
{
  vapi_msg_memif_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_delete_reply>()
{
  return ::vapi_msg_id_memif_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_delete_reply>>()
{
  return ::vapi_msg_id_memif_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_delete_reply>(vapi_msg_id_memif_delete_reply);
}

template class Msg<vapi_msg_memif_delete_reply>;

using Memif_delete_reply = Msg<vapi_msg_memif_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_socket_filename_details>(vapi_msg_memif_socket_filename_details *msg)
{
  vapi_msg_memif_socket_filename_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_socket_filename_details>(vapi_msg_memif_socket_filename_details *msg)
{
  vapi_msg_memif_socket_filename_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_socket_filename_details>()
{
  return ::vapi_msg_id_memif_socket_filename_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_socket_filename_details>>()
{
  return ::vapi_msg_id_memif_socket_filename_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_socket_filename_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_socket_filename_details>(vapi_msg_id_memif_socket_filename_details);
}

template class Msg<vapi_msg_memif_socket_filename_details>;

using Memif_socket_filename_details = Msg<vapi_msg_memif_socket_filename_details>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_socket_filename_dump>(vapi_msg_memif_socket_filename_dump *msg)
{
  vapi_msg_memif_socket_filename_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_socket_filename_dump>(vapi_msg_memif_socket_filename_dump *msg)
{
  vapi_msg_memif_socket_filename_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_socket_filename_dump>()
{
  return ::vapi_msg_id_memif_socket_filename_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_socket_filename_dump>>()
{
  return ::vapi_msg_id_memif_socket_filename_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_socket_filename_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_socket_filename_dump>(vapi_msg_id_memif_socket_filename_dump);
}

template <> inline vapi_msg_memif_socket_filename_dump* vapi_alloc<vapi_msg_memif_socket_filename_dump>(Connection &con)
{
  vapi_msg_memif_socket_filename_dump* result = vapi_alloc_memif_socket_filename_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_socket_filename_dump>;

template class Dump<vapi_msg_memif_socket_filename_dump, vapi_msg_memif_socket_filename_details>;

using Memif_socket_filename_dump = Dump<vapi_msg_memif_socket_filename_dump, vapi_msg_memif_socket_filename_details>;

template <> inline void vapi_swap_to_be<vapi_msg_memif_details>(vapi_msg_memif_details *msg)
{
  vapi_msg_memif_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_details>(vapi_msg_memif_details *msg)
{
  vapi_msg_memif_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_details>()
{
  return ::vapi_msg_id_memif_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_details>>()
{
  return ::vapi_msg_id_memif_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_details>(vapi_msg_id_memif_details);
}

template class Msg<vapi_msg_memif_details>;

using Memif_details = Msg<vapi_msg_memif_details>;
template <> inline void vapi_swap_to_be<vapi_msg_memif_dump>(vapi_msg_memif_dump *msg)
{
  vapi_msg_memif_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_memif_dump>(vapi_msg_memif_dump *msg)
{
  vapi_msg_memif_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_memif_dump>()
{
  return ::vapi_msg_id_memif_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_memif_dump>>()
{
  return ::vapi_msg_id_memif_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_memif_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_memif_dump>(vapi_msg_id_memif_dump);
}

template <> inline vapi_msg_memif_dump* vapi_alloc<vapi_msg_memif_dump>(Connection &con)
{
  vapi_msg_memif_dump* result = vapi_alloc_memif_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_memif_dump>;

template class Dump<vapi_msg_memif_dump, vapi_msg_memif_details>;

using Memif_dump = Dump<vapi_msg_memif_dump, vapi_msg_memif_details>;

}
#endif
