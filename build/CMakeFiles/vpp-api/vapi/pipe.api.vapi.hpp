#ifndef __included_hpp_pipe_api_json
#define __included_hpp_pipe_api_json

#include <vapi/vapi.hpp>
#include <vapi/pipe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_pipe_create>(vapi_msg_pipe_create *msg)
{
  vapi_msg_pipe_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pipe_create>(vapi_msg_pipe_create *msg)
{
  vapi_msg_pipe_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pipe_create>()
{
  return ::vapi_msg_id_pipe_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pipe_create>>()
{
  return ::vapi_msg_id_pipe_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pipe_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pipe_create>(vapi_msg_id_pipe_create);
}

template <> inline vapi_msg_pipe_create* vapi_alloc<vapi_msg_pipe_create>(Connection &con)
{
  vapi_msg_pipe_create* result = vapi_alloc_pipe_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pipe_create>;

template class Request<vapi_msg_pipe_create, vapi_msg_pipe_create_reply>;

using Pipe_create = Request<vapi_msg_pipe_create, vapi_msg_pipe_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pipe_create_reply>(vapi_msg_pipe_create_reply *msg)
{
  vapi_msg_pipe_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pipe_create_reply>(vapi_msg_pipe_create_reply *msg)
{
  vapi_msg_pipe_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pipe_create_reply>()
{
  return ::vapi_msg_id_pipe_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pipe_create_reply>>()
{
  return ::vapi_msg_id_pipe_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pipe_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pipe_create_reply>(vapi_msg_id_pipe_create_reply);
}

template class Msg<vapi_msg_pipe_create_reply>;

using Pipe_create_reply = Msg<vapi_msg_pipe_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pipe_delete>(vapi_msg_pipe_delete *msg)
{
  vapi_msg_pipe_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pipe_delete>(vapi_msg_pipe_delete *msg)
{
  vapi_msg_pipe_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pipe_delete>()
{
  return ::vapi_msg_id_pipe_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pipe_delete>>()
{
  return ::vapi_msg_id_pipe_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pipe_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pipe_delete>(vapi_msg_id_pipe_delete);
}

template <> inline vapi_msg_pipe_delete* vapi_alloc<vapi_msg_pipe_delete>(Connection &con)
{
  vapi_msg_pipe_delete* result = vapi_alloc_pipe_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pipe_delete>;

template class Request<vapi_msg_pipe_delete, vapi_msg_pipe_delete_reply>;

using Pipe_delete = Request<vapi_msg_pipe_delete, vapi_msg_pipe_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_pipe_delete_reply>(vapi_msg_pipe_delete_reply *msg)
{
  vapi_msg_pipe_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pipe_delete_reply>(vapi_msg_pipe_delete_reply *msg)
{
  vapi_msg_pipe_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pipe_delete_reply>()
{
  return ::vapi_msg_id_pipe_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pipe_delete_reply>>()
{
  return ::vapi_msg_id_pipe_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pipe_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pipe_delete_reply>(vapi_msg_id_pipe_delete_reply);
}

template class Msg<vapi_msg_pipe_delete_reply>;

using Pipe_delete_reply = Msg<vapi_msg_pipe_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pipe_dump>(vapi_msg_pipe_dump *msg)
{
  vapi_msg_pipe_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pipe_dump>(vapi_msg_pipe_dump *msg)
{
  vapi_msg_pipe_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pipe_dump>()
{
  return ::vapi_msg_id_pipe_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pipe_dump>>()
{
  return ::vapi_msg_id_pipe_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pipe_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pipe_dump>(vapi_msg_id_pipe_dump);
}

template <> inline vapi_msg_pipe_dump* vapi_alloc<vapi_msg_pipe_dump>(Connection &con)
{
  vapi_msg_pipe_dump* result = vapi_alloc_pipe_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pipe_dump>;

template class Dump<vapi_msg_pipe_dump, vapi_msg_pipe_details>;

using Pipe_dump = Dump<vapi_msg_pipe_dump, vapi_msg_pipe_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pipe_details>(vapi_msg_pipe_details *msg)
{
  vapi_msg_pipe_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pipe_details>(vapi_msg_pipe_details *msg)
{
  vapi_msg_pipe_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pipe_details>()
{
  return ::vapi_msg_id_pipe_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pipe_details>>()
{
  return ::vapi_msg_id_pipe_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pipe_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pipe_details>(vapi_msg_id_pipe_details);
}

template class Msg<vapi_msg_pipe_details>;

using Pipe_details = Msg<vapi_msg_pipe_details>;
}
#endif
