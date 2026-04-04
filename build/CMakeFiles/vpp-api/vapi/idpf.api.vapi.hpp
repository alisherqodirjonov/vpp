#ifndef __included_hpp_idpf_api_json
#define __included_hpp_idpf_api_json

#include <vapi/vapi.hpp>
#include <vapi/idpf.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_idpf_create>(vapi_msg_idpf_create *msg)
{
  vapi_msg_idpf_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_idpf_create>(vapi_msg_idpf_create *msg)
{
  vapi_msg_idpf_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_idpf_create>()
{
  return ::vapi_msg_id_idpf_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_idpf_create>>()
{
  return ::vapi_msg_id_idpf_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_idpf_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_idpf_create>(vapi_msg_id_idpf_create);
}

template <> inline vapi_msg_idpf_create* vapi_alloc<vapi_msg_idpf_create>(Connection &con)
{
  vapi_msg_idpf_create* result = vapi_alloc_idpf_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_idpf_create>;

template class Request<vapi_msg_idpf_create, vapi_msg_idpf_create_reply>;

using Idpf_create = Request<vapi_msg_idpf_create, vapi_msg_idpf_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_idpf_create_reply>(vapi_msg_idpf_create_reply *msg)
{
  vapi_msg_idpf_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_idpf_create_reply>(vapi_msg_idpf_create_reply *msg)
{
  vapi_msg_idpf_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_idpf_create_reply>()
{
  return ::vapi_msg_id_idpf_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_idpf_create_reply>>()
{
  return ::vapi_msg_id_idpf_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_idpf_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_idpf_create_reply>(vapi_msg_id_idpf_create_reply);
}

template class Msg<vapi_msg_idpf_create_reply>;

using Idpf_create_reply = Msg<vapi_msg_idpf_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_idpf_delete>(vapi_msg_idpf_delete *msg)
{
  vapi_msg_idpf_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_idpf_delete>(vapi_msg_idpf_delete *msg)
{
  vapi_msg_idpf_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_idpf_delete>()
{
  return ::vapi_msg_id_idpf_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_idpf_delete>>()
{
  return ::vapi_msg_id_idpf_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_idpf_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_idpf_delete>(vapi_msg_id_idpf_delete);
}

template <> inline vapi_msg_idpf_delete* vapi_alloc<vapi_msg_idpf_delete>(Connection &con)
{
  vapi_msg_idpf_delete* result = vapi_alloc_idpf_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_idpf_delete>;

template class Request<vapi_msg_idpf_delete, vapi_msg_idpf_delete_reply>;

using Idpf_delete = Request<vapi_msg_idpf_delete, vapi_msg_idpf_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_idpf_delete_reply>(vapi_msg_idpf_delete_reply *msg)
{
  vapi_msg_idpf_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_idpf_delete_reply>(vapi_msg_idpf_delete_reply *msg)
{
  vapi_msg_idpf_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_idpf_delete_reply>()
{
  return ::vapi_msg_id_idpf_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_idpf_delete_reply>>()
{
  return ::vapi_msg_id_idpf_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_idpf_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_idpf_delete_reply>(vapi_msg_id_idpf_delete_reply);
}

template class Msg<vapi_msg_idpf_delete_reply>;

using Idpf_delete_reply = Msg<vapi_msg_idpf_delete_reply>;
}
#endif
