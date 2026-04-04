#ifndef __included_hpp_dev_api_json
#define __included_hpp_dev_api_json

#include <vapi/vapi.hpp>
#include <vapi/dev.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_dev_attach>(vapi_msg_dev_attach *msg)
{
  vapi_msg_dev_attach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_attach>(vapi_msg_dev_attach *msg)
{
  vapi_msg_dev_attach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_attach>()
{
  return ::vapi_msg_id_dev_attach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_attach>>()
{
  return ::vapi_msg_id_dev_attach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_attach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_attach>(vapi_msg_id_dev_attach);
}

template <> inline vapi_msg_dev_attach* vapi_alloc<vapi_msg_dev_attach, size_t>(Connection &con, size_t args_buf_array_size)
{
  vapi_msg_dev_attach* result = vapi_alloc_dev_attach(con.vapi_ctx, args_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dev_attach>;

template class Request<vapi_msg_dev_attach, vapi_msg_dev_attach_reply, size_t>;

using Dev_attach = Request<vapi_msg_dev_attach, vapi_msg_dev_attach_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_dev_attach_reply>(vapi_msg_dev_attach_reply *msg)
{
  vapi_msg_dev_attach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_attach_reply>(vapi_msg_dev_attach_reply *msg)
{
  vapi_msg_dev_attach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_attach_reply>()
{
  return ::vapi_msg_id_dev_attach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_attach_reply>>()
{
  return ::vapi_msg_id_dev_attach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_attach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_attach_reply>(vapi_msg_id_dev_attach_reply);
}

template class Msg<vapi_msg_dev_attach_reply>;

using Dev_attach_reply = Msg<vapi_msg_dev_attach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dev_detach>(vapi_msg_dev_detach *msg)
{
  vapi_msg_dev_detach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_detach>(vapi_msg_dev_detach *msg)
{
  vapi_msg_dev_detach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_detach>()
{
  return ::vapi_msg_id_dev_detach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_detach>>()
{
  return ::vapi_msg_id_dev_detach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_detach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_detach>(vapi_msg_id_dev_detach);
}

template <> inline vapi_msg_dev_detach* vapi_alloc<vapi_msg_dev_detach>(Connection &con)
{
  vapi_msg_dev_detach* result = vapi_alloc_dev_detach(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dev_detach>;

template class Request<vapi_msg_dev_detach, vapi_msg_dev_detach_reply>;

using Dev_detach = Request<vapi_msg_dev_detach, vapi_msg_dev_detach_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dev_detach_reply>(vapi_msg_dev_detach_reply *msg)
{
  vapi_msg_dev_detach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_detach_reply>(vapi_msg_dev_detach_reply *msg)
{
  vapi_msg_dev_detach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_detach_reply>()
{
  return ::vapi_msg_id_dev_detach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_detach_reply>>()
{
  return ::vapi_msg_id_dev_detach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_detach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_detach_reply>(vapi_msg_id_dev_detach_reply);
}

template class Msg<vapi_msg_dev_detach_reply>;

using Dev_detach_reply = Msg<vapi_msg_dev_detach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dev_create_port_if>(vapi_msg_dev_create_port_if *msg)
{
  vapi_msg_dev_create_port_if_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_create_port_if>(vapi_msg_dev_create_port_if *msg)
{
  vapi_msg_dev_create_port_if_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_create_port_if>()
{
  return ::vapi_msg_id_dev_create_port_if; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_create_port_if>>()
{
  return ::vapi_msg_id_dev_create_port_if; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_create_port_if()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_create_port_if>(vapi_msg_id_dev_create_port_if);
}

template <> inline vapi_msg_dev_create_port_if* vapi_alloc<vapi_msg_dev_create_port_if, size_t>(Connection &con, size_t args_buf_array_size)
{
  vapi_msg_dev_create_port_if* result = vapi_alloc_dev_create_port_if(con.vapi_ctx, args_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dev_create_port_if>;

template class Request<vapi_msg_dev_create_port_if, vapi_msg_dev_create_port_if_reply, size_t>;

using Dev_create_port_if = Request<vapi_msg_dev_create_port_if, vapi_msg_dev_create_port_if_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_dev_create_port_if_reply>(vapi_msg_dev_create_port_if_reply *msg)
{
  vapi_msg_dev_create_port_if_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_create_port_if_reply>(vapi_msg_dev_create_port_if_reply *msg)
{
  vapi_msg_dev_create_port_if_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_create_port_if_reply>()
{
  return ::vapi_msg_id_dev_create_port_if_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_create_port_if_reply>>()
{
  return ::vapi_msg_id_dev_create_port_if_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_create_port_if_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_create_port_if_reply>(vapi_msg_id_dev_create_port_if_reply);
}

template class Msg<vapi_msg_dev_create_port_if_reply>;

using Dev_create_port_if_reply = Msg<vapi_msg_dev_create_port_if_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dev_remove_port_if>(vapi_msg_dev_remove_port_if *msg)
{
  vapi_msg_dev_remove_port_if_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_remove_port_if>(vapi_msg_dev_remove_port_if *msg)
{
  vapi_msg_dev_remove_port_if_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_remove_port_if>()
{
  return ::vapi_msg_id_dev_remove_port_if; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_remove_port_if>>()
{
  return ::vapi_msg_id_dev_remove_port_if; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_remove_port_if()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_remove_port_if>(vapi_msg_id_dev_remove_port_if);
}

template <> inline vapi_msg_dev_remove_port_if* vapi_alloc<vapi_msg_dev_remove_port_if>(Connection &con)
{
  vapi_msg_dev_remove_port_if* result = vapi_alloc_dev_remove_port_if(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dev_remove_port_if>;

template class Request<vapi_msg_dev_remove_port_if, vapi_msg_dev_remove_port_if_reply>;

using Dev_remove_port_if = Request<vapi_msg_dev_remove_port_if, vapi_msg_dev_remove_port_if_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dev_remove_port_if_reply>(vapi_msg_dev_remove_port_if_reply *msg)
{
  vapi_msg_dev_remove_port_if_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dev_remove_port_if_reply>(vapi_msg_dev_remove_port_if_reply *msg)
{
  vapi_msg_dev_remove_port_if_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dev_remove_port_if_reply>()
{
  return ::vapi_msg_id_dev_remove_port_if_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dev_remove_port_if_reply>>()
{
  return ::vapi_msg_id_dev_remove_port_if_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dev_remove_port_if_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dev_remove_port_if_reply>(vapi_msg_id_dev_remove_port_if_reply);
}

template class Msg<vapi_msg_dev_remove_port_if_reply>;

using Dev_remove_port_if_reply = Msg<vapi_msg_dev_remove_port_if_reply>;
}
#endif
