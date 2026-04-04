#ifndef __included_hpp_snort_api_json
#define __included_hpp_snort_api_json

#include <vapi/vapi.hpp>
#include <vapi/snort.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_create>(vapi_msg_snort_instance_create *msg)
{
  vapi_msg_snort_instance_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_create>(vapi_msg_snort_instance_create *msg)
{
  vapi_msg_snort_instance_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_create>()
{
  return ::vapi_msg_id_snort_instance_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_create>>()
{
  return ::vapi_msg_id_snort_instance_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_create>(vapi_msg_id_snort_instance_create);
}

template <> inline vapi_msg_snort_instance_create* vapi_alloc<vapi_msg_snort_instance_create, size_t>(Connection &con, size_t name_buf_array_size)
{
  vapi_msg_snort_instance_create* result = vapi_alloc_snort_instance_create(con.vapi_ctx, name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_instance_create>;

template class Request<vapi_msg_snort_instance_create, vapi_msg_snort_instance_create_reply, size_t>;

using Snort_instance_create = Request<vapi_msg_snort_instance_create, vapi_msg_snort_instance_create_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_create_reply>(vapi_msg_snort_instance_create_reply *msg)
{
  vapi_msg_snort_instance_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_create_reply>(vapi_msg_snort_instance_create_reply *msg)
{
  vapi_msg_snort_instance_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_create_reply>()
{
  return ::vapi_msg_id_snort_instance_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_create_reply>>()
{
  return ::vapi_msg_id_snort_instance_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_create_reply>(vapi_msg_id_snort_instance_create_reply);
}

template class Msg<vapi_msg_snort_instance_create_reply>;

using Snort_instance_create_reply = Msg<vapi_msg_snort_instance_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_delete>(vapi_msg_snort_instance_delete *msg)
{
  vapi_msg_snort_instance_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_delete>(vapi_msg_snort_instance_delete *msg)
{
  vapi_msg_snort_instance_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_delete>()
{
  return ::vapi_msg_id_snort_instance_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_delete>>()
{
  return ::vapi_msg_id_snort_instance_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_delete>(vapi_msg_id_snort_instance_delete);
}

template <> inline vapi_msg_snort_instance_delete* vapi_alloc<vapi_msg_snort_instance_delete>(Connection &con)
{
  vapi_msg_snort_instance_delete* result = vapi_alloc_snort_instance_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_instance_delete>;

template class Request<vapi_msg_snort_instance_delete, vapi_msg_snort_instance_delete_reply>;

using Snort_instance_delete = Request<vapi_msg_snort_instance_delete, vapi_msg_snort_instance_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_delete_reply>(vapi_msg_snort_instance_delete_reply *msg)
{
  vapi_msg_snort_instance_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_delete_reply>(vapi_msg_snort_instance_delete_reply *msg)
{
  vapi_msg_snort_instance_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_delete_reply>()
{
  return ::vapi_msg_id_snort_instance_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_delete_reply>>()
{
  return ::vapi_msg_id_snort_instance_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_delete_reply>(vapi_msg_id_snort_instance_delete_reply);
}

template class Msg<vapi_msg_snort_instance_delete_reply>;

using Snort_instance_delete_reply = Msg<vapi_msg_snort_instance_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_client_disconnect>(vapi_msg_snort_client_disconnect *msg)
{
  vapi_msg_snort_client_disconnect_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_client_disconnect>(vapi_msg_snort_client_disconnect *msg)
{
  vapi_msg_snort_client_disconnect_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_client_disconnect>()
{
  return ::vapi_msg_id_snort_client_disconnect; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_client_disconnect>>()
{
  return ::vapi_msg_id_snort_client_disconnect; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_client_disconnect()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_client_disconnect>(vapi_msg_id_snort_client_disconnect);
}

template <> inline vapi_msg_snort_client_disconnect* vapi_alloc<vapi_msg_snort_client_disconnect>(Connection &con)
{
  vapi_msg_snort_client_disconnect* result = vapi_alloc_snort_client_disconnect(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_client_disconnect>;

template class Request<vapi_msg_snort_client_disconnect, vapi_msg_snort_client_disconnect_reply>;

using Snort_client_disconnect = Request<vapi_msg_snort_client_disconnect, vapi_msg_snort_client_disconnect_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_client_disconnect_reply>(vapi_msg_snort_client_disconnect_reply *msg)
{
  vapi_msg_snort_client_disconnect_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_client_disconnect_reply>(vapi_msg_snort_client_disconnect_reply *msg)
{
  vapi_msg_snort_client_disconnect_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_client_disconnect_reply>()
{
  return ::vapi_msg_id_snort_client_disconnect_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_client_disconnect_reply>>()
{
  return ::vapi_msg_id_snort_client_disconnect_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_client_disconnect_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_client_disconnect_reply>(vapi_msg_id_snort_client_disconnect_reply);
}

template class Msg<vapi_msg_snort_client_disconnect_reply>;

using Snort_client_disconnect_reply = Msg<vapi_msg_snort_client_disconnect_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_disconnect>(vapi_msg_snort_instance_disconnect *msg)
{
  vapi_msg_snort_instance_disconnect_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_disconnect>(vapi_msg_snort_instance_disconnect *msg)
{
  vapi_msg_snort_instance_disconnect_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_disconnect>()
{
  return ::vapi_msg_id_snort_instance_disconnect; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_disconnect>>()
{
  return ::vapi_msg_id_snort_instance_disconnect; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_disconnect()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_disconnect>(vapi_msg_id_snort_instance_disconnect);
}

template <> inline vapi_msg_snort_instance_disconnect* vapi_alloc<vapi_msg_snort_instance_disconnect>(Connection &con)
{
  vapi_msg_snort_instance_disconnect* result = vapi_alloc_snort_instance_disconnect(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_instance_disconnect>;

template class Request<vapi_msg_snort_instance_disconnect, vapi_msg_snort_instance_disconnect_reply>;

using Snort_instance_disconnect = Request<vapi_msg_snort_instance_disconnect, vapi_msg_snort_instance_disconnect_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_disconnect_reply>(vapi_msg_snort_instance_disconnect_reply *msg)
{
  vapi_msg_snort_instance_disconnect_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_disconnect_reply>(vapi_msg_snort_instance_disconnect_reply *msg)
{
  vapi_msg_snort_instance_disconnect_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_disconnect_reply>()
{
  return ::vapi_msg_id_snort_instance_disconnect_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_disconnect_reply>>()
{
  return ::vapi_msg_id_snort_instance_disconnect_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_disconnect_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_disconnect_reply>(vapi_msg_id_snort_instance_disconnect_reply);
}

template class Msg<vapi_msg_snort_instance_disconnect_reply>;

using Snort_instance_disconnect_reply = Msg<vapi_msg_snort_instance_disconnect_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_attach>(vapi_msg_snort_interface_attach *msg)
{
  vapi_msg_snort_interface_attach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_attach>(vapi_msg_snort_interface_attach *msg)
{
  vapi_msg_snort_interface_attach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_attach>()
{
  return ::vapi_msg_id_snort_interface_attach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_attach>>()
{
  return ::vapi_msg_id_snort_interface_attach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_attach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_attach>(vapi_msg_id_snort_interface_attach);
}

template <> inline vapi_msg_snort_interface_attach* vapi_alloc<vapi_msg_snort_interface_attach>(Connection &con)
{
  vapi_msg_snort_interface_attach* result = vapi_alloc_snort_interface_attach(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_interface_attach>;

template class Request<vapi_msg_snort_interface_attach, vapi_msg_snort_interface_attach_reply>;

using Snort_interface_attach = Request<vapi_msg_snort_interface_attach, vapi_msg_snort_interface_attach_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_attach_reply>(vapi_msg_snort_interface_attach_reply *msg)
{
  vapi_msg_snort_interface_attach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_attach_reply>(vapi_msg_snort_interface_attach_reply *msg)
{
  vapi_msg_snort_interface_attach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_attach_reply>()
{
  return ::vapi_msg_id_snort_interface_attach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_attach_reply>>()
{
  return ::vapi_msg_id_snort_interface_attach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_attach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_attach_reply>(vapi_msg_id_snort_interface_attach_reply);
}

template class Msg<vapi_msg_snort_interface_attach_reply>;

using Snort_interface_attach_reply = Msg<vapi_msg_snort_interface_attach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_detach>(vapi_msg_snort_interface_detach *msg)
{
  vapi_msg_snort_interface_detach_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_detach>(vapi_msg_snort_interface_detach *msg)
{
  vapi_msg_snort_interface_detach_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_detach>()
{
  return ::vapi_msg_id_snort_interface_detach; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_detach>>()
{
  return ::vapi_msg_id_snort_interface_detach; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_detach()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_detach>(vapi_msg_id_snort_interface_detach);
}

template <> inline vapi_msg_snort_interface_detach* vapi_alloc<vapi_msg_snort_interface_detach>(Connection &con)
{
  vapi_msg_snort_interface_detach* result = vapi_alloc_snort_interface_detach(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_interface_detach>;

template class Request<vapi_msg_snort_interface_detach, vapi_msg_snort_interface_detach_reply>;

using Snort_interface_detach = Request<vapi_msg_snort_interface_detach, vapi_msg_snort_interface_detach_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_detach_reply>(vapi_msg_snort_interface_detach_reply *msg)
{
  vapi_msg_snort_interface_detach_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_detach_reply>(vapi_msg_snort_interface_detach_reply *msg)
{
  vapi_msg_snort_interface_detach_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_detach_reply>()
{
  return ::vapi_msg_id_snort_interface_detach_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_detach_reply>>()
{
  return ::vapi_msg_id_snort_interface_detach_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_detach_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_detach_reply>(vapi_msg_id_snort_interface_detach_reply);
}

template class Msg<vapi_msg_snort_interface_detach_reply>;

using Snort_interface_detach_reply = Msg<vapi_msg_snort_interface_detach_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_input_mode_get>(vapi_msg_snort_input_mode_get *msg)
{
  vapi_msg_snort_input_mode_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_input_mode_get>(vapi_msg_snort_input_mode_get *msg)
{
  vapi_msg_snort_input_mode_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_input_mode_get>()
{
  return ::vapi_msg_id_snort_input_mode_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_input_mode_get>>()
{
  return ::vapi_msg_id_snort_input_mode_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_input_mode_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_input_mode_get>(vapi_msg_id_snort_input_mode_get);
}

template <> inline vapi_msg_snort_input_mode_get* vapi_alloc<vapi_msg_snort_input_mode_get>(Connection &con)
{
  vapi_msg_snort_input_mode_get* result = vapi_alloc_snort_input_mode_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_input_mode_get>;

template class Request<vapi_msg_snort_input_mode_get, vapi_msg_snort_input_mode_get_reply>;

using Snort_input_mode_get = Request<vapi_msg_snort_input_mode_get, vapi_msg_snort_input_mode_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_input_mode_get_reply>(vapi_msg_snort_input_mode_get_reply *msg)
{
  vapi_msg_snort_input_mode_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_input_mode_get_reply>(vapi_msg_snort_input_mode_get_reply *msg)
{
  vapi_msg_snort_input_mode_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_input_mode_get_reply>()
{
  return ::vapi_msg_id_snort_input_mode_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_input_mode_get_reply>>()
{
  return ::vapi_msg_id_snort_input_mode_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_input_mode_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_input_mode_get_reply>(vapi_msg_id_snort_input_mode_get_reply);
}

template class Msg<vapi_msg_snort_input_mode_get_reply>;

using Snort_input_mode_get_reply = Msg<vapi_msg_snort_input_mode_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_input_mode_set>(vapi_msg_snort_input_mode_set *msg)
{
  vapi_msg_snort_input_mode_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_input_mode_set>(vapi_msg_snort_input_mode_set *msg)
{
  vapi_msg_snort_input_mode_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_input_mode_set>()
{
  return ::vapi_msg_id_snort_input_mode_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_input_mode_set>>()
{
  return ::vapi_msg_id_snort_input_mode_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_input_mode_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_input_mode_set>(vapi_msg_id_snort_input_mode_set);
}

template <> inline vapi_msg_snort_input_mode_set* vapi_alloc<vapi_msg_snort_input_mode_set>(Connection &con)
{
  vapi_msg_snort_input_mode_set* result = vapi_alloc_snort_input_mode_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_input_mode_set>;

template class Request<vapi_msg_snort_input_mode_set, vapi_msg_snort_input_mode_set_reply>;

using Snort_input_mode_set = Request<vapi_msg_snort_input_mode_set, vapi_msg_snort_input_mode_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_input_mode_set_reply>(vapi_msg_snort_input_mode_set_reply *msg)
{
  vapi_msg_snort_input_mode_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_input_mode_set_reply>(vapi_msg_snort_input_mode_set_reply *msg)
{
  vapi_msg_snort_input_mode_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_input_mode_set_reply>()
{
  return ::vapi_msg_id_snort_input_mode_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_input_mode_set_reply>>()
{
  return ::vapi_msg_id_snort_input_mode_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_input_mode_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_input_mode_set_reply>(vapi_msg_id_snort_input_mode_set_reply);
}

template class Msg<vapi_msg_snort_input_mode_set_reply>;

using Snort_input_mode_set_reply = Msg<vapi_msg_snort_input_mode_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_get>(vapi_msg_snort_instance_get *msg)
{
  vapi_msg_snort_instance_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_get>(vapi_msg_snort_instance_get *msg)
{
  vapi_msg_snort_instance_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_get>()
{
  return ::vapi_msg_id_snort_instance_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_get>>()
{
  return ::vapi_msg_id_snort_instance_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_get>(vapi_msg_id_snort_instance_get);
}

template <> inline vapi_msg_snort_instance_get* vapi_alloc<vapi_msg_snort_instance_get>(Connection &con)
{
  vapi_msg_snort_instance_get* result = vapi_alloc_snort_instance_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_instance_get>;

template class Stream<vapi_msg_snort_instance_get, vapi_msg_snort_instance_get_reply, vapi_msg_snort_instance_details>;

using Snort_instance_get = Stream<vapi_msg_snort_instance_get, vapi_msg_snort_instance_get_reply, vapi_msg_snort_instance_details>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_get_reply>(vapi_msg_snort_instance_get_reply *msg)
{
  vapi_msg_snort_instance_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_get_reply>(vapi_msg_snort_instance_get_reply *msg)
{
  vapi_msg_snort_instance_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_get_reply>()
{
  return ::vapi_msg_id_snort_instance_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_get_reply>>()
{
  return ::vapi_msg_id_snort_instance_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_get_reply>(vapi_msg_id_snort_instance_get_reply);
}

template class Msg<vapi_msg_snort_instance_get_reply>;

using Snort_instance_get_reply = Msg<vapi_msg_snort_instance_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_instance_details>(vapi_msg_snort_instance_details *msg)
{
  vapi_msg_snort_instance_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_instance_details>(vapi_msg_snort_instance_details *msg)
{
  vapi_msg_snort_instance_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_instance_details>()
{
  return ::vapi_msg_id_snort_instance_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_instance_details>>()
{
  return ::vapi_msg_id_snort_instance_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_instance_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_instance_details>(vapi_msg_id_snort_instance_details);
}

template class Msg<vapi_msg_snort_instance_details>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_get>(vapi_msg_snort_interface_get *msg)
{
  vapi_msg_snort_interface_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_get>(vapi_msg_snort_interface_get *msg)
{
  vapi_msg_snort_interface_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_get>()
{
  return ::vapi_msg_id_snort_interface_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_get>>()
{
  return ::vapi_msg_id_snort_interface_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_get>(vapi_msg_id_snort_interface_get);
}

template <> inline vapi_msg_snort_interface_get* vapi_alloc<vapi_msg_snort_interface_get>(Connection &con)
{
  vapi_msg_snort_interface_get* result = vapi_alloc_snort_interface_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_interface_get>;

template class Stream<vapi_msg_snort_interface_get, vapi_msg_snort_interface_get_reply, vapi_msg_snort_interface_details>;

using Snort_interface_get = Stream<vapi_msg_snort_interface_get, vapi_msg_snort_interface_get_reply, vapi_msg_snort_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_get_reply>(vapi_msg_snort_interface_get_reply *msg)
{
  vapi_msg_snort_interface_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_get_reply>(vapi_msg_snort_interface_get_reply *msg)
{
  vapi_msg_snort_interface_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_get_reply>()
{
  return ::vapi_msg_id_snort_interface_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_get_reply>>()
{
  return ::vapi_msg_id_snort_interface_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_get_reply>(vapi_msg_id_snort_interface_get_reply);
}

template class Msg<vapi_msg_snort_interface_get_reply>;

using Snort_interface_get_reply = Msg<vapi_msg_snort_interface_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_interface_details>(vapi_msg_snort_interface_details *msg)
{
  vapi_msg_snort_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_interface_details>(vapi_msg_snort_interface_details *msg)
{
  vapi_msg_snort_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_interface_details>()
{
  return ::vapi_msg_id_snort_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_interface_details>>()
{
  return ::vapi_msg_id_snort_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_interface_details>(vapi_msg_id_snort_interface_details);
}

template class Msg<vapi_msg_snort_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_client_get>(vapi_msg_snort_client_get *msg)
{
  vapi_msg_snort_client_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_client_get>(vapi_msg_snort_client_get *msg)
{
  vapi_msg_snort_client_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_client_get>()
{
  return ::vapi_msg_id_snort_client_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_client_get>>()
{
  return ::vapi_msg_id_snort_client_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_client_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_client_get>(vapi_msg_id_snort_client_get);
}

template <> inline vapi_msg_snort_client_get* vapi_alloc<vapi_msg_snort_client_get>(Connection &con)
{
  vapi_msg_snort_client_get* result = vapi_alloc_snort_client_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_snort_client_get>;

template class Stream<vapi_msg_snort_client_get, vapi_msg_snort_client_get_reply, vapi_msg_snort_client_details>;

using Snort_client_get = Stream<vapi_msg_snort_client_get, vapi_msg_snort_client_get_reply, vapi_msg_snort_client_details>;

template <> inline void vapi_swap_to_be<vapi_msg_snort_client_get_reply>(vapi_msg_snort_client_get_reply *msg)
{
  vapi_msg_snort_client_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_client_get_reply>(vapi_msg_snort_client_get_reply *msg)
{
  vapi_msg_snort_client_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_client_get_reply>()
{
  return ::vapi_msg_id_snort_client_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_client_get_reply>>()
{
  return ::vapi_msg_id_snort_client_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_client_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_client_get_reply>(vapi_msg_id_snort_client_get_reply);
}

template class Msg<vapi_msg_snort_client_get_reply>;

using Snort_client_get_reply = Msg<vapi_msg_snort_client_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_snort_client_details>(vapi_msg_snort_client_details *msg)
{
  vapi_msg_snort_client_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_snort_client_details>(vapi_msg_snort_client_details *msg)
{
  vapi_msg_snort_client_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_snort_client_details>()
{
  return ::vapi_msg_id_snort_client_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_snort_client_details>>()
{
  return ::vapi_msg_id_snort_client_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_snort_client_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_snort_client_details>(vapi_msg_id_snort_client_details);
}

template class Msg<vapi_msg_snort_client_details>;

}
#endif
