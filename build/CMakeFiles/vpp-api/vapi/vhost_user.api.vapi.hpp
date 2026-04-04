#ifndef __included_hpp_vhost_user_api_json
#define __included_hpp_vhost_user_api_json

#include <vapi/vapi.hpp>
#include <vapi/vhost_user.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_create_vhost_user_if>(vapi_msg_create_vhost_user_if *msg)
{
  vapi_msg_create_vhost_user_if_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_vhost_user_if>(vapi_msg_create_vhost_user_if *msg)
{
  vapi_msg_create_vhost_user_if_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_vhost_user_if>()
{
  return ::vapi_msg_id_create_vhost_user_if; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_vhost_user_if>>()
{
  return ::vapi_msg_id_create_vhost_user_if; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_vhost_user_if()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_vhost_user_if>(vapi_msg_id_create_vhost_user_if);
}

template <> inline vapi_msg_create_vhost_user_if* vapi_alloc<vapi_msg_create_vhost_user_if>(Connection &con)
{
  vapi_msg_create_vhost_user_if* result = vapi_alloc_create_vhost_user_if(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_create_vhost_user_if>;

template class Request<vapi_msg_create_vhost_user_if, vapi_msg_create_vhost_user_if_reply>;

using Create_vhost_user_if = Request<vapi_msg_create_vhost_user_if, vapi_msg_create_vhost_user_if_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_create_vhost_user_if_reply>(vapi_msg_create_vhost_user_if_reply *msg)
{
  vapi_msg_create_vhost_user_if_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_vhost_user_if_reply>(vapi_msg_create_vhost_user_if_reply *msg)
{
  vapi_msg_create_vhost_user_if_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_vhost_user_if_reply>()
{
  return ::vapi_msg_id_create_vhost_user_if_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_vhost_user_if_reply>>()
{
  return ::vapi_msg_id_create_vhost_user_if_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_vhost_user_if_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_vhost_user_if_reply>(vapi_msg_id_create_vhost_user_if_reply);
}

template class Msg<vapi_msg_create_vhost_user_if_reply>;

using Create_vhost_user_if_reply = Msg<vapi_msg_create_vhost_user_if_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_modify_vhost_user_if>(vapi_msg_modify_vhost_user_if *msg)
{
  vapi_msg_modify_vhost_user_if_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_modify_vhost_user_if>(vapi_msg_modify_vhost_user_if *msg)
{
  vapi_msg_modify_vhost_user_if_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_modify_vhost_user_if>()
{
  return ::vapi_msg_id_modify_vhost_user_if; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_modify_vhost_user_if>>()
{
  return ::vapi_msg_id_modify_vhost_user_if; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_modify_vhost_user_if()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_modify_vhost_user_if>(vapi_msg_id_modify_vhost_user_if);
}

template <> inline vapi_msg_modify_vhost_user_if* vapi_alloc<vapi_msg_modify_vhost_user_if>(Connection &con)
{
  vapi_msg_modify_vhost_user_if* result = vapi_alloc_modify_vhost_user_if(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_modify_vhost_user_if>;

template class Request<vapi_msg_modify_vhost_user_if, vapi_msg_modify_vhost_user_if_reply>;

using Modify_vhost_user_if = Request<vapi_msg_modify_vhost_user_if, vapi_msg_modify_vhost_user_if_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_modify_vhost_user_if_reply>(vapi_msg_modify_vhost_user_if_reply *msg)
{
  vapi_msg_modify_vhost_user_if_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_modify_vhost_user_if_reply>(vapi_msg_modify_vhost_user_if_reply *msg)
{
  vapi_msg_modify_vhost_user_if_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_modify_vhost_user_if_reply>()
{
  return ::vapi_msg_id_modify_vhost_user_if_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_modify_vhost_user_if_reply>>()
{
  return ::vapi_msg_id_modify_vhost_user_if_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_modify_vhost_user_if_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_modify_vhost_user_if_reply>(vapi_msg_id_modify_vhost_user_if_reply);
}

template class Msg<vapi_msg_modify_vhost_user_if_reply>;

using Modify_vhost_user_if_reply = Msg<vapi_msg_modify_vhost_user_if_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_create_vhost_user_if_v2>(vapi_msg_create_vhost_user_if_v2 *msg)
{
  vapi_msg_create_vhost_user_if_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_vhost_user_if_v2>(vapi_msg_create_vhost_user_if_v2 *msg)
{
  vapi_msg_create_vhost_user_if_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_vhost_user_if_v2>()
{
  return ::vapi_msg_id_create_vhost_user_if_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_vhost_user_if_v2>>()
{
  return ::vapi_msg_id_create_vhost_user_if_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_vhost_user_if_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_vhost_user_if_v2>(vapi_msg_id_create_vhost_user_if_v2);
}

template <> inline vapi_msg_create_vhost_user_if_v2* vapi_alloc<vapi_msg_create_vhost_user_if_v2>(Connection &con)
{
  vapi_msg_create_vhost_user_if_v2* result = vapi_alloc_create_vhost_user_if_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_create_vhost_user_if_v2>;

template class Request<vapi_msg_create_vhost_user_if_v2, vapi_msg_create_vhost_user_if_v2_reply>;

using Create_vhost_user_if_v2 = Request<vapi_msg_create_vhost_user_if_v2, vapi_msg_create_vhost_user_if_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_create_vhost_user_if_v2_reply>(vapi_msg_create_vhost_user_if_v2_reply *msg)
{
  vapi_msg_create_vhost_user_if_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_create_vhost_user_if_v2_reply>(vapi_msg_create_vhost_user_if_v2_reply *msg)
{
  vapi_msg_create_vhost_user_if_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_create_vhost_user_if_v2_reply>()
{
  return ::vapi_msg_id_create_vhost_user_if_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_create_vhost_user_if_v2_reply>>()
{
  return ::vapi_msg_id_create_vhost_user_if_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_create_vhost_user_if_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_create_vhost_user_if_v2_reply>(vapi_msg_id_create_vhost_user_if_v2_reply);
}

template class Msg<vapi_msg_create_vhost_user_if_v2_reply>;

using Create_vhost_user_if_v2_reply = Msg<vapi_msg_create_vhost_user_if_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_modify_vhost_user_if_v2>(vapi_msg_modify_vhost_user_if_v2 *msg)
{
  vapi_msg_modify_vhost_user_if_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_modify_vhost_user_if_v2>(vapi_msg_modify_vhost_user_if_v2 *msg)
{
  vapi_msg_modify_vhost_user_if_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_modify_vhost_user_if_v2>()
{
  return ::vapi_msg_id_modify_vhost_user_if_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_modify_vhost_user_if_v2>>()
{
  return ::vapi_msg_id_modify_vhost_user_if_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_modify_vhost_user_if_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_modify_vhost_user_if_v2>(vapi_msg_id_modify_vhost_user_if_v2);
}

template <> inline vapi_msg_modify_vhost_user_if_v2* vapi_alloc<vapi_msg_modify_vhost_user_if_v2>(Connection &con)
{
  vapi_msg_modify_vhost_user_if_v2* result = vapi_alloc_modify_vhost_user_if_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_modify_vhost_user_if_v2>;

template class Request<vapi_msg_modify_vhost_user_if_v2, vapi_msg_modify_vhost_user_if_v2_reply>;

using Modify_vhost_user_if_v2 = Request<vapi_msg_modify_vhost_user_if_v2, vapi_msg_modify_vhost_user_if_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_modify_vhost_user_if_v2_reply>(vapi_msg_modify_vhost_user_if_v2_reply *msg)
{
  vapi_msg_modify_vhost_user_if_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_modify_vhost_user_if_v2_reply>(vapi_msg_modify_vhost_user_if_v2_reply *msg)
{
  vapi_msg_modify_vhost_user_if_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_modify_vhost_user_if_v2_reply>()
{
  return ::vapi_msg_id_modify_vhost_user_if_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_modify_vhost_user_if_v2_reply>>()
{
  return ::vapi_msg_id_modify_vhost_user_if_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_modify_vhost_user_if_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_modify_vhost_user_if_v2_reply>(vapi_msg_id_modify_vhost_user_if_v2_reply);
}

template class Msg<vapi_msg_modify_vhost_user_if_v2_reply>;

using Modify_vhost_user_if_v2_reply = Msg<vapi_msg_modify_vhost_user_if_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_delete_vhost_user_if>(vapi_msg_delete_vhost_user_if *msg)
{
  vapi_msg_delete_vhost_user_if_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_delete_vhost_user_if>(vapi_msg_delete_vhost_user_if *msg)
{
  vapi_msg_delete_vhost_user_if_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_delete_vhost_user_if>()
{
  return ::vapi_msg_id_delete_vhost_user_if; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_delete_vhost_user_if>>()
{
  return ::vapi_msg_id_delete_vhost_user_if; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_delete_vhost_user_if()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_delete_vhost_user_if>(vapi_msg_id_delete_vhost_user_if);
}

template <> inline vapi_msg_delete_vhost_user_if* vapi_alloc<vapi_msg_delete_vhost_user_if>(Connection &con)
{
  vapi_msg_delete_vhost_user_if* result = vapi_alloc_delete_vhost_user_if(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_delete_vhost_user_if>;

template class Request<vapi_msg_delete_vhost_user_if, vapi_msg_delete_vhost_user_if_reply>;

using Delete_vhost_user_if = Request<vapi_msg_delete_vhost_user_if, vapi_msg_delete_vhost_user_if_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_delete_vhost_user_if_reply>(vapi_msg_delete_vhost_user_if_reply *msg)
{
  vapi_msg_delete_vhost_user_if_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_delete_vhost_user_if_reply>(vapi_msg_delete_vhost_user_if_reply *msg)
{
  vapi_msg_delete_vhost_user_if_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_delete_vhost_user_if_reply>()
{
  return ::vapi_msg_id_delete_vhost_user_if_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_delete_vhost_user_if_reply>>()
{
  return ::vapi_msg_id_delete_vhost_user_if_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_delete_vhost_user_if_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_delete_vhost_user_if_reply>(vapi_msg_id_delete_vhost_user_if_reply);
}

template class Msg<vapi_msg_delete_vhost_user_if_reply>;

using Delete_vhost_user_if_reply = Msg<vapi_msg_delete_vhost_user_if_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_vhost_user_details>(vapi_msg_sw_interface_vhost_user_details *msg)
{
  vapi_msg_sw_interface_vhost_user_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_vhost_user_details>(vapi_msg_sw_interface_vhost_user_details *msg)
{
  vapi_msg_sw_interface_vhost_user_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_vhost_user_details>()
{
  return ::vapi_msg_id_sw_interface_vhost_user_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_vhost_user_details>>()
{
  return ::vapi_msg_id_sw_interface_vhost_user_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_vhost_user_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_vhost_user_details>(vapi_msg_id_sw_interface_vhost_user_details);
}

template class Msg<vapi_msg_sw_interface_vhost_user_details>;

using Sw_interface_vhost_user_details = Msg<vapi_msg_sw_interface_vhost_user_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sw_interface_vhost_user_dump>(vapi_msg_sw_interface_vhost_user_dump *msg)
{
  vapi_msg_sw_interface_vhost_user_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sw_interface_vhost_user_dump>(vapi_msg_sw_interface_vhost_user_dump *msg)
{
  vapi_msg_sw_interface_vhost_user_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sw_interface_vhost_user_dump>()
{
  return ::vapi_msg_id_sw_interface_vhost_user_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sw_interface_vhost_user_dump>>()
{
  return ::vapi_msg_id_sw_interface_vhost_user_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sw_interface_vhost_user_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sw_interface_vhost_user_dump>(vapi_msg_id_sw_interface_vhost_user_dump);
}

template <> inline vapi_msg_sw_interface_vhost_user_dump* vapi_alloc<vapi_msg_sw_interface_vhost_user_dump>(Connection &con)
{
  vapi_msg_sw_interface_vhost_user_dump* result = vapi_alloc_sw_interface_vhost_user_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sw_interface_vhost_user_dump>;

template class Dump<vapi_msg_sw_interface_vhost_user_dump, vapi_msg_sw_interface_vhost_user_details>;

using Sw_interface_vhost_user_dump = Dump<vapi_msg_sw_interface_vhost_user_dump, vapi_msg_sw_interface_vhost_user_details>;

}
#endif
