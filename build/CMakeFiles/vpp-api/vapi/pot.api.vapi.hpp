#ifndef __included_hpp_pot_api_json
#define __included_hpp_pot_api_json

#include <vapi/vapi.hpp>
#include <vapi/pot.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_add>(vapi_msg_pot_profile_add *msg)
{
  vapi_msg_pot_profile_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_add>(vapi_msg_pot_profile_add *msg)
{
  vapi_msg_pot_profile_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_add>()
{
  return ::vapi_msg_id_pot_profile_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_add>>()
{
  return ::vapi_msg_id_pot_profile_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_add>(vapi_msg_id_pot_profile_add);
}

template <> inline vapi_msg_pot_profile_add* vapi_alloc<vapi_msg_pot_profile_add, size_t>(Connection &con, size_t list_name_buf_array_size)
{
  vapi_msg_pot_profile_add* result = vapi_alloc_pot_profile_add(con.vapi_ctx, list_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pot_profile_add>;

template class Request<vapi_msg_pot_profile_add, vapi_msg_pot_profile_add_reply, size_t>;

using Pot_profile_add = Request<vapi_msg_pot_profile_add, vapi_msg_pot_profile_add_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_add_reply>(vapi_msg_pot_profile_add_reply *msg)
{
  vapi_msg_pot_profile_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_add_reply>(vapi_msg_pot_profile_add_reply *msg)
{
  vapi_msg_pot_profile_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_add_reply>()
{
  return ::vapi_msg_id_pot_profile_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_add_reply>>()
{
  return ::vapi_msg_id_pot_profile_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_add_reply>(vapi_msg_id_pot_profile_add_reply);
}

template class Msg<vapi_msg_pot_profile_add_reply>;

using Pot_profile_add_reply = Msg<vapi_msg_pot_profile_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_activate>(vapi_msg_pot_profile_activate *msg)
{
  vapi_msg_pot_profile_activate_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_activate>(vapi_msg_pot_profile_activate *msg)
{
  vapi_msg_pot_profile_activate_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_activate>()
{
  return ::vapi_msg_id_pot_profile_activate; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_activate>>()
{
  return ::vapi_msg_id_pot_profile_activate; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_activate()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_activate>(vapi_msg_id_pot_profile_activate);
}

template <> inline vapi_msg_pot_profile_activate* vapi_alloc<vapi_msg_pot_profile_activate, size_t>(Connection &con, size_t list_name_buf_array_size)
{
  vapi_msg_pot_profile_activate* result = vapi_alloc_pot_profile_activate(con.vapi_ctx, list_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pot_profile_activate>;

template class Request<vapi_msg_pot_profile_activate, vapi_msg_pot_profile_activate_reply, size_t>;

using Pot_profile_activate = Request<vapi_msg_pot_profile_activate, vapi_msg_pot_profile_activate_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_activate_reply>(vapi_msg_pot_profile_activate_reply *msg)
{
  vapi_msg_pot_profile_activate_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_activate_reply>(vapi_msg_pot_profile_activate_reply *msg)
{
  vapi_msg_pot_profile_activate_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_activate_reply>()
{
  return ::vapi_msg_id_pot_profile_activate_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_activate_reply>>()
{
  return ::vapi_msg_id_pot_profile_activate_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_activate_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_activate_reply>(vapi_msg_id_pot_profile_activate_reply);
}

template class Msg<vapi_msg_pot_profile_activate_reply>;

using Pot_profile_activate_reply = Msg<vapi_msg_pot_profile_activate_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_del>(vapi_msg_pot_profile_del *msg)
{
  vapi_msg_pot_profile_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_del>(vapi_msg_pot_profile_del *msg)
{
  vapi_msg_pot_profile_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_del>()
{
  return ::vapi_msg_id_pot_profile_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_del>>()
{
  return ::vapi_msg_id_pot_profile_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_del>(vapi_msg_id_pot_profile_del);
}

template <> inline vapi_msg_pot_profile_del* vapi_alloc<vapi_msg_pot_profile_del, size_t>(Connection &con, size_t list_name_buf_array_size)
{
  vapi_msg_pot_profile_del* result = vapi_alloc_pot_profile_del(con.vapi_ctx, list_name_buf_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pot_profile_del>;

template class Request<vapi_msg_pot_profile_del, vapi_msg_pot_profile_del_reply, size_t>;

using Pot_profile_del = Request<vapi_msg_pot_profile_del, vapi_msg_pot_profile_del_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_del_reply>(vapi_msg_pot_profile_del_reply *msg)
{
  vapi_msg_pot_profile_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_del_reply>(vapi_msg_pot_profile_del_reply *msg)
{
  vapi_msg_pot_profile_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_del_reply>()
{
  return ::vapi_msg_id_pot_profile_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_del_reply>>()
{
  return ::vapi_msg_id_pot_profile_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_del_reply>(vapi_msg_id_pot_profile_del_reply);
}

template class Msg<vapi_msg_pot_profile_del_reply>;

using Pot_profile_del_reply = Msg<vapi_msg_pot_profile_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_show_config_dump>(vapi_msg_pot_profile_show_config_dump *msg)
{
  vapi_msg_pot_profile_show_config_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_show_config_dump>(vapi_msg_pot_profile_show_config_dump *msg)
{
  vapi_msg_pot_profile_show_config_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_show_config_dump>()
{
  return ::vapi_msg_id_pot_profile_show_config_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_show_config_dump>>()
{
  return ::vapi_msg_id_pot_profile_show_config_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_show_config_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_show_config_dump>(vapi_msg_id_pot_profile_show_config_dump);
}

template <> inline vapi_msg_pot_profile_show_config_dump* vapi_alloc<vapi_msg_pot_profile_show_config_dump>(Connection &con)
{
  vapi_msg_pot_profile_show_config_dump* result = vapi_alloc_pot_profile_show_config_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_pot_profile_show_config_dump>;

template class Dump<vapi_msg_pot_profile_show_config_dump, vapi_msg_pot_profile_show_config_details>;

using Pot_profile_show_config_dump = Dump<vapi_msg_pot_profile_show_config_dump, vapi_msg_pot_profile_show_config_details>;

template <> inline void vapi_swap_to_be<vapi_msg_pot_profile_show_config_details>(vapi_msg_pot_profile_show_config_details *msg)
{
  vapi_msg_pot_profile_show_config_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_pot_profile_show_config_details>(vapi_msg_pot_profile_show_config_details *msg)
{
  vapi_msg_pot_profile_show_config_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_pot_profile_show_config_details>()
{
  return ::vapi_msg_id_pot_profile_show_config_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_pot_profile_show_config_details>>()
{
  return ::vapi_msg_id_pot_profile_show_config_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_pot_profile_show_config_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_pot_profile_show_config_details>(vapi_msg_id_pot_profile_show_config_details);
}

template class Msg<vapi_msg_pot_profile_show_config_details>;

using Pot_profile_show_config_details = Msg<vapi_msg_pot_profile_show_config_details>;
}
#endif
