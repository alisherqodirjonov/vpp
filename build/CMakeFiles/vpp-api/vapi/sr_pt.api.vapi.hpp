#ifndef __included_hpp_sr_pt_api_json
#define __included_hpp_sr_pt_api_json

#include <vapi/vapi.hpp>
#include <vapi/sr_pt.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_sr_pt_iface_dump>(vapi_msg_sr_pt_iface_dump *msg)
{
  vapi_msg_sr_pt_iface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_pt_iface_dump>(vapi_msg_sr_pt_iface_dump *msg)
{
  vapi_msg_sr_pt_iface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_pt_iface_dump>()
{
  return ::vapi_msg_id_sr_pt_iface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_pt_iface_dump>>()
{
  return ::vapi_msg_id_sr_pt_iface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_pt_iface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_pt_iface_dump>(vapi_msg_id_sr_pt_iface_dump);
}

template <> inline vapi_msg_sr_pt_iface_dump* vapi_alloc<vapi_msg_sr_pt_iface_dump>(Connection &con)
{
  vapi_msg_sr_pt_iface_dump* result = vapi_alloc_sr_pt_iface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_pt_iface_dump>;

template class Dump<vapi_msg_sr_pt_iface_dump, vapi_msg_sr_pt_iface_details>;

using Sr_pt_iface_dump = Dump<vapi_msg_sr_pt_iface_dump, vapi_msg_sr_pt_iface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_pt_iface_details>(vapi_msg_sr_pt_iface_details *msg)
{
  vapi_msg_sr_pt_iface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_pt_iface_details>(vapi_msg_sr_pt_iface_details *msg)
{
  vapi_msg_sr_pt_iface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_pt_iface_details>()
{
  return ::vapi_msg_id_sr_pt_iface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_pt_iface_details>>()
{
  return ::vapi_msg_id_sr_pt_iface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_pt_iface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_pt_iface_details>(vapi_msg_id_sr_pt_iface_details);
}

template class Msg<vapi_msg_sr_pt_iface_details>;

using Sr_pt_iface_details = Msg<vapi_msg_sr_pt_iface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_pt_iface_add>(vapi_msg_sr_pt_iface_add *msg)
{
  vapi_msg_sr_pt_iface_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_pt_iface_add>(vapi_msg_sr_pt_iface_add *msg)
{
  vapi_msg_sr_pt_iface_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_pt_iface_add>()
{
  return ::vapi_msg_id_sr_pt_iface_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_pt_iface_add>>()
{
  return ::vapi_msg_id_sr_pt_iface_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_pt_iface_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_pt_iface_add>(vapi_msg_id_sr_pt_iface_add);
}

template <> inline vapi_msg_sr_pt_iface_add* vapi_alloc<vapi_msg_sr_pt_iface_add>(Connection &con)
{
  vapi_msg_sr_pt_iface_add* result = vapi_alloc_sr_pt_iface_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_pt_iface_add>;

template class Request<vapi_msg_sr_pt_iface_add, vapi_msg_sr_pt_iface_add_reply>;

using Sr_pt_iface_add = Request<vapi_msg_sr_pt_iface_add, vapi_msg_sr_pt_iface_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_pt_iface_add_reply>(vapi_msg_sr_pt_iface_add_reply *msg)
{
  vapi_msg_sr_pt_iface_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_pt_iface_add_reply>(vapi_msg_sr_pt_iface_add_reply *msg)
{
  vapi_msg_sr_pt_iface_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_pt_iface_add_reply>()
{
  return ::vapi_msg_id_sr_pt_iface_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_pt_iface_add_reply>>()
{
  return ::vapi_msg_id_sr_pt_iface_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_pt_iface_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_pt_iface_add_reply>(vapi_msg_id_sr_pt_iface_add_reply);
}

template class Msg<vapi_msg_sr_pt_iface_add_reply>;

using Sr_pt_iface_add_reply = Msg<vapi_msg_sr_pt_iface_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_sr_pt_iface_del>(vapi_msg_sr_pt_iface_del *msg)
{
  vapi_msg_sr_pt_iface_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_pt_iface_del>(vapi_msg_sr_pt_iface_del *msg)
{
  vapi_msg_sr_pt_iface_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_pt_iface_del>()
{
  return ::vapi_msg_id_sr_pt_iface_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_pt_iface_del>>()
{
  return ::vapi_msg_id_sr_pt_iface_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_pt_iface_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_pt_iface_del>(vapi_msg_id_sr_pt_iface_del);
}

template <> inline vapi_msg_sr_pt_iface_del* vapi_alloc<vapi_msg_sr_pt_iface_del>(Connection &con)
{
  vapi_msg_sr_pt_iface_del* result = vapi_alloc_sr_pt_iface_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_sr_pt_iface_del>;

template class Request<vapi_msg_sr_pt_iface_del, vapi_msg_sr_pt_iface_del_reply>;

using Sr_pt_iface_del = Request<vapi_msg_sr_pt_iface_del, vapi_msg_sr_pt_iface_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_sr_pt_iface_del_reply>(vapi_msg_sr_pt_iface_del_reply *msg)
{
  vapi_msg_sr_pt_iface_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_sr_pt_iface_del_reply>(vapi_msg_sr_pt_iface_del_reply *msg)
{
  vapi_msg_sr_pt_iface_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_sr_pt_iface_del_reply>()
{
  return ::vapi_msg_id_sr_pt_iface_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_sr_pt_iface_del_reply>>()
{
  return ::vapi_msg_id_sr_pt_iface_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_sr_pt_iface_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_sr_pt_iface_del_reply>(vapi_msg_id_sr_pt_iface_del_reply);
}

template class Msg<vapi_msg_sr_pt_iface_del_reply>;

using Sr_pt_iface_del_reply = Msg<vapi_msg_sr_pt_iface_del_reply>;
}
#endif
