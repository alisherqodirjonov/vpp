#ifndef __included_hpp_teib_api_json
#define __included_hpp_teib_api_json

#include <vapi/vapi.hpp>
#include <vapi/teib.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_teib_entry_add_del>(vapi_msg_teib_entry_add_del *msg)
{
  vapi_msg_teib_entry_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_teib_entry_add_del>(vapi_msg_teib_entry_add_del *msg)
{
  vapi_msg_teib_entry_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_teib_entry_add_del>()
{
  return ::vapi_msg_id_teib_entry_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_teib_entry_add_del>>()
{
  return ::vapi_msg_id_teib_entry_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_teib_entry_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_teib_entry_add_del>(vapi_msg_id_teib_entry_add_del);
}

template <> inline vapi_msg_teib_entry_add_del* vapi_alloc<vapi_msg_teib_entry_add_del>(Connection &con)
{
  vapi_msg_teib_entry_add_del* result = vapi_alloc_teib_entry_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_teib_entry_add_del>;

template class Request<vapi_msg_teib_entry_add_del, vapi_msg_teib_entry_add_del_reply>;

using Teib_entry_add_del = Request<vapi_msg_teib_entry_add_del, vapi_msg_teib_entry_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_teib_entry_add_del_reply>(vapi_msg_teib_entry_add_del_reply *msg)
{
  vapi_msg_teib_entry_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_teib_entry_add_del_reply>(vapi_msg_teib_entry_add_del_reply *msg)
{
  vapi_msg_teib_entry_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_teib_entry_add_del_reply>()
{
  return ::vapi_msg_id_teib_entry_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_teib_entry_add_del_reply>>()
{
  return ::vapi_msg_id_teib_entry_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_teib_entry_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_teib_entry_add_del_reply>(vapi_msg_id_teib_entry_add_del_reply);
}

template class Msg<vapi_msg_teib_entry_add_del_reply>;

using Teib_entry_add_del_reply = Msg<vapi_msg_teib_entry_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_teib_dump>(vapi_msg_teib_dump *msg)
{
  vapi_msg_teib_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_teib_dump>(vapi_msg_teib_dump *msg)
{
  vapi_msg_teib_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_teib_dump>()
{
  return ::vapi_msg_id_teib_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_teib_dump>>()
{
  return ::vapi_msg_id_teib_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_teib_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_teib_dump>(vapi_msg_id_teib_dump);
}

template <> inline vapi_msg_teib_dump* vapi_alloc<vapi_msg_teib_dump>(Connection &con)
{
  vapi_msg_teib_dump* result = vapi_alloc_teib_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_teib_dump>;

template class Dump<vapi_msg_teib_dump, vapi_msg_teib_details>;

using Teib_dump = Dump<vapi_msg_teib_dump, vapi_msg_teib_details>;

template <> inline void vapi_swap_to_be<vapi_msg_teib_details>(vapi_msg_teib_details *msg)
{
  vapi_msg_teib_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_teib_details>(vapi_msg_teib_details *msg)
{
  vapi_msg_teib_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_teib_details>()
{
  return ::vapi_msg_id_teib_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_teib_details>>()
{
  return ::vapi_msg_id_teib_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_teib_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_teib_details>(vapi_msg_id_teib_details);
}

template class Msg<vapi_msg_teib_details>;

using Teib_details = Msg<vapi_msg_teib_details>;
}
#endif
