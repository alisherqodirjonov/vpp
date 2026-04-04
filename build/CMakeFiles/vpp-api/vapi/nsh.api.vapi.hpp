#ifndef __included_hpp_nsh_api_json
#define __included_hpp_nsh_api_json

#include <vapi/vapi.hpp>
#include <vapi/nsh.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_nsh_add_del_entry>(vapi_msg_nsh_add_del_entry *msg)
{
  vapi_msg_nsh_add_del_entry_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_add_del_entry>(vapi_msg_nsh_add_del_entry *msg)
{
  vapi_msg_nsh_add_del_entry_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_add_del_entry>()
{
  return ::vapi_msg_id_nsh_add_del_entry; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_add_del_entry>>()
{
  return ::vapi_msg_id_nsh_add_del_entry; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_add_del_entry()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_add_del_entry>(vapi_msg_id_nsh_add_del_entry);
}

template <> inline vapi_msg_nsh_add_del_entry* vapi_alloc<vapi_msg_nsh_add_del_entry>(Connection &con)
{
  vapi_msg_nsh_add_del_entry* result = vapi_alloc_nsh_add_del_entry(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsh_add_del_entry>;

template class Request<vapi_msg_nsh_add_del_entry, vapi_msg_nsh_add_del_entry_reply>;

using Nsh_add_del_entry = Request<vapi_msg_nsh_add_del_entry, vapi_msg_nsh_add_del_entry_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nsh_add_del_entry_reply>(vapi_msg_nsh_add_del_entry_reply *msg)
{
  vapi_msg_nsh_add_del_entry_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_add_del_entry_reply>(vapi_msg_nsh_add_del_entry_reply *msg)
{
  vapi_msg_nsh_add_del_entry_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_add_del_entry_reply>()
{
  return ::vapi_msg_id_nsh_add_del_entry_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_add_del_entry_reply>>()
{
  return ::vapi_msg_id_nsh_add_del_entry_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_add_del_entry_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_add_del_entry_reply>(vapi_msg_id_nsh_add_del_entry_reply);
}

template class Msg<vapi_msg_nsh_add_del_entry_reply>;

using Nsh_add_del_entry_reply = Msg<vapi_msg_nsh_add_del_entry_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nsh_entry_dump>(vapi_msg_nsh_entry_dump *msg)
{
  vapi_msg_nsh_entry_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_entry_dump>(vapi_msg_nsh_entry_dump *msg)
{
  vapi_msg_nsh_entry_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_entry_dump>()
{
  return ::vapi_msg_id_nsh_entry_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_entry_dump>>()
{
  return ::vapi_msg_id_nsh_entry_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_entry_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_entry_dump>(vapi_msg_id_nsh_entry_dump);
}

template <> inline vapi_msg_nsh_entry_dump* vapi_alloc<vapi_msg_nsh_entry_dump>(Connection &con)
{
  vapi_msg_nsh_entry_dump* result = vapi_alloc_nsh_entry_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsh_entry_dump>;

template class Dump<vapi_msg_nsh_entry_dump, vapi_msg_nsh_entry_details>;

using Nsh_entry_dump = Dump<vapi_msg_nsh_entry_dump, vapi_msg_nsh_entry_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nsh_entry_details>(vapi_msg_nsh_entry_details *msg)
{
  vapi_msg_nsh_entry_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_entry_details>(vapi_msg_nsh_entry_details *msg)
{
  vapi_msg_nsh_entry_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_entry_details>()
{
  return ::vapi_msg_id_nsh_entry_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_entry_details>>()
{
  return ::vapi_msg_id_nsh_entry_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_entry_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_entry_details>(vapi_msg_id_nsh_entry_details);
}

template class Msg<vapi_msg_nsh_entry_details>;

using Nsh_entry_details = Msg<vapi_msg_nsh_entry_details>;
template <> inline void vapi_swap_to_be<vapi_msg_nsh_add_del_map>(vapi_msg_nsh_add_del_map *msg)
{
  vapi_msg_nsh_add_del_map_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_add_del_map>(vapi_msg_nsh_add_del_map *msg)
{
  vapi_msg_nsh_add_del_map_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_add_del_map>()
{
  return ::vapi_msg_id_nsh_add_del_map; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_add_del_map>>()
{
  return ::vapi_msg_id_nsh_add_del_map; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_add_del_map()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_add_del_map>(vapi_msg_id_nsh_add_del_map);
}

template <> inline vapi_msg_nsh_add_del_map* vapi_alloc<vapi_msg_nsh_add_del_map>(Connection &con)
{
  vapi_msg_nsh_add_del_map* result = vapi_alloc_nsh_add_del_map(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsh_add_del_map>;

template class Request<vapi_msg_nsh_add_del_map, vapi_msg_nsh_add_del_map_reply>;

using Nsh_add_del_map = Request<vapi_msg_nsh_add_del_map, vapi_msg_nsh_add_del_map_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_nsh_add_del_map_reply>(vapi_msg_nsh_add_del_map_reply *msg)
{
  vapi_msg_nsh_add_del_map_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_add_del_map_reply>(vapi_msg_nsh_add_del_map_reply *msg)
{
  vapi_msg_nsh_add_del_map_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_add_del_map_reply>()
{
  return ::vapi_msg_id_nsh_add_del_map_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_add_del_map_reply>>()
{
  return ::vapi_msg_id_nsh_add_del_map_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_add_del_map_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_add_del_map_reply>(vapi_msg_id_nsh_add_del_map_reply);
}

template class Msg<vapi_msg_nsh_add_del_map_reply>;

using Nsh_add_del_map_reply = Msg<vapi_msg_nsh_add_del_map_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_nsh_map_dump>(vapi_msg_nsh_map_dump *msg)
{
  vapi_msg_nsh_map_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_map_dump>(vapi_msg_nsh_map_dump *msg)
{
  vapi_msg_nsh_map_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_map_dump>()
{
  return ::vapi_msg_id_nsh_map_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_map_dump>>()
{
  return ::vapi_msg_id_nsh_map_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_map_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_map_dump>(vapi_msg_id_nsh_map_dump);
}

template <> inline vapi_msg_nsh_map_dump* vapi_alloc<vapi_msg_nsh_map_dump>(Connection &con)
{
  vapi_msg_nsh_map_dump* result = vapi_alloc_nsh_map_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_nsh_map_dump>;

template class Dump<vapi_msg_nsh_map_dump, vapi_msg_nsh_map_details>;

using Nsh_map_dump = Dump<vapi_msg_nsh_map_dump, vapi_msg_nsh_map_details>;

template <> inline void vapi_swap_to_be<vapi_msg_nsh_map_details>(vapi_msg_nsh_map_details *msg)
{
  vapi_msg_nsh_map_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_nsh_map_details>(vapi_msg_nsh_map_details *msg)
{
  vapi_msg_nsh_map_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_nsh_map_details>()
{
  return ::vapi_msg_id_nsh_map_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_nsh_map_details>>()
{
  return ::vapi_msg_id_nsh_map_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_nsh_map_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_nsh_map_details>(vapi_msg_id_nsh_map_details);
}

template class Msg<vapi_msg_nsh_map_details>;

using Nsh_map_details = Msg<vapi_msg_nsh_map_details>;
}
#endif
