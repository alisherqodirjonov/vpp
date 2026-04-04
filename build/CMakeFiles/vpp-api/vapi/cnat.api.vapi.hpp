#ifndef __included_hpp_cnat_api_json
#define __included_hpp_cnat_api_json

#include <vapi/vapi.hpp>
#include <vapi/cnat.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_cnat_translation_update>(vapi_msg_cnat_translation_update *msg)
{
  vapi_msg_cnat_translation_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_translation_update>(vapi_msg_cnat_translation_update *msg)
{
  vapi_msg_cnat_translation_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_translation_update>()
{
  return ::vapi_msg_id_cnat_translation_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_translation_update>>()
{
  return ::vapi_msg_id_cnat_translation_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_translation_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_translation_update>(vapi_msg_id_cnat_translation_update);
}

template <> inline vapi_msg_cnat_translation_update* vapi_alloc<vapi_msg_cnat_translation_update, size_t>(Connection &con, size_t translation_paths_array_size)
{
  vapi_msg_cnat_translation_update* result = vapi_alloc_cnat_translation_update(con.vapi_ctx, translation_paths_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_translation_update>;

template class Request<vapi_msg_cnat_translation_update, vapi_msg_cnat_translation_update_reply, size_t>;

using Cnat_translation_update = Request<vapi_msg_cnat_translation_update, vapi_msg_cnat_translation_update_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_translation_update_reply>(vapi_msg_cnat_translation_update_reply *msg)
{
  vapi_msg_cnat_translation_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_translation_update_reply>(vapi_msg_cnat_translation_update_reply *msg)
{
  vapi_msg_cnat_translation_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_translation_update_reply>()
{
  return ::vapi_msg_id_cnat_translation_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_translation_update_reply>>()
{
  return ::vapi_msg_id_cnat_translation_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_translation_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_translation_update_reply>(vapi_msg_id_cnat_translation_update_reply);
}

template class Msg<vapi_msg_cnat_translation_update_reply>;

using Cnat_translation_update_reply = Msg<vapi_msg_cnat_translation_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_translation_del>(vapi_msg_cnat_translation_del *msg)
{
  vapi_msg_cnat_translation_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_translation_del>(vapi_msg_cnat_translation_del *msg)
{
  vapi_msg_cnat_translation_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_translation_del>()
{
  return ::vapi_msg_id_cnat_translation_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_translation_del>>()
{
  return ::vapi_msg_id_cnat_translation_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_translation_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_translation_del>(vapi_msg_id_cnat_translation_del);
}

template <> inline vapi_msg_cnat_translation_del* vapi_alloc<vapi_msg_cnat_translation_del>(Connection &con)
{
  vapi_msg_cnat_translation_del* result = vapi_alloc_cnat_translation_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_translation_del>;

template class Request<vapi_msg_cnat_translation_del, vapi_msg_cnat_translation_del_reply>;

using Cnat_translation_del = Request<vapi_msg_cnat_translation_del, vapi_msg_cnat_translation_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_translation_del_reply>(vapi_msg_cnat_translation_del_reply *msg)
{
  vapi_msg_cnat_translation_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_translation_del_reply>(vapi_msg_cnat_translation_del_reply *msg)
{
  vapi_msg_cnat_translation_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_translation_del_reply>()
{
  return ::vapi_msg_id_cnat_translation_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_translation_del_reply>>()
{
  return ::vapi_msg_id_cnat_translation_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_translation_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_translation_del_reply>(vapi_msg_id_cnat_translation_del_reply);
}

template class Msg<vapi_msg_cnat_translation_del_reply>;

using Cnat_translation_del_reply = Msg<vapi_msg_cnat_translation_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_translation_details>(vapi_msg_cnat_translation_details *msg)
{
  vapi_msg_cnat_translation_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_translation_details>(vapi_msg_cnat_translation_details *msg)
{
  vapi_msg_cnat_translation_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_translation_details>()
{
  return ::vapi_msg_id_cnat_translation_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_translation_details>>()
{
  return ::vapi_msg_id_cnat_translation_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_translation_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_translation_details>(vapi_msg_id_cnat_translation_details);
}

template class Msg<vapi_msg_cnat_translation_details>;

using Cnat_translation_details = Msg<vapi_msg_cnat_translation_details>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_translation_dump>(vapi_msg_cnat_translation_dump *msg)
{
  vapi_msg_cnat_translation_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_translation_dump>(vapi_msg_cnat_translation_dump *msg)
{
  vapi_msg_cnat_translation_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_translation_dump>()
{
  return ::vapi_msg_id_cnat_translation_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_translation_dump>>()
{
  return ::vapi_msg_id_cnat_translation_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_translation_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_translation_dump>(vapi_msg_id_cnat_translation_dump);
}

template <> inline vapi_msg_cnat_translation_dump* vapi_alloc<vapi_msg_cnat_translation_dump>(Connection &con)
{
  vapi_msg_cnat_translation_dump* result = vapi_alloc_cnat_translation_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_translation_dump>;

template class Dump<vapi_msg_cnat_translation_dump, vapi_msg_cnat_translation_details>;

using Cnat_translation_dump = Dump<vapi_msg_cnat_translation_dump, vapi_msg_cnat_translation_details>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_session_purge>(vapi_msg_cnat_session_purge *msg)
{
  vapi_msg_cnat_session_purge_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_session_purge>(vapi_msg_cnat_session_purge *msg)
{
  vapi_msg_cnat_session_purge_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_session_purge>()
{
  return ::vapi_msg_id_cnat_session_purge; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_session_purge>>()
{
  return ::vapi_msg_id_cnat_session_purge; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_session_purge()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_session_purge>(vapi_msg_id_cnat_session_purge);
}

template <> inline vapi_msg_cnat_session_purge* vapi_alloc<vapi_msg_cnat_session_purge>(Connection &con)
{
  vapi_msg_cnat_session_purge* result = vapi_alloc_cnat_session_purge(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_session_purge>;

template class Request<vapi_msg_cnat_session_purge, vapi_msg_cnat_session_purge_reply>;

using Cnat_session_purge = Request<vapi_msg_cnat_session_purge, vapi_msg_cnat_session_purge_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_session_purge_reply>(vapi_msg_cnat_session_purge_reply *msg)
{
  vapi_msg_cnat_session_purge_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_session_purge_reply>(vapi_msg_cnat_session_purge_reply *msg)
{
  vapi_msg_cnat_session_purge_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_session_purge_reply>()
{
  return ::vapi_msg_id_cnat_session_purge_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_session_purge_reply>>()
{
  return ::vapi_msg_id_cnat_session_purge_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_session_purge_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_session_purge_reply>(vapi_msg_id_cnat_session_purge_reply);
}

template class Msg<vapi_msg_cnat_session_purge_reply>;

using Cnat_session_purge_reply = Msg<vapi_msg_cnat_session_purge_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_session_details>(vapi_msg_cnat_session_details *msg)
{
  vapi_msg_cnat_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_session_details>(vapi_msg_cnat_session_details *msg)
{
  vapi_msg_cnat_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_session_details>()
{
  return ::vapi_msg_id_cnat_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_session_details>>()
{
  return ::vapi_msg_id_cnat_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_session_details>(vapi_msg_id_cnat_session_details);
}

template class Msg<vapi_msg_cnat_session_details>;

using Cnat_session_details = Msg<vapi_msg_cnat_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_session_dump>(vapi_msg_cnat_session_dump *msg)
{
  vapi_msg_cnat_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_session_dump>(vapi_msg_cnat_session_dump *msg)
{
  vapi_msg_cnat_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_session_dump>()
{
  return ::vapi_msg_id_cnat_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_session_dump>>()
{
  return ::vapi_msg_id_cnat_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_session_dump>(vapi_msg_id_cnat_session_dump);
}

template <> inline vapi_msg_cnat_session_dump* vapi_alloc<vapi_msg_cnat_session_dump>(Connection &con)
{
  vapi_msg_cnat_session_dump* result = vapi_alloc_cnat_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_session_dump>;

template class Dump<vapi_msg_cnat_session_dump, vapi_msg_cnat_session_details>;

using Cnat_session_dump = Dump<vapi_msg_cnat_session_dump, vapi_msg_cnat_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_set_snat_addresses>(vapi_msg_cnat_set_snat_addresses *msg)
{
  vapi_msg_cnat_set_snat_addresses_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_set_snat_addresses>(vapi_msg_cnat_set_snat_addresses *msg)
{
  vapi_msg_cnat_set_snat_addresses_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_set_snat_addresses>()
{
  return ::vapi_msg_id_cnat_set_snat_addresses; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_set_snat_addresses>>()
{
  return ::vapi_msg_id_cnat_set_snat_addresses; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_set_snat_addresses()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_set_snat_addresses>(vapi_msg_id_cnat_set_snat_addresses);
}

template <> inline vapi_msg_cnat_set_snat_addresses* vapi_alloc<vapi_msg_cnat_set_snat_addresses>(Connection &con)
{
  vapi_msg_cnat_set_snat_addresses* result = vapi_alloc_cnat_set_snat_addresses(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_set_snat_addresses>;

template class Request<vapi_msg_cnat_set_snat_addresses, vapi_msg_cnat_set_snat_addresses_reply>;

using Cnat_set_snat_addresses = Request<vapi_msg_cnat_set_snat_addresses, vapi_msg_cnat_set_snat_addresses_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_set_snat_addresses_reply>(vapi_msg_cnat_set_snat_addresses_reply *msg)
{
  vapi_msg_cnat_set_snat_addresses_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_set_snat_addresses_reply>(vapi_msg_cnat_set_snat_addresses_reply *msg)
{
  vapi_msg_cnat_set_snat_addresses_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_set_snat_addresses_reply>()
{
  return ::vapi_msg_id_cnat_set_snat_addresses_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_set_snat_addresses_reply>>()
{
  return ::vapi_msg_id_cnat_set_snat_addresses_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_set_snat_addresses_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_set_snat_addresses_reply>(vapi_msg_id_cnat_set_snat_addresses_reply);
}

template class Msg<vapi_msg_cnat_set_snat_addresses_reply>;

using Cnat_set_snat_addresses_reply = Msg<vapi_msg_cnat_set_snat_addresses_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_get_snat_addresses>(vapi_msg_cnat_get_snat_addresses *msg)
{
  vapi_msg_cnat_get_snat_addresses_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_get_snat_addresses>(vapi_msg_cnat_get_snat_addresses *msg)
{
  vapi_msg_cnat_get_snat_addresses_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_get_snat_addresses>()
{
  return ::vapi_msg_id_cnat_get_snat_addresses; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_get_snat_addresses>>()
{
  return ::vapi_msg_id_cnat_get_snat_addresses; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_get_snat_addresses()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_get_snat_addresses>(vapi_msg_id_cnat_get_snat_addresses);
}

template <> inline vapi_msg_cnat_get_snat_addresses* vapi_alloc<vapi_msg_cnat_get_snat_addresses>(Connection &con)
{
  vapi_msg_cnat_get_snat_addresses* result = vapi_alloc_cnat_get_snat_addresses(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_get_snat_addresses>;

template class Request<vapi_msg_cnat_get_snat_addresses, vapi_msg_cnat_get_snat_addresses_reply>;

using Cnat_get_snat_addresses = Request<vapi_msg_cnat_get_snat_addresses, vapi_msg_cnat_get_snat_addresses_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_get_snat_addresses_reply>(vapi_msg_cnat_get_snat_addresses_reply *msg)
{
  vapi_msg_cnat_get_snat_addresses_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_get_snat_addresses_reply>(vapi_msg_cnat_get_snat_addresses_reply *msg)
{
  vapi_msg_cnat_get_snat_addresses_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_get_snat_addresses_reply>()
{
  return ::vapi_msg_id_cnat_get_snat_addresses_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_get_snat_addresses_reply>>()
{
  return ::vapi_msg_id_cnat_get_snat_addresses_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_get_snat_addresses_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_get_snat_addresses_reply>(vapi_msg_id_cnat_get_snat_addresses_reply);
}

template class Msg<vapi_msg_cnat_get_snat_addresses_reply>;

using Cnat_get_snat_addresses_reply = Msg<vapi_msg_cnat_get_snat_addresses_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>(vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg)
{
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>(vapi_msg_cnat_snat_policy_add_del_exclude_pfx *msg)
{
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_snat_policy_add_del_exclude_pfx()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>(vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx);
}

template <> inline vapi_msg_cnat_snat_policy_add_del_exclude_pfx* vapi_alloc<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>(Connection &con)
{
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx* result = vapi_alloc_cnat_snat_policy_add_del_exclude_pfx(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_snat_policy_add_del_exclude_pfx>;

template class Request<vapi_msg_cnat_snat_policy_add_del_exclude_pfx, vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>;

using Cnat_snat_policy_add_del_exclude_pfx = Request<vapi_msg_cnat_snat_policy_add_del_exclude_pfx, vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply *msg)
{
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>(vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply *msg)
{
  vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_snat_policy_add_del_exclude_pfx_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>(vapi_msg_id_cnat_snat_policy_add_del_exclude_pfx_reply);
}

template class Msg<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>;

using Cnat_snat_policy_add_del_exclude_pfx_reply = Msg<vapi_msg_cnat_snat_policy_add_del_exclude_pfx_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_snat_policy_add_del_if>(vapi_msg_cnat_snat_policy_add_del_if *msg)
{
  vapi_msg_cnat_snat_policy_add_del_if_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_snat_policy_add_del_if>(vapi_msg_cnat_snat_policy_add_del_if *msg)
{
  vapi_msg_cnat_snat_policy_add_del_if_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_snat_policy_add_del_if>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_if; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_snat_policy_add_del_if>>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_if; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_snat_policy_add_del_if()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_snat_policy_add_del_if>(vapi_msg_id_cnat_snat_policy_add_del_if);
}

template <> inline vapi_msg_cnat_snat_policy_add_del_if* vapi_alloc<vapi_msg_cnat_snat_policy_add_del_if>(Connection &con)
{
  vapi_msg_cnat_snat_policy_add_del_if* result = vapi_alloc_cnat_snat_policy_add_del_if(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_snat_policy_add_del_if>;

template class Request<vapi_msg_cnat_snat_policy_add_del_if, vapi_msg_cnat_snat_policy_add_del_if_reply>;

using Cnat_snat_policy_add_del_if = Request<vapi_msg_cnat_snat_policy_add_del_if, vapi_msg_cnat_snat_policy_add_del_if_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_snat_policy_add_del_if_reply>(vapi_msg_cnat_snat_policy_add_del_if_reply *msg)
{
  vapi_msg_cnat_snat_policy_add_del_if_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_snat_policy_add_del_if_reply>(vapi_msg_cnat_snat_policy_add_del_if_reply *msg)
{
  vapi_msg_cnat_snat_policy_add_del_if_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_snat_policy_add_del_if_reply>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_if_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_snat_policy_add_del_if_reply>>()
{
  return ::vapi_msg_id_cnat_snat_policy_add_del_if_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_snat_policy_add_del_if_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_snat_policy_add_del_if_reply>(vapi_msg_id_cnat_snat_policy_add_del_if_reply);
}

template class Msg<vapi_msg_cnat_snat_policy_add_del_if_reply>;

using Cnat_snat_policy_add_del_if_reply = Msg<vapi_msg_cnat_snat_policy_add_del_if_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_cnat_set_snat_policy>(vapi_msg_cnat_set_snat_policy *msg)
{
  vapi_msg_cnat_set_snat_policy_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_set_snat_policy>(vapi_msg_cnat_set_snat_policy *msg)
{
  vapi_msg_cnat_set_snat_policy_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_set_snat_policy>()
{
  return ::vapi_msg_id_cnat_set_snat_policy; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_set_snat_policy>>()
{
  return ::vapi_msg_id_cnat_set_snat_policy; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_set_snat_policy()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_set_snat_policy>(vapi_msg_id_cnat_set_snat_policy);
}

template <> inline vapi_msg_cnat_set_snat_policy* vapi_alloc<vapi_msg_cnat_set_snat_policy>(Connection &con)
{
  vapi_msg_cnat_set_snat_policy* result = vapi_alloc_cnat_set_snat_policy(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_cnat_set_snat_policy>;

template class Request<vapi_msg_cnat_set_snat_policy, vapi_msg_cnat_set_snat_policy_reply>;

using Cnat_set_snat_policy = Request<vapi_msg_cnat_set_snat_policy, vapi_msg_cnat_set_snat_policy_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_cnat_set_snat_policy_reply>(vapi_msg_cnat_set_snat_policy_reply *msg)
{
  vapi_msg_cnat_set_snat_policy_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_cnat_set_snat_policy_reply>(vapi_msg_cnat_set_snat_policy_reply *msg)
{
  vapi_msg_cnat_set_snat_policy_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_cnat_set_snat_policy_reply>()
{
  return ::vapi_msg_id_cnat_set_snat_policy_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_cnat_set_snat_policy_reply>>()
{
  return ::vapi_msg_id_cnat_set_snat_policy_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_cnat_set_snat_policy_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_cnat_set_snat_policy_reply>(vapi_msg_id_cnat_set_snat_policy_reply);
}

template class Msg<vapi_msg_cnat_set_snat_policy_reply>;

using Cnat_set_snat_policy_reply = Msg<vapi_msg_cnat_set_snat_policy_reply>;
}
#endif
