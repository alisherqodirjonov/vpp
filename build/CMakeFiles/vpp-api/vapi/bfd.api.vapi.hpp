#ifndef __included_hpp_bfd_api_json
#define __included_hpp_bfd_api_json

#include <vapi/vapi.hpp>
#include <vapi/bfd.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_set_echo_source>(vapi_msg_bfd_udp_set_echo_source *msg)
{
  vapi_msg_bfd_udp_set_echo_source_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_set_echo_source>(vapi_msg_bfd_udp_set_echo_source *msg)
{
  vapi_msg_bfd_udp_set_echo_source_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_set_echo_source>()
{
  return ::vapi_msg_id_bfd_udp_set_echo_source; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_set_echo_source>>()
{
  return ::vapi_msg_id_bfd_udp_set_echo_source; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_set_echo_source()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_set_echo_source>(vapi_msg_id_bfd_udp_set_echo_source);
}

template <> inline vapi_msg_bfd_udp_set_echo_source* vapi_alloc<vapi_msg_bfd_udp_set_echo_source>(Connection &con)
{
  vapi_msg_bfd_udp_set_echo_source* result = vapi_alloc_bfd_udp_set_echo_source(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_set_echo_source>;

template class Request<vapi_msg_bfd_udp_set_echo_source, vapi_msg_bfd_udp_set_echo_source_reply>;

using Bfd_udp_set_echo_source = Request<vapi_msg_bfd_udp_set_echo_source, vapi_msg_bfd_udp_set_echo_source_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_set_echo_source_reply>(vapi_msg_bfd_udp_set_echo_source_reply *msg)
{
  vapi_msg_bfd_udp_set_echo_source_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_set_echo_source_reply>(vapi_msg_bfd_udp_set_echo_source_reply *msg)
{
  vapi_msg_bfd_udp_set_echo_source_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_set_echo_source_reply>()
{
  return ::vapi_msg_id_bfd_udp_set_echo_source_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_set_echo_source_reply>>()
{
  return ::vapi_msg_id_bfd_udp_set_echo_source_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_set_echo_source_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_set_echo_source_reply>(vapi_msg_id_bfd_udp_set_echo_source_reply);
}

template class Msg<vapi_msg_bfd_udp_set_echo_source_reply>;

using Bfd_udp_set_echo_source_reply = Msg<vapi_msg_bfd_udp_set_echo_source_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_del_echo_source>(vapi_msg_bfd_udp_del_echo_source *msg)
{
  vapi_msg_bfd_udp_del_echo_source_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_del_echo_source>(vapi_msg_bfd_udp_del_echo_source *msg)
{
  vapi_msg_bfd_udp_del_echo_source_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_del_echo_source>()
{
  return ::vapi_msg_id_bfd_udp_del_echo_source; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_del_echo_source>>()
{
  return ::vapi_msg_id_bfd_udp_del_echo_source; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_del_echo_source()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_del_echo_source>(vapi_msg_id_bfd_udp_del_echo_source);
}

template <> inline vapi_msg_bfd_udp_del_echo_source* vapi_alloc<vapi_msg_bfd_udp_del_echo_source>(Connection &con)
{
  vapi_msg_bfd_udp_del_echo_source* result = vapi_alloc_bfd_udp_del_echo_source(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_del_echo_source>;

template class Request<vapi_msg_bfd_udp_del_echo_source, vapi_msg_bfd_udp_del_echo_source_reply>;

using Bfd_udp_del_echo_source = Request<vapi_msg_bfd_udp_del_echo_source, vapi_msg_bfd_udp_del_echo_source_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_del_echo_source_reply>(vapi_msg_bfd_udp_del_echo_source_reply *msg)
{
  vapi_msg_bfd_udp_del_echo_source_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_del_echo_source_reply>(vapi_msg_bfd_udp_del_echo_source_reply *msg)
{
  vapi_msg_bfd_udp_del_echo_source_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_del_echo_source_reply>()
{
  return ::vapi_msg_id_bfd_udp_del_echo_source_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_del_echo_source_reply>>()
{
  return ::vapi_msg_id_bfd_udp_del_echo_source_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_del_echo_source_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_del_echo_source_reply>(vapi_msg_id_bfd_udp_del_echo_source_reply);
}

template class Msg<vapi_msg_bfd_udp_del_echo_source_reply>;

using Bfd_udp_del_echo_source_reply = Msg<vapi_msg_bfd_udp_del_echo_source_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_get_echo_source>(vapi_msg_bfd_udp_get_echo_source *msg)
{
  vapi_msg_bfd_udp_get_echo_source_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_get_echo_source>(vapi_msg_bfd_udp_get_echo_source *msg)
{
  vapi_msg_bfd_udp_get_echo_source_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_get_echo_source>()
{
  return ::vapi_msg_id_bfd_udp_get_echo_source; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_get_echo_source>>()
{
  return ::vapi_msg_id_bfd_udp_get_echo_source; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_get_echo_source()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_get_echo_source>(vapi_msg_id_bfd_udp_get_echo_source);
}

template <> inline vapi_msg_bfd_udp_get_echo_source* vapi_alloc<vapi_msg_bfd_udp_get_echo_source>(Connection &con)
{
  vapi_msg_bfd_udp_get_echo_source* result = vapi_alloc_bfd_udp_get_echo_source(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_get_echo_source>;

template class Request<vapi_msg_bfd_udp_get_echo_source, vapi_msg_bfd_udp_get_echo_source_reply>;

using Bfd_udp_get_echo_source = Request<vapi_msg_bfd_udp_get_echo_source, vapi_msg_bfd_udp_get_echo_source_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_get_echo_source_reply>(vapi_msg_bfd_udp_get_echo_source_reply *msg)
{
  vapi_msg_bfd_udp_get_echo_source_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_get_echo_source_reply>(vapi_msg_bfd_udp_get_echo_source_reply *msg)
{
  vapi_msg_bfd_udp_get_echo_source_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_get_echo_source_reply>()
{
  return ::vapi_msg_id_bfd_udp_get_echo_source_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_get_echo_source_reply>>()
{
  return ::vapi_msg_id_bfd_udp_get_echo_source_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_get_echo_source_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_get_echo_source_reply>(vapi_msg_id_bfd_udp_get_echo_source_reply);
}

template class Msg<vapi_msg_bfd_udp_get_echo_source_reply>;

using Bfd_udp_get_echo_source_reply = Msg<vapi_msg_bfd_udp_get_echo_source_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_add>(vapi_msg_bfd_udp_add *msg)
{
  vapi_msg_bfd_udp_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_add>(vapi_msg_bfd_udp_add *msg)
{
  vapi_msg_bfd_udp_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_add>()
{
  return ::vapi_msg_id_bfd_udp_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_add>>()
{
  return ::vapi_msg_id_bfd_udp_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_add>(vapi_msg_id_bfd_udp_add);
}

template <> inline vapi_msg_bfd_udp_add* vapi_alloc<vapi_msg_bfd_udp_add>(Connection &con)
{
  vapi_msg_bfd_udp_add* result = vapi_alloc_bfd_udp_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_add>;

template class Request<vapi_msg_bfd_udp_add, vapi_msg_bfd_udp_add_reply>;

using Bfd_udp_add = Request<vapi_msg_bfd_udp_add, vapi_msg_bfd_udp_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_add_reply>(vapi_msg_bfd_udp_add_reply *msg)
{
  vapi_msg_bfd_udp_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_add_reply>(vapi_msg_bfd_udp_add_reply *msg)
{
  vapi_msg_bfd_udp_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_add_reply>()
{
  return ::vapi_msg_id_bfd_udp_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_add_reply>>()
{
  return ::vapi_msg_id_bfd_udp_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_add_reply>(vapi_msg_id_bfd_udp_add_reply);
}

template class Msg<vapi_msg_bfd_udp_add_reply>;

using Bfd_udp_add_reply = Msg<vapi_msg_bfd_udp_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_upd>(vapi_msg_bfd_udp_upd *msg)
{
  vapi_msg_bfd_udp_upd_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_upd>(vapi_msg_bfd_udp_upd *msg)
{
  vapi_msg_bfd_udp_upd_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_upd>()
{
  return ::vapi_msg_id_bfd_udp_upd; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_upd>>()
{
  return ::vapi_msg_id_bfd_udp_upd; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_upd()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_upd>(vapi_msg_id_bfd_udp_upd);
}

template <> inline vapi_msg_bfd_udp_upd* vapi_alloc<vapi_msg_bfd_udp_upd>(Connection &con)
{
  vapi_msg_bfd_udp_upd* result = vapi_alloc_bfd_udp_upd(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_upd>;

template class Request<vapi_msg_bfd_udp_upd, vapi_msg_bfd_udp_upd_reply>;

using Bfd_udp_upd = Request<vapi_msg_bfd_udp_upd, vapi_msg_bfd_udp_upd_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_upd_reply>(vapi_msg_bfd_udp_upd_reply *msg)
{
  vapi_msg_bfd_udp_upd_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_upd_reply>(vapi_msg_bfd_udp_upd_reply *msg)
{
  vapi_msg_bfd_udp_upd_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_upd_reply>()
{
  return ::vapi_msg_id_bfd_udp_upd_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_upd_reply>>()
{
  return ::vapi_msg_id_bfd_udp_upd_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_upd_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_upd_reply>(vapi_msg_id_bfd_udp_upd_reply);
}

template class Msg<vapi_msg_bfd_udp_upd_reply>;

using Bfd_udp_upd_reply = Msg<vapi_msg_bfd_udp_upd_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_mod>(vapi_msg_bfd_udp_mod *msg)
{
  vapi_msg_bfd_udp_mod_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_mod>(vapi_msg_bfd_udp_mod *msg)
{
  vapi_msg_bfd_udp_mod_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_mod>()
{
  return ::vapi_msg_id_bfd_udp_mod; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_mod>>()
{
  return ::vapi_msg_id_bfd_udp_mod; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_mod()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_mod>(vapi_msg_id_bfd_udp_mod);
}

template <> inline vapi_msg_bfd_udp_mod* vapi_alloc<vapi_msg_bfd_udp_mod>(Connection &con)
{
  vapi_msg_bfd_udp_mod* result = vapi_alloc_bfd_udp_mod(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_mod>;

template class Request<vapi_msg_bfd_udp_mod, vapi_msg_bfd_udp_mod_reply>;

using Bfd_udp_mod = Request<vapi_msg_bfd_udp_mod, vapi_msg_bfd_udp_mod_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_mod_reply>(vapi_msg_bfd_udp_mod_reply *msg)
{
  vapi_msg_bfd_udp_mod_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_mod_reply>(vapi_msg_bfd_udp_mod_reply *msg)
{
  vapi_msg_bfd_udp_mod_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_mod_reply>()
{
  return ::vapi_msg_id_bfd_udp_mod_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_mod_reply>>()
{
  return ::vapi_msg_id_bfd_udp_mod_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_mod_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_mod_reply>(vapi_msg_id_bfd_udp_mod_reply);
}

template class Msg<vapi_msg_bfd_udp_mod_reply>;

using Bfd_udp_mod_reply = Msg<vapi_msg_bfd_udp_mod_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_del>(vapi_msg_bfd_udp_del *msg)
{
  vapi_msg_bfd_udp_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_del>(vapi_msg_bfd_udp_del *msg)
{
  vapi_msg_bfd_udp_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_del>()
{
  return ::vapi_msg_id_bfd_udp_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_del>>()
{
  return ::vapi_msg_id_bfd_udp_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_del>(vapi_msg_id_bfd_udp_del);
}

template <> inline vapi_msg_bfd_udp_del* vapi_alloc<vapi_msg_bfd_udp_del>(Connection &con)
{
  vapi_msg_bfd_udp_del* result = vapi_alloc_bfd_udp_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_del>;

template class Request<vapi_msg_bfd_udp_del, vapi_msg_bfd_udp_del_reply>;

using Bfd_udp_del = Request<vapi_msg_bfd_udp_del, vapi_msg_bfd_udp_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_del_reply>(vapi_msg_bfd_udp_del_reply *msg)
{
  vapi_msg_bfd_udp_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_del_reply>(vapi_msg_bfd_udp_del_reply *msg)
{
  vapi_msg_bfd_udp_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_del_reply>()
{
  return ::vapi_msg_id_bfd_udp_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_del_reply>>()
{
  return ::vapi_msg_id_bfd_udp_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_del_reply>(vapi_msg_id_bfd_udp_del_reply);
}

template class Msg<vapi_msg_bfd_udp_del_reply>;

using Bfd_udp_del_reply = Msg<vapi_msg_bfd_udp_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_session_dump>(vapi_msg_bfd_udp_session_dump *msg)
{
  vapi_msg_bfd_udp_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_session_dump>(vapi_msg_bfd_udp_session_dump *msg)
{
  vapi_msg_bfd_udp_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_session_dump>()
{
  return ::vapi_msg_id_bfd_udp_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_session_dump>>()
{
  return ::vapi_msg_id_bfd_udp_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_session_dump>(vapi_msg_id_bfd_udp_session_dump);
}

template <> inline vapi_msg_bfd_udp_session_dump* vapi_alloc<vapi_msg_bfd_udp_session_dump>(Connection &con)
{
  vapi_msg_bfd_udp_session_dump* result = vapi_alloc_bfd_udp_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_session_dump>;

template class Dump<vapi_msg_bfd_udp_session_dump, vapi_msg_bfd_udp_session_details>;

using Bfd_udp_session_dump = Dump<vapi_msg_bfd_udp_session_dump, vapi_msg_bfd_udp_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_session_details>(vapi_msg_bfd_udp_session_details *msg)
{
  vapi_msg_bfd_udp_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_session_details>(vapi_msg_bfd_udp_session_details *msg)
{
  vapi_msg_bfd_udp_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_session_details>()
{
  return ::vapi_msg_id_bfd_udp_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_session_details>>()
{
  return ::vapi_msg_id_bfd_udp_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_session_details>(vapi_msg_id_bfd_udp_session_details);
}

template class Msg<vapi_msg_bfd_udp_session_details>;

using Bfd_udp_session_details = Msg<vapi_msg_bfd_udp_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_session_set_flags>(vapi_msg_bfd_udp_session_set_flags *msg)
{
  vapi_msg_bfd_udp_session_set_flags_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_session_set_flags>(vapi_msg_bfd_udp_session_set_flags *msg)
{
  vapi_msg_bfd_udp_session_set_flags_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_session_set_flags>()
{
  return ::vapi_msg_id_bfd_udp_session_set_flags; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_session_set_flags>>()
{
  return ::vapi_msg_id_bfd_udp_session_set_flags; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_session_set_flags()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_session_set_flags>(vapi_msg_id_bfd_udp_session_set_flags);
}

template <> inline vapi_msg_bfd_udp_session_set_flags* vapi_alloc<vapi_msg_bfd_udp_session_set_flags>(Connection &con)
{
  vapi_msg_bfd_udp_session_set_flags* result = vapi_alloc_bfd_udp_session_set_flags(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_session_set_flags>;

template class Request<vapi_msg_bfd_udp_session_set_flags, vapi_msg_bfd_udp_session_set_flags_reply>;

using Bfd_udp_session_set_flags = Request<vapi_msg_bfd_udp_session_set_flags, vapi_msg_bfd_udp_session_set_flags_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_session_set_flags_reply>(vapi_msg_bfd_udp_session_set_flags_reply *msg)
{
  vapi_msg_bfd_udp_session_set_flags_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_session_set_flags_reply>(vapi_msg_bfd_udp_session_set_flags_reply *msg)
{
  vapi_msg_bfd_udp_session_set_flags_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_session_set_flags_reply>()
{
  return ::vapi_msg_id_bfd_udp_session_set_flags_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_session_set_flags_reply>>()
{
  return ::vapi_msg_id_bfd_udp_session_set_flags_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_session_set_flags_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_session_set_flags_reply>(vapi_msg_id_bfd_udp_session_set_flags_reply);
}

template class Msg<vapi_msg_bfd_udp_session_set_flags_reply>;

using Bfd_udp_session_set_flags_reply = Msg<vapi_msg_bfd_udp_session_set_flags_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_want_bfd_events>(vapi_msg_want_bfd_events *msg)
{
  vapi_msg_want_bfd_events_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_bfd_events>(vapi_msg_want_bfd_events *msg)
{
  vapi_msg_want_bfd_events_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_bfd_events>()
{
  return ::vapi_msg_id_want_bfd_events; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_bfd_events>>()
{
  return ::vapi_msg_id_want_bfd_events; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_bfd_events()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_bfd_events>(vapi_msg_id_want_bfd_events);
}

template <> inline vapi_msg_want_bfd_events* vapi_alloc<vapi_msg_want_bfd_events>(Connection &con)
{
  vapi_msg_want_bfd_events* result = vapi_alloc_want_bfd_events(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_want_bfd_events>;

template class Request<vapi_msg_want_bfd_events, vapi_msg_want_bfd_events_reply>;

using Want_bfd_events = Request<vapi_msg_want_bfd_events, vapi_msg_want_bfd_events_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_want_bfd_events_reply>(vapi_msg_want_bfd_events_reply *msg)
{
  vapi_msg_want_bfd_events_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_want_bfd_events_reply>(vapi_msg_want_bfd_events_reply *msg)
{
  vapi_msg_want_bfd_events_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_want_bfd_events_reply>()
{
  return ::vapi_msg_id_want_bfd_events_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_want_bfd_events_reply>>()
{
  return ::vapi_msg_id_want_bfd_events_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_want_bfd_events_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_want_bfd_events_reply>(vapi_msg_id_want_bfd_events_reply);
}

template class Msg<vapi_msg_want_bfd_events_reply>;

using Want_bfd_events_reply = Msg<vapi_msg_want_bfd_events_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_session_event>(vapi_msg_bfd_udp_session_event *msg)
{
  vapi_msg_bfd_udp_session_event_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_session_event>(vapi_msg_bfd_udp_session_event *msg)
{
  vapi_msg_bfd_udp_session_event_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_session_event>()
{
  return ::vapi_msg_id_bfd_udp_session_event; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_session_event>>()
{
  return ::vapi_msg_id_bfd_udp_session_event; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_session_event()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_session_event>(vapi_msg_id_bfd_udp_session_event);
}

template class Msg<vapi_msg_bfd_udp_session_event>;

using Bfd_udp_session_event = Msg<vapi_msg_bfd_udp_session_event>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_auth_set_key>(vapi_msg_bfd_auth_set_key *msg)
{
  vapi_msg_bfd_auth_set_key_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_auth_set_key>(vapi_msg_bfd_auth_set_key *msg)
{
  vapi_msg_bfd_auth_set_key_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_auth_set_key>()
{
  return ::vapi_msg_id_bfd_auth_set_key; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_auth_set_key>>()
{
  return ::vapi_msg_id_bfd_auth_set_key; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_auth_set_key()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_auth_set_key>(vapi_msg_id_bfd_auth_set_key);
}

template <> inline vapi_msg_bfd_auth_set_key* vapi_alloc<vapi_msg_bfd_auth_set_key>(Connection &con)
{
  vapi_msg_bfd_auth_set_key* result = vapi_alloc_bfd_auth_set_key(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_auth_set_key>;

template class Request<vapi_msg_bfd_auth_set_key, vapi_msg_bfd_auth_set_key_reply>;

using Bfd_auth_set_key = Request<vapi_msg_bfd_auth_set_key, vapi_msg_bfd_auth_set_key_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_auth_set_key_reply>(vapi_msg_bfd_auth_set_key_reply *msg)
{
  vapi_msg_bfd_auth_set_key_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_auth_set_key_reply>(vapi_msg_bfd_auth_set_key_reply *msg)
{
  vapi_msg_bfd_auth_set_key_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_auth_set_key_reply>()
{
  return ::vapi_msg_id_bfd_auth_set_key_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_auth_set_key_reply>>()
{
  return ::vapi_msg_id_bfd_auth_set_key_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_auth_set_key_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_auth_set_key_reply>(vapi_msg_id_bfd_auth_set_key_reply);
}

template class Msg<vapi_msg_bfd_auth_set_key_reply>;

using Bfd_auth_set_key_reply = Msg<vapi_msg_bfd_auth_set_key_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_auth_del_key>(vapi_msg_bfd_auth_del_key *msg)
{
  vapi_msg_bfd_auth_del_key_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_auth_del_key>(vapi_msg_bfd_auth_del_key *msg)
{
  vapi_msg_bfd_auth_del_key_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_auth_del_key>()
{
  return ::vapi_msg_id_bfd_auth_del_key; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_auth_del_key>>()
{
  return ::vapi_msg_id_bfd_auth_del_key; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_auth_del_key()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_auth_del_key>(vapi_msg_id_bfd_auth_del_key);
}

template <> inline vapi_msg_bfd_auth_del_key* vapi_alloc<vapi_msg_bfd_auth_del_key>(Connection &con)
{
  vapi_msg_bfd_auth_del_key* result = vapi_alloc_bfd_auth_del_key(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_auth_del_key>;

template class Request<vapi_msg_bfd_auth_del_key, vapi_msg_bfd_auth_del_key_reply>;

using Bfd_auth_del_key = Request<vapi_msg_bfd_auth_del_key, vapi_msg_bfd_auth_del_key_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_auth_del_key_reply>(vapi_msg_bfd_auth_del_key_reply *msg)
{
  vapi_msg_bfd_auth_del_key_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_auth_del_key_reply>(vapi_msg_bfd_auth_del_key_reply *msg)
{
  vapi_msg_bfd_auth_del_key_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_auth_del_key_reply>()
{
  return ::vapi_msg_id_bfd_auth_del_key_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_auth_del_key_reply>>()
{
  return ::vapi_msg_id_bfd_auth_del_key_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_auth_del_key_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_auth_del_key_reply>(vapi_msg_id_bfd_auth_del_key_reply);
}

template class Msg<vapi_msg_bfd_auth_del_key_reply>;

using Bfd_auth_del_key_reply = Msg<vapi_msg_bfd_auth_del_key_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_auth_keys_dump>(vapi_msg_bfd_auth_keys_dump *msg)
{
  vapi_msg_bfd_auth_keys_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_auth_keys_dump>(vapi_msg_bfd_auth_keys_dump *msg)
{
  vapi_msg_bfd_auth_keys_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_auth_keys_dump>()
{
  return ::vapi_msg_id_bfd_auth_keys_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_auth_keys_dump>>()
{
  return ::vapi_msg_id_bfd_auth_keys_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_auth_keys_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_auth_keys_dump>(vapi_msg_id_bfd_auth_keys_dump);
}

template <> inline vapi_msg_bfd_auth_keys_dump* vapi_alloc<vapi_msg_bfd_auth_keys_dump>(Connection &con)
{
  vapi_msg_bfd_auth_keys_dump* result = vapi_alloc_bfd_auth_keys_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_auth_keys_dump>;

template class Dump<vapi_msg_bfd_auth_keys_dump, vapi_msg_bfd_auth_keys_details>;

using Bfd_auth_keys_dump = Dump<vapi_msg_bfd_auth_keys_dump, vapi_msg_bfd_auth_keys_details>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_auth_keys_details>(vapi_msg_bfd_auth_keys_details *msg)
{
  vapi_msg_bfd_auth_keys_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_auth_keys_details>(vapi_msg_bfd_auth_keys_details *msg)
{
  vapi_msg_bfd_auth_keys_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_auth_keys_details>()
{
  return ::vapi_msg_id_bfd_auth_keys_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_auth_keys_details>>()
{
  return ::vapi_msg_id_bfd_auth_keys_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_auth_keys_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_auth_keys_details>(vapi_msg_id_bfd_auth_keys_details);
}

template class Msg<vapi_msg_bfd_auth_keys_details>;

using Bfd_auth_keys_details = Msg<vapi_msg_bfd_auth_keys_details>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_auth_activate>(vapi_msg_bfd_udp_auth_activate *msg)
{
  vapi_msg_bfd_udp_auth_activate_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_auth_activate>(vapi_msg_bfd_udp_auth_activate *msg)
{
  vapi_msg_bfd_udp_auth_activate_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_auth_activate>()
{
  return ::vapi_msg_id_bfd_udp_auth_activate; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_auth_activate>>()
{
  return ::vapi_msg_id_bfd_udp_auth_activate; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_auth_activate()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_auth_activate>(vapi_msg_id_bfd_udp_auth_activate);
}

template <> inline vapi_msg_bfd_udp_auth_activate* vapi_alloc<vapi_msg_bfd_udp_auth_activate>(Connection &con)
{
  vapi_msg_bfd_udp_auth_activate* result = vapi_alloc_bfd_udp_auth_activate(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_auth_activate>;

template class Request<vapi_msg_bfd_udp_auth_activate, vapi_msg_bfd_udp_auth_activate_reply>;

using Bfd_udp_auth_activate = Request<vapi_msg_bfd_udp_auth_activate, vapi_msg_bfd_udp_auth_activate_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_auth_activate_reply>(vapi_msg_bfd_udp_auth_activate_reply *msg)
{
  vapi_msg_bfd_udp_auth_activate_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_auth_activate_reply>(vapi_msg_bfd_udp_auth_activate_reply *msg)
{
  vapi_msg_bfd_udp_auth_activate_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_auth_activate_reply>()
{
  return ::vapi_msg_id_bfd_udp_auth_activate_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_auth_activate_reply>>()
{
  return ::vapi_msg_id_bfd_udp_auth_activate_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_auth_activate_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_auth_activate_reply>(vapi_msg_id_bfd_udp_auth_activate_reply);
}

template class Msg<vapi_msg_bfd_udp_auth_activate_reply>;

using Bfd_udp_auth_activate_reply = Msg<vapi_msg_bfd_udp_auth_activate_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_auth_deactivate>(vapi_msg_bfd_udp_auth_deactivate *msg)
{
  vapi_msg_bfd_udp_auth_deactivate_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_auth_deactivate>(vapi_msg_bfd_udp_auth_deactivate *msg)
{
  vapi_msg_bfd_udp_auth_deactivate_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_auth_deactivate>()
{
  return ::vapi_msg_id_bfd_udp_auth_deactivate; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_auth_deactivate>>()
{
  return ::vapi_msg_id_bfd_udp_auth_deactivate; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_auth_deactivate()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_auth_deactivate>(vapi_msg_id_bfd_udp_auth_deactivate);
}

template <> inline vapi_msg_bfd_udp_auth_deactivate* vapi_alloc<vapi_msg_bfd_udp_auth_deactivate>(Connection &con)
{
  vapi_msg_bfd_udp_auth_deactivate* result = vapi_alloc_bfd_udp_auth_deactivate(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_auth_deactivate>;

template class Request<vapi_msg_bfd_udp_auth_deactivate, vapi_msg_bfd_udp_auth_deactivate_reply>;

using Bfd_udp_auth_deactivate = Request<vapi_msg_bfd_udp_auth_deactivate, vapi_msg_bfd_udp_auth_deactivate_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_auth_deactivate_reply>(vapi_msg_bfd_udp_auth_deactivate_reply *msg)
{
  vapi_msg_bfd_udp_auth_deactivate_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_auth_deactivate_reply>(vapi_msg_bfd_udp_auth_deactivate_reply *msg)
{
  vapi_msg_bfd_udp_auth_deactivate_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_auth_deactivate_reply>()
{
  return ::vapi_msg_id_bfd_udp_auth_deactivate_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_auth_deactivate_reply>>()
{
  return ::vapi_msg_id_bfd_udp_auth_deactivate_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_auth_deactivate_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_auth_deactivate_reply>(vapi_msg_id_bfd_udp_auth_deactivate_reply);
}

template class Msg<vapi_msg_bfd_udp_auth_deactivate_reply>;

using Bfd_udp_auth_deactivate_reply = Msg<vapi_msg_bfd_udp_auth_deactivate_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_enable_multihop>(vapi_msg_bfd_udp_enable_multihop *msg)
{
  vapi_msg_bfd_udp_enable_multihop_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_enable_multihop>(vapi_msg_bfd_udp_enable_multihop *msg)
{
  vapi_msg_bfd_udp_enable_multihop_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_enable_multihop>()
{
  return ::vapi_msg_id_bfd_udp_enable_multihop; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_enable_multihop>>()
{
  return ::vapi_msg_id_bfd_udp_enable_multihop; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_enable_multihop()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_enable_multihop>(vapi_msg_id_bfd_udp_enable_multihop);
}

template <> inline vapi_msg_bfd_udp_enable_multihop* vapi_alloc<vapi_msg_bfd_udp_enable_multihop>(Connection &con)
{
  vapi_msg_bfd_udp_enable_multihop* result = vapi_alloc_bfd_udp_enable_multihop(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_enable_multihop>;

template class Request<vapi_msg_bfd_udp_enable_multihop, vapi_msg_bfd_udp_enable_multihop_reply>;

using Bfd_udp_enable_multihop = Request<vapi_msg_bfd_udp_enable_multihop, vapi_msg_bfd_udp_enable_multihop_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_enable_multihop_reply>(vapi_msg_bfd_udp_enable_multihop_reply *msg)
{
  vapi_msg_bfd_udp_enable_multihop_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_enable_multihop_reply>(vapi_msg_bfd_udp_enable_multihop_reply *msg)
{
  vapi_msg_bfd_udp_enable_multihop_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_enable_multihop_reply>()
{
  return ::vapi_msg_id_bfd_udp_enable_multihop_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_enable_multihop_reply>>()
{
  return ::vapi_msg_id_bfd_udp_enable_multihop_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_enable_multihop_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_enable_multihop_reply>(vapi_msg_id_bfd_udp_enable_multihop_reply);
}

template class Msg<vapi_msg_bfd_udp_enable_multihop_reply>;

using Bfd_udp_enable_multihop_reply = Msg<vapi_msg_bfd_udp_enable_multihop_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_set_tos>(vapi_msg_bfd_udp_set_tos *msg)
{
  vapi_msg_bfd_udp_set_tos_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_set_tos>(vapi_msg_bfd_udp_set_tos *msg)
{
  vapi_msg_bfd_udp_set_tos_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_set_tos>()
{
  return ::vapi_msg_id_bfd_udp_set_tos; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_set_tos>>()
{
  return ::vapi_msg_id_bfd_udp_set_tos; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_set_tos()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_set_tos>(vapi_msg_id_bfd_udp_set_tos);
}

template <> inline vapi_msg_bfd_udp_set_tos* vapi_alloc<vapi_msg_bfd_udp_set_tos>(Connection &con)
{
  vapi_msg_bfd_udp_set_tos* result = vapi_alloc_bfd_udp_set_tos(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_set_tos>;

template class Request<vapi_msg_bfd_udp_set_tos, vapi_msg_bfd_udp_set_tos_reply>;

using Bfd_udp_set_tos = Request<vapi_msg_bfd_udp_set_tos, vapi_msg_bfd_udp_set_tos_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_set_tos_reply>(vapi_msg_bfd_udp_set_tos_reply *msg)
{
  vapi_msg_bfd_udp_set_tos_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_set_tos_reply>(vapi_msg_bfd_udp_set_tos_reply *msg)
{
  vapi_msg_bfd_udp_set_tos_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_set_tos_reply>()
{
  return ::vapi_msg_id_bfd_udp_set_tos_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_set_tos_reply>>()
{
  return ::vapi_msg_id_bfd_udp_set_tos_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_set_tos_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_set_tos_reply>(vapi_msg_id_bfd_udp_set_tos_reply);
}

template class Msg<vapi_msg_bfd_udp_set_tos_reply>;

using Bfd_udp_set_tos_reply = Msg<vapi_msg_bfd_udp_set_tos_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_get_tos>(vapi_msg_bfd_udp_get_tos *msg)
{
  vapi_msg_bfd_udp_get_tos_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_get_tos>(vapi_msg_bfd_udp_get_tos *msg)
{
  vapi_msg_bfd_udp_get_tos_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_get_tos>()
{
  return ::vapi_msg_id_bfd_udp_get_tos; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_get_tos>>()
{
  return ::vapi_msg_id_bfd_udp_get_tos; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_get_tos()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_get_tos>(vapi_msg_id_bfd_udp_get_tos);
}

template <> inline vapi_msg_bfd_udp_get_tos* vapi_alloc<vapi_msg_bfd_udp_get_tos>(Connection &con)
{
  vapi_msg_bfd_udp_get_tos* result = vapi_alloc_bfd_udp_get_tos(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_bfd_udp_get_tos>;

template class Request<vapi_msg_bfd_udp_get_tos, vapi_msg_bfd_udp_get_tos_reply>;

using Bfd_udp_get_tos = Request<vapi_msg_bfd_udp_get_tos, vapi_msg_bfd_udp_get_tos_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_bfd_udp_get_tos_reply>(vapi_msg_bfd_udp_get_tos_reply *msg)
{
  vapi_msg_bfd_udp_get_tos_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_bfd_udp_get_tos_reply>(vapi_msg_bfd_udp_get_tos_reply *msg)
{
  vapi_msg_bfd_udp_get_tos_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_bfd_udp_get_tos_reply>()
{
  return ::vapi_msg_id_bfd_udp_get_tos_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_bfd_udp_get_tos_reply>>()
{
  return ::vapi_msg_id_bfd_udp_get_tos_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_bfd_udp_get_tos_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_bfd_udp_get_tos_reply>(vapi_msg_id_bfd_udp_get_tos_reply);
}

template class Msg<vapi_msg_bfd_udp_get_tos_reply>;

using Bfd_udp_get_tos_reply = Msg<vapi_msg_bfd_udp_get_tos_reply>;
}
#endif
