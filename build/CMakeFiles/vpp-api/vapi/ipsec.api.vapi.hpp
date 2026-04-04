#ifndef __included_hpp_ipsec_api_json
#define __included_hpp_ipsec_api_json

#include <vapi/vapi.hpp>
#include <vapi/ipsec.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_add_del>(vapi_msg_ipsec_spd_add_del *msg)
{
  vapi_msg_ipsec_spd_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_add_del>(vapi_msg_ipsec_spd_add_del *msg)
{
  vapi_msg_ipsec_spd_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_add_del>()
{
  return ::vapi_msg_id_ipsec_spd_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_add_del>>()
{
  return ::vapi_msg_id_ipsec_spd_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_add_del>(vapi_msg_id_ipsec_spd_add_del);
}

template <> inline vapi_msg_ipsec_spd_add_del* vapi_alloc<vapi_msg_ipsec_spd_add_del>(Connection &con)
{
  vapi_msg_ipsec_spd_add_del* result = vapi_alloc_ipsec_spd_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_spd_add_del>;

template class Request<vapi_msg_ipsec_spd_add_del, vapi_msg_ipsec_spd_add_del_reply>;

using Ipsec_spd_add_del = Request<vapi_msg_ipsec_spd_add_del, vapi_msg_ipsec_spd_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_add_del_reply>(vapi_msg_ipsec_spd_add_del_reply *msg)
{
  vapi_msg_ipsec_spd_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_add_del_reply>(vapi_msg_ipsec_spd_add_del_reply *msg)
{
  vapi_msg_ipsec_spd_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_add_del_reply>()
{
  return ::vapi_msg_id_ipsec_spd_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_add_del_reply>>()
{
  return ::vapi_msg_id_ipsec_spd_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_add_del_reply>(vapi_msg_id_ipsec_spd_add_del_reply);
}

template class Msg<vapi_msg_ipsec_spd_add_del_reply>;

using Ipsec_spd_add_del_reply = Msg<vapi_msg_ipsec_spd_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_interface_add_del_spd>(vapi_msg_ipsec_interface_add_del_spd *msg)
{
  vapi_msg_ipsec_interface_add_del_spd_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_interface_add_del_spd>(vapi_msg_ipsec_interface_add_del_spd *msg)
{
  vapi_msg_ipsec_interface_add_del_spd_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_interface_add_del_spd>()
{
  return ::vapi_msg_id_ipsec_interface_add_del_spd; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_interface_add_del_spd>>()
{
  return ::vapi_msg_id_ipsec_interface_add_del_spd; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_interface_add_del_spd()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_interface_add_del_spd>(vapi_msg_id_ipsec_interface_add_del_spd);
}

template <> inline vapi_msg_ipsec_interface_add_del_spd* vapi_alloc<vapi_msg_ipsec_interface_add_del_spd>(Connection &con)
{
  vapi_msg_ipsec_interface_add_del_spd* result = vapi_alloc_ipsec_interface_add_del_spd(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_interface_add_del_spd>;

template class Request<vapi_msg_ipsec_interface_add_del_spd, vapi_msg_ipsec_interface_add_del_spd_reply>;

using Ipsec_interface_add_del_spd = Request<vapi_msg_ipsec_interface_add_del_spd, vapi_msg_ipsec_interface_add_del_spd_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_interface_add_del_spd_reply>(vapi_msg_ipsec_interface_add_del_spd_reply *msg)
{
  vapi_msg_ipsec_interface_add_del_spd_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_interface_add_del_spd_reply>(vapi_msg_ipsec_interface_add_del_spd_reply *msg)
{
  vapi_msg_ipsec_interface_add_del_spd_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_interface_add_del_spd_reply>()
{
  return ::vapi_msg_id_ipsec_interface_add_del_spd_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_interface_add_del_spd_reply>>()
{
  return ::vapi_msg_id_ipsec_interface_add_del_spd_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_interface_add_del_spd_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_interface_add_del_spd_reply>(vapi_msg_id_ipsec_interface_add_del_spd_reply);
}

template class Msg<vapi_msg_ipsec_interface_add_del_spd_reply>;

using Ipsec_interface_add_del_spd_reply = Msg<vapi_msg_ipsec_interface_add_del_spd_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_entry_add_del>(vapi_msg_ipsec_spd_entry_add_del *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_entry_add_del>(vapi_msg_ipsec_spd_entry_add_del *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_entry_add_del>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_entry_add_del>>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_entry_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_entry_add_del>(vapi_msg_id_ipsec_spd_entry_add_del);
}

template <> inline vapi_msg_ipsec_spd_entry_add_del* vapi_alloc<vapi_msg_ipsec_spd_entry_add_del>(Connection &con)
{
  vapi_msg_ipsec_spd_entry_add_del* result = vapi_alloc_ipsec_spd_entry_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_spd_entry_add_del>;

template class Request<vapi_msg_ipsec_spd_entry_add_del, vapi_msg_ipsec_spd_entry_add_del_reply>;

using Ipsec_spd_entry_add_del = Request<vapi_msg_ipsec_spd_entry_add_del, vapi_msg_ipsec_spd_entry_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_entry_add_del_v2>(vapi_msg_ipsec_spd_entry_add_del_v2 *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_entry_add_del_v2>(vapi_msg_ipsec_spd_entry_add_del_v2 *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_entry_add_del_v2>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_entry_add_del_v2>>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_entry_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_entry_add_del_v2>(vapi_msg_id_ipsec_spd_entry_add_del_v2);
}

template <> inline vapi_msg_ipsec_spd_entry_add_del_v2* vapi_alloc<vapi_msg_ipsec_spd_entry_add_del_v2>(Connection &con)
{
  vapi_msg_ipsec_spd_entry_add_del_v2* result = vapi_alloc_ipsec_spd_entry_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_spd_entry_add_del_v2>;

template class Request<vapi_msg_ipsec_spd_entry_add_del_v2, vapi_msg_ipsec_spd_entry_add_del_v2_reply>;

using Ipsec_spd_entry_add_del_v2 = Request<vapi_msg_ipsec_spd_entry_add_del_v2, vapi_msg_ipsec_spd_entry_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_entry_add_del_reply>(vapi_msg_ipsec_spd_entry_add_del_reply *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_entry_add_del_reply>(vapi_msg_ipsec_spd_entry_add_del_reply *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_entry_add_del_reply>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_entry_add_del_reply>>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_entry_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_entry_add_del_reply>(vapi_msg_id_ipsec_spd_entry_add_del_reply);
}

template class Msg<vapi_msg_ipsec_spd_entry_add_del_reply>;

using Ipsec_spd_entry_add_del_reply = Msg<vapi_msg_ipsec_spd_entry_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_entry_add_del_v2_reply>(vapi_msg_ipsec_spd_entry_add_del_v2_reply *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_entry_add_del_v2_reply>(vapi_msg_ipsec_spd_entry_add_del_v2_reply *msg)
{
  vapi_msg_ipsec_spd_entry_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_entry_add_del_v2_reply>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_entry_add_del_v2_reply>>()
{
  return ::vapi_msg_id_ipsec_spd_entry_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_entry_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_entry_add_del_v2_reply>(vapi_msg_id_ipsec_spd_entry_add_del_v2_reply);
}

template class Msg<vapi_msg_ipsec_spd_entry_add_del_v2_reply>;

using Ipsec_spd_entry_add_del_v2_reply = Msg<vapi_msg_ipsec_spd_entry_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spds_dump>(vapi_msg_ipsec_spds_dump *msg)
{
  vapi_msg_ipsec_spds_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spds_dump>(vapi_msg_ipsec_spds_dump *msg)
{
  vapi_msg_ipsec_spds_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spds_dump>()
{
  return ::vapi_msg_id_ipsec_spds_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spds_dump>>()
{
  return ::vapi_msg_id_ipsec_spds_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spds_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spds_dump>(vapi_msg_id_ipsec_spds_dump);
}

template <> inline vapi_msg_ipsec_spds_dump* vapi_alloc<vapi_msg_ipsec_spds_dump>(Connection &con)
{
  vapi_msg_ipsec_spds_dump* result = vapi_alloc_ipsec_spds_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_spds_dump>;

template class Dump<vapi_msg_ipsec_spds_dump, vapi_msg_ipsec_spds_details>;

using Ipsec_spds_dump = Dump<vapi_msg_ipsec_spds_dump, vapi_msg_ipsec_spds_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spds_details>(vapi_msg_ipsec_spds_details *msg)
{
  vapi_msg_ipsec_spds_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spds_details>(vapi_msg_ipsec_spds_details *msg)
{
  vapi_msg_ipsec_spds_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spds_details>()
{
  return ::vapi_msg_id_ipsec_spds_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spds_details>>()
{
  return ::vapi_msg_id_ipsec_spds_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spds_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spds_details>(vapi_msg_id_ipsec_spds_details);
}

template class Msg<vapi_msg_ipsec_spds_details>;

using Ipsec_spds_details = Msg<vapi_msg_ipsec_spds_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_dump>(vapi_msg_ipsec_spd_dump *msg)
{
  vapi_msg_ipsec_spd_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_dump>(vapi_msg_ipsec_spd_dump *msg)
{
  vapi_msg_ipsec_spd_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_dump>()
{
  return ::vapi_msg_id_ipsec_spd_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_dump>>()
{
  return ::vapi_msg_id_ipsec_spd_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_dump>(vapi_msg_id_ipsec_spd_dump);
}

template <> inline vapi_msg_ipsec_spd_dump* vapi_alloc<vapi_msg_ipsec_spd_dump>(Connection &con)
{
  vapi_msg_ipsec_spd_dump* result = vapi_alloc_ipsec_spd_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_spd_dump>;

template class Dump<vapi_msg_ipsec_spd_dump, vapi_msg_ipsec_spd_details>;

using Ipsec_spd_dump = Dump<vapi_msg_ipsec_spd_dump, vapi_msg_ipsec_spd_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_details>(vapi_msg_ipsec_spd_details *msg)
{
  vapi_msg_ipsec_spd_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_details>(vapi_msg_ipsec_spd_details *msg)
{
  vapi_msg_ipsec_spd_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_details>()
{
  return ::vapi_msg_id_ipsec_spd_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_details>>()
{
  return ::vapi_msg_id_ipsec_spd_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_details>(vapi_msg_id_ipsec_spd_details);
}

template class Msg<vapi_msg_ipsec_spd_details>;

using Ipsec_spd_details = Msg<vapi_msg_ipsec_spd_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_del>(vapi_msg_ipsec_sad_entry_add_del *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_del>(vapi_msg_ipsec_sad_entry_add_del *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_del>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_del>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_del>(vapi_msg_id_ipsec_sad_entry_add_del);
}

template <> inline vapi_msg_ipsec_sad_entry_add_del* vapi_alloc<vapi_msg_ipsec_sad_entry_add_del>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_add_del* result = vapi_alloc_ipsec_sad_entry_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_add_del>;

template class Request<vapi_msg_ipsec_sad_entry_add_del, vapi_msg_ipsec_sad_entry_add_del_reply>;

using Ipsec_sad_entry_add_del = Request<vapi_msg_ipsec_sad_entry_add_del, vapi_msg_ipsec_sad_entry_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_del_v2>(vapi_msg_ipsec_sad_entry_add_del_v2 *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_del_v2>(vapi_msg_ipsec_sad_entry_add_del_v2 *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_del_v2>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_del_v2>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_del_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_del_v2>(vapi_msg_id_ipsec_sad_entry_add_del_v2);
}

template <> inline vapi_msg_ipsec_sad_entry_add_del_v2* vapi_alloc<vapi_msg_ipsec_sad_entry_add_del_v2>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_add_del_v2* result = vapi_alloc_ipsec_sad_entry_add_del_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_add_del_v2>;

template class Request<vapi_msg_ipsec_sad_entry_add_del_v2, vapi_msg_ipsec_sad_entry_add_del_v2_reply>;

using Ipsec_sad_entry_add_del_v2 = Request<vapi_msg_ipsec_sad_entry_add_del_v2, vapi_msg_ipsec_sad_entry_add_del_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_del_v3>(vapi_msg_ipsec_sad_entry_add_del_v3 *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_del_v3>(vapi_msg_ipsec_sad_entry_add_del_v3 *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_del_v3>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_del_v3>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_del_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_del_v3>(vapi_msg_id_ipsec_sad_entry_add_del_v3);
}

template <> inline vapi_msg_ipsec_sad_entry_add_del_v3* vapi_alloc<vapi_msg_ipsec_sad_entry_add_del_v3>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_add_del_v3* result = vapi_alloc_ipsec_sad_entry_add_del_v3(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_add_del_v3>;

template class Request<vapi_msg_ipsec_sad_entry_add_del_v3, vapi_msg_ipsec_sad_entry_add_del_v3_reply>;

using Ipsec_sad_entry_add_del_v3 = Request<vapi_msg_ipsec_sad_entry_add_del_v3, vapi_msg_ipsec_sad_entry_add_del_v3_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add>(vapi_msg_ipsec_sad_entry_add *msg)
{
  vapi_msg_ipsec_sad_entry_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add>(vapi_msg_ipsec_sad_entry_add *msg)
{
  vapi_msg_ipsec_sad_entry_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add>(vapi_msg_id_ipsec_sad_entry_add);
}

template <> inline vapi_msg_ipsec_sad_entry_add* vapi_alloc<vapi_msg_ipsec_sad_entry_add>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_add* result = vapi_alloc_ipsec_sad_entry_add(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_add>;

template class Request<vapi_msg_ipsec_sad_entry_add, vapi_msg_ipsec_sad_entry_add_reply>;

using Ipsec_sad_entry_add = Request<vapi_msg_ipsec_sad_entry_add, vapi_msg_ipsec_sad_entry_add_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_v2>(vapi_msg_ipsec_sad_entry_add_v2 *msg)
{
  vapi_msg_ipsec_sad_entry_add_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_v2>(vapi_msg_ipsec_sad_entry_add_v2 *msg)
{
  vapi_msg_ipsec_sad_entry_add_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_v2>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_v2>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_v2>(vapi_msg_id_ipsec_sad_entry_add_v2);
}

template <> inline vapi_msg_ipsec_sad_entry_add_v2* vapi_alloc<vapi_msg_ipsec_sad_entry_add_v2>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_add_v2* result = vapi_alloc_ipsec_sad_entry_add_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_add_v2>;

template class Request<vapi_msg_ipsec_sad_entry_add_v2, vapi_msg_ipsec_sad_entry_add_v2_reply>;

using Ipsec_sad_entry_add_v2 = Request<vapi_msg_ipsec_sad_entry_add_v2, vapi_msg_ipsec_sad_entry_add_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_del>(vapi_msg_ipsec_sad_entry_del *msg)
{
  vapi_msg_ipsec_sad_entry_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_del>(vapi_msg_ipsec_sad_entry_del *msg)
{
  vapi_msg_ipsec_sad_entry_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_del>()
{
  return ::vapi_msg_id_ipsec_sad_entry_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_del>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_del>(vapi_msg_id_ipsec_sad_entry_del);
}

template <> inline vapi_msg_ipsec_sad_entry_del* vapi_alloc<vapi_msg_ipsec_sad_entry_del>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_del* result = vapi_alloc_ipsec_sad_entry_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_del>;

template class Request<vapi_msg_ipsec_sad_entry_del, vapi_msg_ipsec_sad_entry_del_reply>;

using Ipsec_sad_entry_del = Request<vapi_msg_ipsec_sad_entry_del, vapi_msg_ipsec_sad_entry_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_del_reply>(vapi_msg_ipsec_sad_entry_del_reply *msg)
{
  vapi_msg_ipsec_sad_entry_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_del_reply>(vapi_msg_ipsec_sad_entry_del_reply *msg)
{
  vapi_msg_ipsec_sad_entry_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_del_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_del_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_del_reply>(vapi_msg_id_ipsec_sad_entry_del_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_del_reply>;

using Ipsec_sad_entry_del_reply = Msg<vapi_msg_ipsec_sad_entry_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_bind>(vapi_msg_ipsec_sad_bind *msg)
{
  vapi_msg_ipsec_sad_bind_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_bind>(vapi_msg_ipsec_sad_bind *msg)
{
  vapi_msg_ipsec_sad_bind_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_bind>()
{
  return ::vapi_msg_id_ipsec_sad_bind; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_bind>>()
{
  return ::vapi_msg_id_ipsec_sad_bind; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_bind()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_bind>(vapi_msg_id_ipsec_sad_bind);
}

template <> inline vapi_msg_ipsec_sad_bind* vapi_alloc<vapi_msg_ipsec_sad_bind>(Connection &con)
{
  vapi_msg_ipsec_sad_bind* result = vapi_alloc_ipsec_sad_bind(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_bind>;

template class Request<vapi_msg_ipsec_sad_bind, vapi_msg_ipsec_sad_bind_reply>;

using Ipsec_sad_bind = Request<vapi_msg_ipsec_sad_bind, vapi_msg_ipsec_sad_bind_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_bind_reply>(vapi_msg_ipsec_sad_bind_reply *msg)
{
  vapi_msg_ipsec_sad_bind_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_bind_reply>(vapi_msg_ipsec_sad_bind_reply *msg)
{
  vapi_msg_ipsec_sad_bind_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_bind_reply>()
{
  return ::vapi_msg_id_ipsec_sad_bind_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_bind_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_bind_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_bind_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_bind_reply>(vapi_msg_id_ipsec_sad_bind_reply);
}

template class Msg<vapi_msg_ipsec_sad_bind_reply>;

using Ipsec_sad_bind_reply = Msg<vapi_msg_ipsec_sad_bind_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_unbind>(vapi_msg_ipsec_sad_unbind *msg)
{
  vapi_msg_ipsec_sad_unbind_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_unbind>(vapi_msg_ipsec_sad_unbind *msg)
{
  vapi_msg_ipsec_sad_unbind_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_unbind>()
{
  return ::vapi_msg_id_ipsec_sad_unbind; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_unbind>>()
{
  return ::vapi_msg_id_ipsec_sad_unbind; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_unbind()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_unbind>(vapi_msg_id_ipsec_sad_unbind);
}

template <> inline vapi_msg_ipsec_sad_unbind* vapi_alloc<vapi_msg_ipsec_sad_unbind>(Connection &con)
{
  vapi_msg_ipsec_sad_unbind* result = vapi_alloc_ipsec_sad_unbind(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_unbind>;

template class Request<vapi_msg_ipsec_sad_unbind, vapi_msg_ipsec_sad_unbind_reply>;

using Ipsec_sad_unbind = Request<vapi_msg_ipsec_sad_unbind, vapi_msg_ipsec_sad_unbind_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_unbind_reply>(vapi_msg_ipsec_sad_unbind_reply *msg)
{
  vapi_msg_ipsec_sad_unbind_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_unbind_reply>(vapi_msg_ipsec_sad_unbind_reply *msg)
{
  vapi_msg_ipsec_sad_unbind_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_unbind_reply>()
{
  return ::vapi_msg_id_ipsec_sad_unbind_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_unbind_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_unbind_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_unbind_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_unbind_reply>(vapi_msg_id_ipsec_sad_unbind_reply);
}

template class Msg<vapi_msg_ipsec_sad_unbind_reply>;

using Ipsec_sad_unbind_reply = Msg<vapi_msg_ipsec_sad_unbind_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_update>(vapi_msg_ipsec_sad_entry_update *msg)
{
  vapi_msg_ipsec_sad_entry_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_update>(vapi_msg_ipsec_sad_entry_update *msg)
{
  vapi_msg_ipsec_sad_entry_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_update>()
{
  return ::vapi_msg_id_ipsec_sad_entry_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_update>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_update>(vapi_msg_id_ipsec_sad_entry_update);
}

template <> inline vapi_msg_ipsec_sad_entry_update* vapi_alloc<vapi_msg_ipsec_sad_entry_update>(Connection &con)
{
  vapi_msg_ipsec_sad_entry_update* result = vapi_alloc_ipsec_sad_entry_update(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sad_entry_update>;

template class Request<vapi_msg_ipsec_sad_entry_update, vapi_msg_ipsec_sad_entry_update_reply>;

using Ipsec_sad_entry_update = Request<vapi_msg_ipsec_sad_entry_update, vapi_msg_ipsec_sad_entry_update_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_update_reply>(vapi_msg_ipsec_sad_entry_update_reply *msg)
{
  vapi_msg_ipsec_sad_entry_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_update_reply>(vapi_msg_ipsec_sad_entry_update_reply *msg)
{
  vapi_msg_ipsec_sad_entry_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_update_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_update_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_update_reply>(vapi_msg_id_ipsec_sad_entry_update_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_update_reply>;

using Ipsec_sad_entry_update_reply = Msg<vapi_msg_ipsec_sad_entry_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_del_reply>(vapi_msg_ipsec_sad_entry_add_del_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_del_reply>(vapi_msg_ipsec_sad_entry_add_del_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_del_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_del_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_del_reply>(vapi_msg_id_ipsec_sad_entry_add_del_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_add_del_reply>;

using Ipsec_sad_entry_add_del_reply = Msg<vapi_msg_ipsec_sad_entry_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_del_v2_reply>(vapi_msg_ipsec_sad_entry_add_del_v2_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_del_v2_reply>(vapi_msg_ipsec_sad_entry_add_del_v2_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_del_v2_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_del_v2_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_del_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_del_v2_reply>(vapi_msg_id_ipsec_sad_entry_add_del_v2_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_add_del_v2_reply>;

using Ipsec_sad_entry_add_del_v2_reply = Msg<vapi_msg_ipsec_sad_entry_add_del_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_del_v3_reply>(vapi_msg_ipsec_sad_entry_add_del_v3_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_del_v3_reply>(vapi_msg_ipsec_sad_entry_add_del_v3_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_del_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_del_v3_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_del_v3_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_del_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_del_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_del_v3_reply>(vapi_msg_id_ipsec_sad_entry_add_del_v3_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_add_del_v3_reply>;

using Ipsec_sad_entry_add_del_v3_reply = Msg<vapi_msg_ipsec_sad_entry_add_del_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_reply>(vapi_msg_ipsec_sad_entry_add_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_reply>(vapi_msg_ipsec_sad_entry_add_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_reply>(vapi_msg_id_ipsec_sad_entry_add_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_add_reply>;

using Ipsec_sad_entry_add_reply = Msg<vapi_msg_ipsec_sad_entry_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sad_entry_add_v2_reply>(vapi_msg_ipsec_sad_entry_add_v2_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sad_entry_add_v2_reply>(vapi_msg_ipsec_sad_entry_add_v2_reply *msg)
{
  vapi_msg_ipsec_sad_entry_add_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sad_entry_add_v2_reply>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sad_entry_add_v2_reply>>()
{
  return ::vapi_msg_id_ipsec_sad_entry_add_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sad_entry_add_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sad_entry_add_v2_reply>(vapi_msg_id_ipsec_sad_entry_add_v2_reply);
}

template class Msg<vapi_msg_ipsec_sad_entry_add_v2_reply>;

using Ipsec_sad_entry_add_v2_reply = Msg<vapi_msg_ipsec_sad_entry_add_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_tunnel_protect_update>(vapi_msg_ipsec_tunnel_protect_update *msg)
{
  vapi_msg_ipsec_tunnel_protect_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_tunnel_protect_update>(vapi_msg_ipsec_tunnel_protect_update *msg)
{
  vapi_msg_ipsec_tunnel_protect_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_tunnel_protect_update>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_tunnel_protect_update>>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_tunnel_protect_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_tunnel_protect_update>(vapi_msg_id_ipsec_tunnel_protect_update);
}

template <> inline vapi_msg_ipsec_tunnel_protect_update* vapi_alloc<vapi_msg_ipsec_tunnel_protect_update, size_t>(Connection &con, size_t tunnel_sa_in_array_size)
{
  vapi_msg_ipsec_tunnel_protect_update* result = vapi_alloc_ipsec_tunnel_protect_update(con.vapi_ctx, tunnel_sa_in_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_tunnel_protect_update>;

template class Request<vapi_msg_ipsec_tunnel_protect_update, vapi_msg_ipsec_tunnel_protect_update_reply, size_t>;

using Ipsec_tunnel_protect_update = Request<vapi_msg_ipsec_tunnel_protect_update, vapi_msg_ipsec_tunnel_protect_update_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_tunnel_protect_update_reply>(vapi_msg_ipsec_tunnel_protect_update_reply *msg)
{
  vapi_msg_ipsec_tunnel_protect_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_tunnel_protect_update_reply>(vapi_msg_ipsec_tunnel_protect_update_reply *msg)
{
  vapi_msg_ipsec_tunnel_protect_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_tunnel_protect_update_reply>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_tunnel_protect_update_reply>>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_tunnel_protect_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_tunnel_protect_update_reply>(vapi_msg_id_ipsec_tunnel_protect_update_reply);
}

template class Msg<vapi_msg_ipsec_tunnel_protect_update_reply>;

using Ipsec_tunnel_protect_update_reply = Msg<vapi_msg_ipsec_tunnel_protect_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_tunnel_protect_del>(vapi_msg_ipsec_tunnel_protect_del *msg)
{
  vapi_msg_ipsec_tunnel_protect_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_tunnel_protect_del>(vapi_msg_ipsec_tunnel_protect_del *msg)
{
  vapi_msg_ipsec_tunnel_protect_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_tunnel_protect_del>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_tunnel_protect_del>>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_tunnel_protect_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_tunnel_protect_del>(vapi_msg_id_ipsec_tunnel_protect_del);
}

template <> inline vapi_msg_ipsec_tunnel_protect_del* vapi_alloc<vapi_msg_ipsec_tunnel_protect_del>(Connection &con)
{
  vapi_msg_ipsec_tunnel_protect_del* result = vapi_alloc_ipsec_tunnel_protect_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_tunnel_protect_del>;

template class Request<vapi_msg_ipsec_tunnel_protect_del, vapi_msg_ipsec_tunnel_protect_del_reply>;

using Ipsec_tunnel_protect_del = Request<vapi_msg_ipsec_tunnel_protect_del, vapi_msg_ipsec_tunnel_protect_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_tunnel_protect_del_reply>(vapi_msg_ipsec_tunnel_protect_del_reply *msg)
{
  vapi_msg_ipsec_tunnel_protect_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_tunnel_protect_del_reply>(vapi_msg_ipsec_tunnel_protect_del_reply *msg)
{
  vapi_msg_ipsec_tunnel_protect_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_tunnel_protect_del_reply>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_tunnel_protect_del_reply>>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_tunnel_protect_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_tunnel_protect_del_reply>(vapi_msg_id_ipsec_tunnel_protect_del_reply);
}

template class Msg<vapi_msg_ipsec_tunnel_protect_del_reply>;

using Ipsec_tunnel_protect_del_reply = Msg<vapi_msg_ipsec_tunnel_protect_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_tunnel_protect_dump>(vapi_msg_ipsec_tunnel_protect_dump *msg)
{
  vapi_msg_ipsec_tunnel_protect_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_tunnel_protect_dump>(vapi_msg_ipsec_tunnel_protect_dump *msg)
{
  vapi_msg_ipsec_tunnel_protect_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_tunnel_protect_dump>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_tunnel_protect_dump>>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_tunnel_protect_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_tunnel_protect_dump>(vapi_msg_id_ipsec_tunnel_protect_dump);
}

template <> inline vapi_msg_ipsec_tunnel_protect_dump* vapi_alloc<vapi_msg_ipsec_tunnel_protect_dump>(Connection &con)
{
  vapi_msg_ipsec_tunnel_protect_dump* result = vapi_alloc_ipsec_tunnel_protect_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_tunnel_protect_dump>;

template class Dump<vapi_msg_ipsec_tunnel_protect_dump, vapi_msg_ipsec_tunnel_protect_details>;

using Ipsec_tunnel_protect_dump = Dump<vapi_msg_ipsec_tunnel_protect_dump, vapi_msg_ipsec_tunnel_protect_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_tunnel_protect_details>(vapi_msg_ipsec_tunnel_protect_details *msg)
{
  vapi_msg_ipsec_tunnel_protect_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_tunnel_protect_details>(vapi_msg_ipsec_tunnel_protect_details *msg)
{
  vapi_msg_ipsec_tunnel_protect_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_tunnel_protect_details>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_tunnel_protect_details>>()
{
  return ::vapi_msg_id_ipsec_tunnel_protect_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_tunnel_protect_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_tunnel_protect_details>(vapi_msg_id_ipsec_tunnel_protect_details);
}

template class Msg<vapi_msg_ipsec_tunnel_protect_details>;

using Ipsec_tunnel_protect_details = Msg<vapi_msg_ipsec_tunnel_protect_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_interface_dump>(vapi_msg_ipsec_spd_interface_dump *msg)
{
  vapi_msg_ipsec_spd_interface_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_interface_dump>(vapi_msg_ipsec_spd_interface_dump *msg)
{
  vapi_msg_ipsec_spd_interface_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_interface_dump>()
{
  return ::vapi_msg_id_ipsec_spd_interface_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_interface_dump>>()
{
  return ::vapi_msg_id_ipsec_spd_interface_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_interface_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_interface_dump>(vapi_msg_id_ipsec_spd_interface_dump);
}

template <> inline vapi_msg_ipsec_spd_interface_dump* vapi_alloc<vapi_msg_ipsec_spd_interface_dump>(Connection &con)
{
  vapi_msg_ipsec_spd_interface_dump* result = vapi_alloc_ipsec_spd_interface_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_spd_interface_dump>;

template class Dump<vapi_msg_ipsec_spd_interface_dump, vapi_msg_ipsec_spd_interface_details>;

using Ipsec_spd_interface_dump = Dump<vapi_msg_ipsec_spd_interface_dump, vapi_msg_ipsec_spd_interface_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_spd_interface_details>(vapi_msg_ipsec_spd_interface_details *msg)
{
  vapi_msg_ipsec_spd_interface_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_spd_interface_details>(vapi_msg_ipsec_spd_interface_details *msg)
{
  vapi_msg_ipsec_spd_interface_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_spd_interface_details>()
{
  return ::vapi_msg_id_ipsec_spd_interface_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_spd_interface_details>>()
{
  return ::vapi_msg_id_ipsec_spd_interface_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_spd_interface_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_spd_interface_details>(vapi_msg_id_ipsec_spd_interface_details);
}

template class Msg<vapi_msg_ipsec_spd_interface_details>;

using Ipsec_spd_interface_details = Msg<vapi_msg_ipsec_spd_interface_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_itf_create>(vapi_msg_ipsec_itf_create *msg)
{
  vapi_msg_ipsec_itf_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_itf_create>(vapi_msg_ipsec_itf_create *msg)
{
  vapi_msg_ipsec_itf_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_itf_create>()
{
  return ::vapi_msg_id_ipsec_itf_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_itf_create>>()
{
  return ::vapi_msg_id_ipsec_itf_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_itf_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_itf_create>(vapi_msg_id_ipsec_itf_create);
}

template <> inline vapi_msg_ipsec_itf_create* vapi_alloc<vapi_msg_ipsec_itf_create>(Connection &con)
{
  vapi_msg_ipsec_itf_create* result = vapi_alloc_ipsec_itf_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_itf_create>;

template class Request<vapi_msg_ipsec_itf_create, vapi_msg_ipsec_itf_create_reply>;

using Ipsec_itf_create = Request<vapi_msg_ipsec_itf_create, vapi_msg_ipsec_itf_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_itf_create_reply>(vapi_msg_ipsec_itf_create_reply *msg)
{
  vapi_msg_ipsec_itf_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_itf_create_reply>(vapi_msg_ipsec_itf_create_reply *msg)
{
  vapi_msg_ipsec_itf_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_itf_create_reply>()
{
  return ::vapi_msg_id_ipsec_itf_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_itf_create_reply>>()
{
  return ::vapi_msg_id_ipsec_itf_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_itf_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_itf_create_reply>(vapi_msg_id_ipsec_itf_create_reply);
}

template class Msg<vapi_msg_ipsec_itf_create_reply>;

using Ipsec_itf_create_reply = Msg<vapi_msg_ipsec_itf_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_itf_delete>(vapi_msg_ipsec_itf_delete *msg)
{
  vapi_msg_ipsec_itf_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_itf_delete>(vapi_msg_ipsec_itf_delete *msg)
{
  vapi_msg_ipsec_itf_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_itf_delete>()
{
  return ::vapi_msg_id_ipsec_itf_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_itf_delete>>()
{
  return ::vapi_msg_id_ipsec_itf_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_itf_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_itf_delete>(vapi_msg_id_ipsec_itf_delete);
}

template <> inline vapi_msg_ipsec_itf_delete* vapi_alloc<vapi_msg_ipsec_itf_delete>(Connection &con)
{
  vapi_msg_ipsec_itf_delete* result = vapi_alloc_ipsec_itf_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_itf_delete>;

template class Request<vapi_msg_ipsec_itf_delete, vapi_msg_ipsec_itf_delete_reply>;

using Ipsec_itf_delete = Request<vapi_msg_ipsec_itf_delete, vapi_msg_ipsec_itf_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_itf_delete_reply>(vapi_msg_ipsec_itf_delete_reply *msg)
{
  vapi_msg_ipsec_itf_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_itf_delete_reply>(vapi_msg_ipsec_itf_delete_reply *msg)
{
  vapi_msg_ipsec_itf_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_itf_delete_reply>()
{
  return ::vapi_msg_id_ipsec_itf_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_itf_delete_reply>>()
{
  return ::vapi_msg_id_ipsec_itf_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_itf_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_itf_delete_reply>(vapi_msg_id_ipsec_itf_delete_reply);
}

template class Msg<vapi_msg_ipsec_itf_delete_reply>;

using Ipsec_itf_delete_reply = Msg<vapi_msg_ipsec_itf_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_itf_dump>(vapi_msg_ipsec_itf_dump *msg)
{
  vapi_msg_ipsec_itf_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_itf_dump>(vapi_msg_ipsec_itf_dump *msg)
{
  vapi_msg_ipsec_itf_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_itf_dump>()
{
  return ::vapi_msg_id_ipsec_itf_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_itf_dump>>()
{
  return ::vapi_msg_id_ipsec_itf_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_itf_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_itf_dump>(vapi_msg_id_ipsec_itf_dump);
}

template <> inline vapi_msg_ipsec_itf_dump* vapi_alloc<vapi_msg_ipsec_itf_dump>(Connection &con)
{
  vapi_msg_ipsec_itf_dump* result = vapi_alloc_ipsec_itf_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_itf_dump>;

template class Dump<vapi_msg_ipsec_itf_dump, vapi_msg_ipsec_itf_details>;

using Ipsec_itf_dump = Dump<vapi_msg_ipsec_itf_dump, vapi_msg_ipsec_itf_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_itf_details>(vapi_msg_ipsec_itf_details *msg)
{
  vapi_msg_ipsec_itf_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_itf_details>(vapi_msg_ipsec_itf_details *msg)
{
  vapi_msg_ipsec_itf_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_itf_details>()
{
  return ::vapi_msg_id_ipsec_itf_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_itf_details>>()
{
  return ::vapi_msg_id_ipsec_itf_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_itf_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_itf_details>(vapi_msg_id_ipsec_itf_details);
}

template class Msg<vapi_msg_ipsec_itf_details>;

using Ipsec_itf_details = Msg<vapi_msg_ipsec_itf_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_dump>(vapi_msg_ipsec_sa_dump *msg)
{
  vapi_msg_ipsec_sa_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_dump>(vapi_msg_ipsec_sa_dump *msg)
{
  vapi_msg_ipsec_sa_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_dump>()
{
  return ::vapi_msg_id_ipsec_sa_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_dump>>()
{
  return ::vapi_msg_id_ipsec_sa_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_dump>(vapi_msg_id_ipsec_sa_dump);
}

template <> inline vapi_msg_ipsec_sa_dump* vapi_alloc<vapi_msg_ipsec_sa_dump>(Connection &con)
{
  vapi_msg_ipsec_sa_dump* result = vapi_alloc_ipsec_sa_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sa_dump>;

template class Dump<vapi_msg_ipsec_sa_dump, vapi_msg_ipsec_sa_details>;

using Ipsec_sa_dump = Dump<vapi_msg_ipsec_sa_dump, vapi_msg_ipsec_sa_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v2_dump>(vapi_msg_ipsec_sa_v2_dump *msg)
{
  vapi_msg_ipsec_sa_v2_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v2_dump>(vapi_msg_ipsec_sa_v2_dump *msg)
{
  vapi_msg_ipsec_sa_v2_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v2_dump>()
{
  return ::vapi_msg_id_ipsec_sa_v2_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v2_dump>>()
{
  return ::vapi_msg_id_ipsec_sa_v2_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v2_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v2_dump>(vapi_msg_id_ipsec_sa_v2_dump);
}

template <> inline vapi_msg_ipsec_sa_v2_dump* vapi_alloc<vapi_msg_ipsec_sa_v2_dump>(Connection &con)
{
  vapi_msg_ipsec_sa_v2_dump* result = vapi_alloc_ipsec_sa_v2_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sa_v2_dump>;

template class Dump<vapi_msg_ipsec_sa_v2_dump, vapi_msg_ipsec_sa_v2_details>;

using Ipsec_sa_v2_dump = Dump<vapi_msg_ipsec_sa_v2_dump, vapi_msg_ipsec_sa_v2_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v3_dump>(vapi_msg_ipsec_sa_v3_dump *msg)
{
  vapi_msg_ipsec_sa_v3_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v3_dump>(vapi_msg_ipsec_sa_v3_dump *msg)
{
  vapi_msg_ipsec_sa_v3_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v3_dump>()
{
  return ::vapi_msg_id_ipsec_sa_v3_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v3_dump>>()
{
  return ::vapi_msg_id_ipsec_sa_v3_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v3_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v3_dump>(vapi_msg_id_ipsec_sa_v3_dump);
}

template <> inline vapi_msg_ipsec_sa_v3_dump* vapi_alloc<vapi_msg_ipsec_sa_v3_dump>(Connection &con)
{
  vapi_msg_ipsec_sa_v3_dump* result = vapi_alloc_ipsec_sa_v3_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sa_v3_dump>;

template class Dump<vapi_msg_ipsec_sa_v3_dump, vapi_msg_ipsec_sa_v3_details>;

using Ipsec_sa_v3_dump = Dump<vapi_msg_ipsec_sa_v3_dump, vapi_msg_ipsec_sa_v3_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v4_dump>(vapi_msg_ipsec_sa_v4_dump *msg)
{
  vapi_msg_ipsec_sa_v4_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v4_dump>(vapi_msg_ipsec_sa_v4_dump *msg)
{
  vapi_msg_ipsec_sa_v4_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v4_dump>()
{
  return ::vapi_msg_id_ipsec_sa_v4_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v4_dump>>()
{
  return ::vapi_msg_id_ipsec_sa_v4_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v4_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v4_dump>(vapi_msg_id_ipsec_sa_v4_dump);
}

template <> inline vapi_msg_ipsec_sa_v4_dump* vapi_alloc<vapi_msg_ipsec_sa_v4_dump>(Connection &con)
{
  vapi_msg_ipsec_sa_v4_dump* result = vapi_alloc_ipsec_sa_v4_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sa_v4_dump>;

template class Dump<vapi_msg_ipsec_sa_v4_dump, vapi_msg_ipsec_sa_v4_details>;

using Ipsec_sa_v4_dump = Dump<vapi_msg_ipsec_sa_v4_dump, vapi_msg_ipsec_sa_v4_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v5_dump>(vapi_msg_ipsec_sa_v5_dump *msg)
{
  vapi_msg_ipsec_sa_v5_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v5_dump>(vapi_msg_ipsec_sa_v5_dump *msg)
{
  vapi_msg_ipsec_sa_v5_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v5_dump>()
{
  return ::vapi_msg_id_ipsec_sa_v5_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v5_dump>>()
{
  return ::vapi_msg_id_ipsec_sa_v5_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v5_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v5_dump>(vapi_msg_id_ipsec_sa_v5_dump);
}

template <> inline vapi_msg_ipsec_sa_v5_dump* vapi_alloc<vapi_msg_ipsec_sa_v5_dump>(Connection &con)
{
  vapi_msg_ipsec_sa_v5_dump* result = vapi_alloc_ipsec_sa_v5_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_sa_v5_dump>;

template class Dump<vapi_msg_ipsec_sa_v5_dump, vapi_msg_ipsec_sa_v5_details>;

using Ipsec_sa_v5_dump = Dump<vapi_msg_ipsec_sa_v5_dump, vapi_msg_ipsec_sa_v5_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_details>(vapi_msg_ipsec_sa_details *msg)
{
  vapi_msg_ipsec_sa_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_details>(vapi_msg_ipsec_sa_details *msg)
{
  vapi_msg_ipsec_sa_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_details>()
{
  return ::vapi_msg_id_ipsec_sa_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_details>>()
{
  return ::vapi_msg_id_ipsec_sa_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_details>(vapi_msg_id_ipsec_sa_details);
}

template class Msg<vapi_msg_ipsec_sa_details>;

using Ipsec_sa_details = Msg<vapi_msg_ipsec_sa_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v2_details>(vapi_msg_ipsec_sa_v2_details *msg)
{
  vapi_msg_ipsec_sa_v2_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v2_details>(vapi_msg_ipsec_sa_v2_details *msg)
{
  vapi_msg_ipsec_sa_v2_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v2_details>()
{
  return ::vapi_msg_id_ipsec_sa_v2_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v2_details>>()
{
  return ::vapi_msg_id_ipsec_sa_v2_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v2_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v2_details>(vapi_msg_id_ipsec_sa_v2_details);
}

template class Msg<vapi_msg_ipsec_sa_v2_details>;

using Ipsec_sa_v2_details = Msg<vapi_msg_ipsec_sa_v2_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v3_details>(vapi_msg_ipsec_sa_v3_details *msg)
{
  vapi_msg_ipsec_sa_v3_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v3_details>(vapi_msg_ipsec_sa_v3_details *msg)
{
  vapi_msg_ipsec_sa_v3_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v3_details>()
{
  return ::vapi_msg_id_ipsec_sa_v3_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v3_details>>()
{
  return ::vapi_msg_id_ipsec_sa_v3_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v3_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v3_details>(vapi_msg_id_ipsec_sa_v3_details);
}

template class Msg<vapi_msg_ipsec_sa_v3_details>;

using Ipsec_sa_v3_details = Msg<vapi_msg_ipsec_sa_v3_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v4_details>(vapi_msg_ipsec_sa_v4_details *msg)
{
  vapi_msg_ipsec_sa_v4_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v4_details>(vapi_msg_ipsec_sa_v4_details *msg)
{
  vapi_msg_ipsec_sa_v4_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v4_details>()
{
  return ::vapi_msg_id_ipsec_sa_v4_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v4_details>>()
{
  return ::vapi_msg_id_ipsec_sa_v4_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v4_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v4_details>(vapi_msg_id_ipsec_sa_v4_details);
}

template class Msg<vapi_msg_ipsec_sa_v4_details>;

using Ipsec_sa_v4_details = Msg<vapi_msg_ipsec_sa_v4_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_sa_v5_details>(vapi_msg_ipsec_sa_v5_details *msg)
{
  vapi_msg_ipsec_sa_v5_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_sa_v5_details>(vapi_msg_ipsec_sa_v5_details *msg)
{
  vapi_msg_ipsec_sa_v5_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_sa_v5_details>()
{
  return ::vapi_msg_id_ipsec_sa_v5_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_sa_v5_details>>()
{
  return ::vapi_msg_id_ipsec_sa_v5_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_sa_v5_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_sa_v5_details>(vapi_msg_id_ipsec_sa_v5_details);
}

template class Msg<vapi_msg_ipsec_sa_v5_details>;

using Ipsec_sa_v5_details = Msg<vapi_msg_ipsec_sa_v5_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_backend_dump>(vapi_msg_ipsec_backend_dump *msg)
{
  vapi_msg_ipsec_backend_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_backend_dump>(vapi_msg_ipsec_backend_dump *msg)
{
  vapi_msg_ipsec_backend_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_backend_dump>()
{
  return ::vapi_msg_id_ipsec_backend_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_backend_dump>>()
{
  return ::vapi_msg_id_ipsec_backend_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_backend_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_backend_dump>(vapi_msg_id_ipsec_backend_dump);
}

template <> inline vapi_msg_ipsec_backend_dump* vapi_alloc<vapi_msg_ipsec_backend_dump>(Connection &con)
{
  vapi_msg_ipsec_backend_dump* result = vapi_alloc_ipsec_backend_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_backend_dump>;

template class Dump<vapi_msg_ipsec_backend_dump, vapi_msg_ipsec_backend_details>;

using Ipsec_backend_dump = Dump<vapi_msg_ipsec_backend_dump, vapi_msg_ipsec_backend_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_backend_details>(vapi_msg_ipsec_backend_details *msg)
{
  vapi_msg_ipsec_backend_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_backend_details>(vapi_msg_ipsec_backend_details *msg)
{
  vapi_msg_ipsec_backend_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_backend_details>()
{
  return ::vapi_msg_id_ipsec_backend_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_backend_details>>()
{
  return ::vapi_msg_id_ipsec_backend_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_backend_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_backend_details>(vapi_msg_id_ipsec_backend_details);
}

template class Msg<vapi_msg_ipsec_backend_details>;

using Ipsec_backend_details = Msg<vapi_msg_ipsec_backend_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_select_backend>(vapi_msg_ipsec_select_backend *msg)
{
  vapi_msg_ipsec_select_backend_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_select_backend>(vapi_msg_ipsec_select_backend *msg)
{
  vapi_msg_ipsec_select_backend_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_select_backend>()
{
  return ::vapi_msg_id_ipsec_select_backend; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_select_backend>>()
{
  return ::vapi_msg_id_ipsec_select_backend; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_select_backend()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_select_backend>(vapi_msg_id_ipsec_select_backend);
}

template <> inline vapi_msg_ipsec_select_backend* vapi_alloc<vapi_msg_ipsec_select_backend>(Connection &con)
{
  vapi_msg_ipsec_select_backend* result = vapi_alloc_ipsec_select_backend(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_select_backend>;

template class Request<vapi_msg_ipsec_select_backend, vapi_msg_ipsec_select_backend_reply>;

using Ipsec_select_backend = Request<vapi_msg_ipsec_select_backend, vapi_msg_ipsec_select_backend_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_select_backend_reply>(vapi_msg_ipsec_select_backend_reply *msg)
{
  vapi_msg_ipsec_select_backend_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_select_backend_reply>(vapi_msg_ipsec_select_backend_reply *msg)
{
  vapi_msg_ipsec_select_backend_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_select_backend_reply>()
{
  return ::vapi_msg_id_ipsec_select_backend_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_select_backend_reply>>()
{
  return ::vapi_msg_id_ipsec_select_backend_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_select_backend_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_select_backend_reply>(vapi_msg_id_ipsec_select_backend_reply);
}

template class Msg<vapi_msg_ipsec_select_backend_reply>;

using Ipsec_select_backend_reply = Msg<vapi_msg_ipsec_select_backend_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipsec_set_async_mode>(vapi_msg_ipsec_set_async_mode *msg)
{
  vapi_msg_ipsec_set_async_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_set_async_mode>(vapi_msg_ipsec_set_async_mode *msg)
{
  vapi_msg_ipsec_set_async_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_set_async_mode>()
{
  return ::vapi_msg_id_ipsec_set_async_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_set_async_mode>>()
{
  return ::vapi_msg_id_ipsec_set_async_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_set_async_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_set_async_mode>(vapi_msg_id_ipsec_set_async_mode);
}

template <> inline vapi_msg_ipsec_set_async_mode* vapi_alloc<vapi_msg_ipsec_set_async_mode>(Connection &con)
{
  vapi_msg_ipsec_set_async_mode* result = vapi_alloc_ipsec_set_async_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipsec_set_async_mode>;

template class Request<vapi_msg_ipsec_set_async_mode, vapi_msg_ipsec_set_async_mode_reply>;

using Ipsec_set_async_mode = Request<vapi_msg_ipsec_set_async_mode, vapi_msg_ipsec_set_async_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipsec_set_async_mode_reply>(vapi_msg_ipsec_set_async_mode_reply *msg)
{
  vapi_msg_ipsec_set_async_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipsec_set_async_mode_reply>(vapi_msg_ipsec_set_async_mode_reply *msg)
{
  vapi_msg_ipsec_set_async_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipsec_set_async_mode_reply>()
{
  return ::vapi_msg_id_ipsec_set_async_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipsec_set_async_mode_reply>>()
{
  return ::vapi_msg_id_ipsec_set_async_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipsec_set_async_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipsec_set_async_mode_reply>(vapi_msg_id_ipsec_set_async_mode_reply);
}

template class Msg<vapi_msg_ipsec_set_async_mode_reply>;

using Ipsec_set_async_mode_reply = Msg<vapi_msg_ipsec_set_async_mode_reply>;
}
#endif
