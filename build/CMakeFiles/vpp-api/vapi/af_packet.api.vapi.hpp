#ifndef __included_hpp_af_packet_api_json
#define __included_hpp_af_packet_api_json

#include <vapi/vapi.hpp>
#include <vapi/af_packet.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_create>(vapi_msg_af_packet_create *msg)
{
  vapi_msg_af_packet_create_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_create>(vapi_msg_af_packet_create *msg)
{
  vapi_msg_af_packet_create_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_create>()
{
  return ::vapi_msg_id_af_packet_create; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_create>>()
{
  return ::vapi_msg_id_af_packet_create; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_create()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_create>(vapi_msg_id_af_packet_create);
}

template <> inline vapi_msg_af_packet_create* vapi_alloc<vapi_msg_af_packet_create>(Connection &con)
{
  vapi_msg_af_packet_create* result = vapi_alloc_af_packet_create(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_af_packet_create>;

template class Request<vapi_msg_af_packet_create, vapi_msg_af_packet_create_reply>;

using Af_packet_create = Request<vapi_msg_af_packet_create, vapi_msg_af_packet_create_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_create_reply>(vapi_msg_af_packet_create_reply *msg)
{
  vapi_msg_af_packet_create_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_create_reply>(vapi_msg_af_packet_create_reply *msg)
{
  vapi_msg_af_packet_create_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_create_reply>()
{
  return ::vapi_msg_id_af_packet_create_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_create_reply>>()
{
  return ::vapi_msg_id_af_packet_create_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_create_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_create_reply>(vapi_msg_id_af_packet_create_reply);
}

template class Msg<vapi_msg_af_packet_create_reply>;

using Af_packet_create_reply = Msg<vapi_msg_af_packet_create_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_af_packet_create_v2>(vapi_msg_af_packet_create_v2 *msg)
{
  vapi_msg_af_packet_create_v2_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_create_v2>(vapi_msg_af_packet_create_v2 *msg)
{
  vapi_msg_af_packet_create_v2_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_create_v2>()
{
  return ::vapi_msg_id_af_packet_create_v2; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_create_v2>>()
{
  return ::vapi_msg_id_af_packet_create_v2; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_create_v2()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_create_v2>(vapi_msg_id_af_packet_create_v2);
}

template <> inline vapi_msg_af_packet_create_v2* vapi_alloc<vapi_msg_af_packet_create_v2>(Connection &con)
{
  vapi_msg_af_packet_create_v2* result = vapi_alloc_af_packet_create_v2(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_af_packet_create_v2>;

template class Request<vapi_msg_af_packet_create_v2, vapi_msg_af_packet_create_v2_reply>;

using Af_packet_create_v2 = Request<vapi_msg_af_packet_create_v2, vapi_msg_af_packet_create_v2_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_create_v2_reply>(vapi_msg_af_packet_create_v2_reply *msg)
{
  vapi_msg_af_packet_create_v2_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_create_v2_reply>(vapi_msg_af_packet_create_v2_reply *msg)
{
  vapi_msg_af_packet_create_v2_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_create_v2_reply>()
{
  return ::vapi_msg_id_af_packet_create_v2_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_create_v2_reply>>()
{
  return ::vapi_msg_id_af_packet_create_v2_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_create_v2_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_create_v2_reply>(vapi_msg_id_af_packet_create_v2_reply);
}

template class Msg<vapi_msg_af_packet_create_v2_reply>;

using Af_packet_create_v2_reply = Msg<vapi_msg_af_packet_create_v2_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_af_packet_create_v3>(vapi_msg_af_packet_create_v3 *msg)
{
  vapi_msg_af_packet_create_v3_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_create_v3>(vapi_msg_af_packet_create_v3 *msg)
{
  vapi_msg_af_packet_create_v3_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_create_v3>()
{
  return ::vapi_msg_id_af_packet_create_v3; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_create_v3>>()
{
  return ::vapi_msg_id_af_packet_create_v3; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_create_v3()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_create_v3>(vapi_msg_id_af_packet_create_v3);
}

template <> inline vapi_msg_af_packet_create_v3* vapi_alloc<vapi_msg_af_packet_create_v3>(Connection &con)
{
  vapi_msg_af_packet_create_v3* result = vapi_alloc_af_packet_create_v3(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_af_packet_create_v3>;

template class Request<vapi_msg_af_packet_create_v3, vapi_msg_af_packet_create_v3_reply>;

using Af_packet_create_v3 = Request<vapi_msg_af_packet_create_v3, vapi_msg_af_packet_create_v3_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_create_v3_reply>(vapi_msg_af_packet_create_v3_reply *msg)
{
  vapi_msg_af_packet_create_v3_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_create_v3_reply>(vapi_msg_af_packet_create_v3_reply *msg)
{
  vapi_msg_af_packet_create_v3_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_create_v3_reply>()
{
  return ::vapi_msg_id_af_packet_create_v3_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_create_v3_reply>>()
{
  return ::vapi_msg_id_af_packet_create_v3_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_create_v3_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_create_v3_reply>(vapi_msg_id_af_packet_create_v3_reply);
}

template class Msg<vapi_msg_af_packet_create_v3_reply>;

using Af_packet_create_v3_reply = Msg<vapi_msg_af_packet_create_v3_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_af_packet_delete>(vapi_msg_af_packet_delete *msg)
{
  vapi_msg_af_packet_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_delete>(vapi_msg_af_packet_delete *msg)
{
  vapi_msg_af_packet_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_delete>()
{
  return ::vapi_msg_id_af_packet_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_delete>>()
{
  return ::vapi_msg_id_af_packet_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_delete>(vapi_msg_id_af_packet_delete);
}

template <> inline vapi_msg_af_packet_delete* vapi_alloc<vapi_msg_af_packet_delete>(Connection &con)
{
  vapi_msg_af_packet_delete* result = vapi_alloc_af_packet_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_af_packet_delete>;

template class Request<vapi_msg_af_packet_delete, vapi_msg_af_packet_delete_reply>;

using Af_packet_delete = Request<vapi_msg_af_packet_delete, vapi_msg_af_packet_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_delete_reply>(vapi_msg_af_packet_delete_reply *msg)
{
  vapi_msg_af_packet_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_delete_reply>(vapi_msg_af_packet_delete_reply *msg)
{
  vapi_msg_af_packet_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_delete_reply>()
{
  return ::vapi_msg_id_af_packet_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_delete_reply>>()
{
  return ::vapi_msg_id_af_packet_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_delete_reply>(vapi_msg_id_af_packet_delete_reply);
}

template class Msg<vapi_msg_af_packet_delete_reply>;

using Af_packet_delete_reply = Msg<vapi_msg_af_packet_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_af_packet_set_l4_cksum_offload>(vapi_msg_af_packet_set_l4_cksum_offload *msg)
{
  vapi_msg_af_packet_set_l4_cksum_offload_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_set_l4_cksum_offload>(vapi_msg_af_packet_set_l4_cksum_offload *msg)
{
  vapi_msg_af_packet_set_l4_cksum_offload_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_set_l4_cksum_offload>()
{
  return ::vapi_msg_id_af_packet_set_l4_cksum_offload; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_set_l4_cksum_offload>>()
{
  return ::vapi_msg_id_af_packet_set_l4_cksum_offload; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_set_l4_cksum_offload()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_set_l4_cksum_offload>(vapi_msg_id_af_packet_set_l4_cksum_offload);
}

template <> inline vapi_msg_af_packet_set_l4_cksum_offload* vapi_alloc<vapi_msg_af_packet_set_l4_cksum_offload>(Connection &con)
{
  vapi_msg_af_packet_set_l4_cksum_offload* result = vapi_alloc_af_packet_set_l4_cksum_offload(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_af_packet_set_l4_cksum_offload>;

template class Request<vapi_msg_af_packet_set_l4_cksum_offload, vapi_msg_af_packet_set_l4_cksum_offload_reply>;

using Af_packet_set_l4_cksum_offload = Request<vapi_msg_af_packet_set_l4_cksum_offload, vapi_msg_af_packet_set_l4_cksum_offload_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_set_l4_cksum_offload_reply>(vapi_msg_af_packet_set_l4_cksum_offload_reply *msg)
{
  vapi_msg_af_packet_set_l4_cksum_offload_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_set_l4_cksum_offload_reply>(vapi_msg_af_packet_set_l4_cksum_offload_reply *msg)
{
  vapi_msg_af_packet_set_l4_cksum_offload_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_set_l4_cksum_offload_reply>()
{
  return ::vapi_msg_id_af_packet_set_l4_cksum_offload_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_set_l4_cksum_offload_reply>>()
{
  return ::vapi_msg_id_af_packet_set_l4_cksum_offload_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_set_l4_cksum_offload_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_set_l4_cksum_offload_reply>(vapi_msg_id_af_packet_set_l4_cksum_offload_reply);
}

template class Msg<vapi_msg_af_packet_set_l4_cksum_offload_reply>;

using Af_packet_set_l4_cksum_offload_reply = Msg<vapi_msg_af_packet_set_l4_cksum_offload_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_af_packet_dump>(vapi_msg_af_packet_dump *msg)
{
  vapi_msg_af_packet_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_dump>(vapi_msg_af_packet_dump *msg)
{
  vapi_msg_af_packet_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_dump>()
{
  return ::vapi_msg_id_af_packet_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_dump>>()
{
  return ::vapi_msg_id_af_packet_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_dump>(vapi_msg_id_af_packet_dump);
}

template <> inline vapi_msg_af_packet_dump* vapi_alloc<vapi_msg_af_packet_dump>(Connection &con)
{
  vapi_msg_af_packet_dump* result = vapi_alloc_af_packet_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_af_packet_dump>;

template class Dump<vapi_msg_af_packet_dump, vapi_msg_af_packet_details>;

using Af_packet_dump = Dump<vapi_msg_af_packet_dump, vapi_msg_af_packet_details>;

template <> inline void vapi_swap_to_be<vapi_msg_af_packet_details>(vapi_msg_af_packet_details *msg)
{
  vapi_msg_af_packet_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_af_packet_details>(vapi_msg_af_packet_details *msg)
{
  vapi_msg_af_packet_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_af_packet_details>()
{
  return ::vapi_msg_id_af_packet_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_af_packet_details>>()
{
  return ::vapi_msg_id_af_packet_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_af_packet_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_af_packet_details>(vapi_msg_id_af_packet_details);
}

template class Msg<vapi_msg_af_packet_details>;

using Af_packet_details = Msg<vapi_msg_af_packet_details>;
}
#endif
