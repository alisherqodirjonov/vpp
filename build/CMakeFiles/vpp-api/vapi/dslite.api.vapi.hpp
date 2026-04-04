#ifndef __included_hpp_dslite_api_json
#define __included_hpp_dslite_api_json

#include <vapi/vapi.hpp>
#include <vapi/dslite.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_dslite_add_del_pool_addr_range>(vapi_msg_dslite_add_del_pool_addr_range *msg)
{
  vapi_msg_dslite_add_del_pool_addr_range_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_add_del_pool_addr_range>(vapi_msg_dslite_add_del_pool_addr_range *msg)
{
  vapi_msg_dslite_add_del_pool_addr_range_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_add_del_pool_addr_range>()
{
  return ::vapi_msg_id_dslite_add_del_pool_addr_range; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_add_del_pool_addr_range>>()
{
  return ::vapi_msg_id_dslite_add_del_pool_addr_range; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_add_del_pool_addr_range()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_add_del_pool_addr_range>(vapi_msg_id_dslite_add_del_pool_addr_range);
}

template <> inline vapi_msg_dslite_add_del_pool_addr_range* vapi_alloc<vapi_msg_dslite_add_del_pool_addr_range>(Connection &con)
{
  vapi_msg_dslite_add_del_pool_addr_range* result = vapi_alloc_dslite_add_del_pool_addr_range(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dslite_add_del_pool_addr_range>;

template class Request<vapi_msg_dslite_add_del_pool_addr_range, vapi_msg_dslite_add_del_pool_addr_range_reply>;

using Dslite_add_del_pool_addr_range = Request<vapi_msg_dslite_add_del_pool_addr_range, vapi_msg_dslite_add_del_pool_addr_range_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dslite_add_del_pool_addr_range_reply>(vapi_msg_dslite_add_del_pool_addr_range_reply *msg)
{
  vapi_msg_dslite_add_del_pool_addr_range_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_add_del_pool_addr_range_reply>(vapi_msg_dslite_add_del_pool_addr_range_reply *msg)
{
  vapi_msg_dslite_add_del_pool_addr_range_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_add_del_pool_addr_range_reply>()
{
  return ::vapi_msg_id_dslite_add_del_pool_addr_range_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_add_del_pool_addr_range_reply>>()
{
  return ::vapi_msg_id_dslite_add_del_pool_addr_range_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_add_del_pool_addr_range_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_add_del_pool_addr_range_reply>(vapi_msg_id_dslite_add_del_pool_addr_range_reply);
}

template class Msg<vapi_msg_dslite_add_del_pool_addr_range_reply>;

using Dslite_add_del_pool_addr_range_reply = Msg<vapi_msg_dslite_add_del_pool_addr_range_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dslite_address_dump>(vapi_msg_dslite_address_dump *msg)
{
  vapi_msg_dslite_address_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_address_dump>(vapi_msg_dslite_address_dump *msg)
{
  vapi_msg_dslite_address_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_address_dump>()
{
  return ::vapi_msg_id_dslite_address_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_address_dump>>()
{
  return ::vapi_msg_id_dslite_address_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_address_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_address_dump>(vapi_msg_id_dslite_address_dump);
}

template <> inline vapi_msg_dslite_address_dump* vapi_alloc<vapi_msg_dslite_address_dump>(Connection &con)
{
  vapi_msg_dslite_address_dump* result = vapi_alloc_dslite_address_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dslite_address_dump>;

template class Dump<vapi_msg_dslite_address_dump, vapi_msg_dslite_address_details>;

using Dslite_address_dump = Dump<vapi_msg_dslite_address_dump, vapi_msg_dslite_address_details>;

template <> inline void vapi_swap_to_be<vapi_msg_dslite_address_details>(vapi_msg_dslite_address_details *msg)
{
  vapi_msg_dslite_address_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_address_details>(vapi_msg_dslite_address_details *msg)
{
  vapi_msg_dslite_address_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_address_details>()
{
  return ::vapi_msg_id_dslite_address_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_address_details>>()
{
  return ::vapi_msg_id_dslite_address_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_address_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_address_details>(vapi_msg_id_dslite_address_details);
}

template class Msg<vapi_msg_dslite_address_details>;

using Dslite_address_details = Msg<vapi_msg_dslite_address_details>;
template <> inline void vapi_swap_to_be<vapi_msg_dslite_set_aftr_addr>(vapi_msg_dslite_set_aftr_addr *msg)
{
  vapi_msg_dslite_set_aftr_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_set_aftr_addr>(vapi_msg_dslite_set_aftr_addr *msg)
{
  vapi_msg_dslite_set_aftr_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_set_aftr_addr>()
{
  return ::vapi_msg_id_dslite_set_aftr_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_set_aftr_addr>>()
{
  return ::vapi_msg_id_dslite_set_aftr_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_set_aftr_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_set_aftr_addr>(vapi_msg_id_dslite_set_aftr_addr);
}

template <> inline vapi_msg_dslite_set_aftr_addr* vapi_alloc<vapi_msg_dslite_set_aftr_addr>(Connection &con)
{
  vapi_msg_dslite_set_aftr_addr* result = vapi_alloc_dslite_set_aftr_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dslite_set_aftr_addr>;

template class Request<vapi_msg_dslite_set_aftr_addr, vapi_msg_dslite_set_aftr_addr_reply>;

using Dslite_set_aftr_addr = Request<vapi_msg_dslite_set_aftr_addr, vapi_msg_dslite_set_aftr_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dslite_set_aftr_addr_reply>(vapi_msg_dslite_set_aftr_addr_reply *msg)
{
  vapi_msg_dslite_set_aftr_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_set_aftr_addr_reply>(vapi_msg_dslite_set_aftr_addr_reply *msg)
{
  vapi_msg_dslite_set_aftr_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_set_aftr_addr_reply>()
{
  return ::vapi_msg_id_dslite_set_aftr_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_set_aftr_addr_reply>>()
{
  return ::vapi_msg_id_dslite_set_aftr_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_set_aftr_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_set_aftr_addr_reply>(vapi_msg_id_dslite_set_aftr_addr_reply);
}

template class Msg<vapi_msg_dslite_set_aftr_addr_reply>;

using Dslite_set_aftr_addr_reply = Msg<vapi_msg_dslite_set_aftr_addr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dslite_get_aftr_addr>(vapi_msg_dslite_get_aftr_addr *msg)
{
  vapi_msg_dslite_get_aftr_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_get_aftr_addr>(vapi_msg_dslite_get_aftr_addr *msg)
{
  vapi_msg_dslite_get_aftr_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_get_aftr_addr>()
{
  return ::vapi_msg_id_dslite_get_aftr_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_get_aftr_addr>>()
{
  return ::vapi_msg_id_dslite_get_aftr_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_get_aftr_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_get_aftr_addr>(vapi_msg_id_dslite_get_aftr_addr);
}

template <> inline vapi_msg_dslite_get_aftr_addr* vapi_alloc<vapi_msg_dslite_get_aftr_addr>(Connection &con)
{
  vapi_msg_dslite_get_aftr_addr* result = vapi_alloc_dslite_get_aftr_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dslite_get_aftr_addr>;

template class Request<vapi_msg_dslite_get_aftr_addr, vapi_msg_dslite_get_aftr_addr_reply>;

using Dslite_get_aftr_addr = Request<vapi_msg_dslite_get_aftr_addr, vapi_msg_dslite_get_aftr_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dslite_get_aftr_addr_reply>(vapi_msg_dslite_get_aftr_addr_reply *msg)
{
  vapi_msg_dslite_get_aftr_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_get_aftr_addr_reply>(vapi_msg_dslite_get_aftr_addr_reply *msg)
{
  vapi_msg_dslite_get_aftr_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_get_aftr_addr_reply>()
{
  return ::vapi_msg_id_dslite_get_aftr_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_get_aftr_addr_reply>>()
{
  return ::vapi_msg_id_dslite_get_aftr_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_get_aftr_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_get_aftr_addr_reply>(vapi_msg_id_dslite_get_aftr_addr_reply);
}

template class Msg<vapi_msg_dslite_get_aftr_addr_reply>;

using Dslite_get_aftr_addr_reply = Msg<vapi_msg_dslite_get_aftr_addr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dslite_set_b4_addr>(vapi_msg_dslite_set_b4_addr *msg)
{
  vapi_msg_dslite_set_b4_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_set_b4_addr>(vapi_msg_dslite_set_b4_addr *msg)
{
  vapi_msg_dslite_set_b4_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_set_b4_addr>()
{
  return ::vapi_msg_id_dslite_set_b4_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_set_b4_addr>>()
{
  return ::vapi_msg_id_dslite_set_b4_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_set_b4_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_set_b4_addr>(vapi_msg_id_dslite_set_b4_addr);
}

template <> inline vapi_msg_dslite_set_b4_addr* vapi_alloc<vapi_msg_dslite_set_b4_addr>(Connection &con)
{
  vapi_msg_dslite_set_b4_addr* result = vapi_alloc_dslite_set_b4_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dslite_set_b4_addr>;

template class Request<vapi_msg_dslite_set_b4_addr, vapi_msg_dslite_set_b4_addr_reply>;

using Dslite_set_b4_addr = Request<vapi_msg_dslite_set_b4_addr, vapi_msg_dslite_set_b4_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dslite_set_b4_addr_reply>(vapi_msg_dslite_set_b4_addr_reply *msg)
{
  vapi_msg_dslite_set_b4_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_set_b4_addr_reply>(vapi_msg_dslite_set_b4_addr_reply *msg)
{
  vapi_msg_dslite_set_b4_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_set_b4_addr_reply>()
{
  return ::vapi_msg_id_dslite_set_b4_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_set_b4_addr_reply>>()
{
  return ::vapi_msg_id_dslite_set_b4_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_set_b4_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_set_b4_addr_reply>(vapi_msg_id_dslite_set_b4_addr_reply);
}

template class Msg<vapi_msg_dslite_set_b4_addr_reply>;

using Dslite_set_b4_addr_reply = Msg<vapi_msg_dslite_set_b4_addr_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_dslite_get_b4_addr>(vapi_msg_dslite_get_b4_addr *msg)
{
  vapi_msg_dslite_get_b4_addr_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_get_b4_addr>(vapi_msg_dslite_get_b4_addr *msg)
{
  vapi_msg_dslite_get_b4_addr_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_get_b4_addr>()
{
  return ::vapi_msg_id_dslite_get_b4_addr; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_get_b4_addr>>()
{
  return ::vapi_msg_id_dslite_get_b4_addr; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_get_b4_addr()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_get_b4_addr>(vapi_msg_id_dslite_get_b4_addr);
}

template <> inline vapi_msg_dslite_get_b4_addr* vapi_alloc<vapi_msg_dslite_get_b4_addr>(Connection &con)
{
  vapi_msg_dslite_get_b4_addr* result = vapi_alloc_dslite_get_b4_addr(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_dslite_get_b4_addr>;

template class Request<vapi_msg_dslite_get_b4_addr, vapi_msg_dslite_get_b4_addr_reply>;

using Dslite_get_b4_addr = Request<vapi_msg_dslite_get_b4_addr, vapi_msg_dslite_get_b4_addr_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_dslite_get_b4_addr_reply>(vapi_msg_dslite_get_b4_addr_reply *msg)
{
  vapi_msg_dslite_get_b4_addr_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_dslite_get_b4_addr_reply>(vapi_msg_dslite_get_b4_addr_reply *msg)
{
  vapi_msg_dslite_get_b4_addr_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_dslite_get_b4_addr_reply>()
{
  return ::vapi_msg_id_dslite_get_b4_addr_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_dslite_get_b4_addr_reply>>()
{
  return ::vapi_msg_id_dslite_get_b4_addr_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_dslite_get_b4_addr_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_dslite_get_b4_addr_reply>(vapi_msg_id_dslite_get_b4_addr_reply);
}

template class Msg<vapi_msg_dslite_get_b4_addr_reply>;

using Dslite_get_b4_addr_reply = Msg<vapi_msg_dslite_get_b4_addr_reply>;
}
#endif
