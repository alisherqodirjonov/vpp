#ifndef __included_hpp_qos_api_json
#define __included_hpp_qos_api_json

#include <vapi/vapi.hpp>
#include <vapi/qos.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_qos_store_enable_disable>(vapi_msg_qos_store_enable_disable *msg)
{
  vapi_msg_qos_store_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_store_enable_disable>(vapi_msg_qos_store_enable_disable *msg)
{
  vapi_msg_qos_store_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_store_enable_disable>()
{
  return ::vapi_msg_id_qos_store_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_store_enable_disable>>()
{
  return ::vapi_msg_id_qos_store_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_store_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_store_enable_disable>(vapi_msg_id_qos_store_enable_disable);
}

template <> inline vapi_msg_qos_store_enable_disable* vapi_alloc<vapi_msg_qos_store_enable_disable>(Connection &con)
{
  vapi_msg_qos_store_enable_disable* result = vapi_alloc_qos_store_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_store_enable_disable>;

template class Request<vapi_msg_qos_store_enable_disable, vapi_msg_qos_store_enable_disable_reply>;

using Qos_store_enable_disable = Request<vapi_msg_qos_store_enable_disable, vapi_msg_qos_store_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_store_enable_disable_reply>(vapi_msg_qos_store_enable_disable_reply *msg)
{
  vapi_msg_qos_store_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_store_enable_disable_reply>(vapi_msg_qos_store_enable_disable_reply *msg)
{
  vapi_msg_qos_store_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_store_enable_disable_reply>()
{
  return ::vapi_msg_id_qos_store_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_store_enable_disable_reply>>()
{
  return ::vapi_msg_id_qos_store_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_store_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_store_enable_disable_reply>(vapi_msg_id_qos_store_enable_disable_reply);
}

template class Msg<vapi_msg_qos_store_enable_disable_reply>;

using Qos_store_enable_disable_reply = Msg<vapi_msg_qos_store_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_store_dump>(vapi_msg_qos_store_dump *msg)
{
  vapi_msg_qos_store_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_store_dump>(vapi_msg_qos_store_dump *msg)
{
  vapi_msg_qos_store_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_store_dump>()
{
  return ::vapi_msg_id_qos_store_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_store_dump>>()
{
  return ::vapi_msg_id_qos_store_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_store_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_store_dump>(vapi_msg_id_qos_store_dump);
}

template <> inline vapi_msg_qos_store_dump* vapi_alloc<vapi_msg_qos_store_dump>(Connection &con)
{
  vapi_msg_qos_store_dump* result = vapi_alloc_qos_store_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_store_dump>;

template class Dump<vapi_msg_qos_store_dump, vapi_msg_qos_store_details>;

using Qos_store_dump = Dump<vapi_msg_qos_store_dump, vapi_msg_qos_store_details>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_store_details>(vapi_msg_qos_store_details *msg)
{
  vapi_msg_qos_store_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_store_details>(vapi_msg_qos_store_details *msg)
{
  vapi_msg_qos_store_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_store_details>()
{
  return ::vapi_msg_id_qos_store_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_store_details>>()
{
  return ::vapi_msg_id_qos_store_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_store_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_store_details>(vapi_msg_id_qos_store_details);
}

template class Msg<vapi_msg_qos_store_details>;

using Qos_store_details = Msg<vapi_msg_qos_store_details>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_record_enable_disable>(vapi_msg_qos_record_enable_disable *msg)
{
  vapi_msg_qos_record_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_record_enable_disable>(vapi_msg_qos_record_enable_disable *msg)
{
  vapi_msg_qos_record_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_record_enable_disable>()
{
  return ::vapi_msg_id_qos_record_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_record_enable_disable>>()
{
  return ::vapi_msg_id_qos_record_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_record_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_record_enable_disable>(vapi_msg_id_qos_record_enable_disable);
}

template <> inline vapi_msg_qos_record_enable_disable* vapi_alloc<vapi_msg_qos_record_enable_disable>(Connection &con)
{
  vapi_msg_qos_record_enable_disable* result = vapi_alloc_qos_record_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_record_enable_disable>;

template class Request<vapi_msg_qos_record_enable_disable, vapi_msg_qos_record_enable_disable_reply>;

using Qos_record_enable_disable = Request<vapi_msg_qos_record_enable_disable, vapi_msg_qos_record_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_record_enable_disable_reply>(vapi_msg_qos_record_enable_disable_reply *msg)
{
  vapi_msg_qos_record_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_record_enable_disable_reply>(vapi_msg_qos_record_enable_disable_reply *msg)
{
  vapi_msg_qos_record_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_record_enable_disable_reply>()
{
  return ::vapi_msg_id_qos_record_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_record_enable_disable_reply>>()
{
  return ::vapi_msg_id_qos_record_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_record_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_record_enable_disable_reply>(vapi_msg_id_qos_record_enable_disable_reply);
}

template class Msg<vapi_msg_qos_record_enable_disable_reply>;

using Qos_record_enable_disable_reply = Msg<vapi_msg_qos_record_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_record_dump>(vapi_msg_qos_record_dump *msg)
{
  vapi_msg_qos_record_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_record_dump>(vapi_msg_qos_record_dump *msg)
{
  vapi_msg_qos_record_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_record_dump>()
{
  return ::vapi_msg_id_qos_record_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_record_dump>>()
{
  return ::vapi_msg_id_qos_record_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_record_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_record_dump>(vapi_msg_id_qos_record_dump);
}

template <> inline vapi_msg_qos_record_dump* vapi_alloc<vapi_msg_qos_record_dump>(Connection &con)
{
  vapi_msg_qos_record_dump* result = vapi_alloc_qos_record_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_record_dump>;

template class Dump<vapi_msg_qos_record_dump, vapi_msg_qos_record_details>;

using Qos_record_dump = Dump<vapi_msg_qos_record_dump, vapi_msg_qos_record_details>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_record_details>(vapi_msg_qos_record_details *msg)
{
  vapi_msg_qos_record_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_record_details>(vapi_msg_qos_record_details *msg)
{
  vapi_msg_qos_record_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_record_details>()
{
  return ::vapi_msg_id_qos_record_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_record_details>>()
{
  return ::vapi_msg_id_qos_record_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_record_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_record_details>(vapi_msg_id_qos_record_details);
}

template class Msg<vapi_msg_qos_record_details>;

using Qos_record_details = Msg<vapi_msg_qos_record_details>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_egress_map_update>(vapi_msg_qos_egress_map_update *msg)
{
  vapi_msg_qos_egress_map_update_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_egress_map_update>(vapi_msg_qos_egress_map_update *msg)
{
  vapi_msg_qos_egress_map_update_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_egress_map_update>()
{
  return ::vapi_msg_id_qos_egress_map_update; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_egress_map_update>>()
{
  return ::vapi_msg_id_qos_egress_map_update; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_egress_map_update()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_egress_map_update>(vapi_msg_id_qos_egress_map_update);
}

template <> inline vapi_msg_qos_egress_map_update* vapi_alloc<vapi_msg_qos_egress_map_update>(Connection &con)
{
  vapi_msg_qos_egress_map_update* result = vapi_alloc_qos_egress_map_update(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_egress_map_update>;

template class Request<vapi_msg_qos_egress_map_update, vapi_msg_qos_egress_map_update_reply>;

using Qos_egress_map_update = Request<vapi_msg_qos_egress_map_update, vapi_msg_qos_egress_map_update_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_egress_map_update_reply>(vapi_msg_qos_egress_map_update_reply *msg)
{
  vapi_msg_qos_egress_map_update_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_egress_map_update_reply>(vapi_msg_qos_egress_map_update_reply *msg)
{
  vapi_msg_qos_egress_map_update_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_egress_map_update_reply>()
{
  return ::vapi_msg_id_qos_egress_map_update_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_egress_map_update_reply>>()
{
  return ::vapi_msg_id_qos_egress_map_update_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_egress_map_update_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_egress_map_update_reply>(vapi_msg_id_qos_egress_map_update_reply);
}

template class Msg<vapi_msg_qos_egress_map_update_reply>;

using Qos_egress_map_update_reply = Msg<vapi_msg_qos_egress_map_update_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_egress_map_delete>(vapi_msg_qos_egress_map_delete *msg)
{
  vapi_msg_qos_egress_map_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_egress_map_delete>(vapi_msg_qos_egress_map_delete *msg)
{
  vapi_msg_qos_egress_map_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_egress_map_delete>()
{
  return ::vapi_msg_id_qos_egress_map_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_egress_map_delete>>()
{
  return ::vapi_msg_id_qos_egress_map_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_egress_map_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_egress_map_delete>(vapi_msg_id_qos_egress_map_delete);
}

template <> inline vapi_msg_qos_egress_map_delete* vapi_alloc<vapi_msg_qos_egress_map_delete>(Connection &con)
{
  vapi_msg_qos_egress_map_delete* result = vapi_alloc_qos_egress_map_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_egress_map_delete>;

template class Request<vapi_msg_qos_egress_map_delete, vapi_msg_qos_egress_map_delete_reply>;

using Qos_egress_map_delete = Request<vapi_msg_qos_egress_map_delete, vapi_msg_qos_egress_map_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_egress_map_delete_reply>(vapi_msg_qos_egress_map_delete_reply *msg)
{
  vapi_msg_qos_egress_map_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_egress_map_delete_reply>(vapi_msg_qos_egress_map_delete_reply *msg)
{
  vapi_msg_qos_egress_map_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_egress_map_delete_reply>()
{
  return ::vapi_msg_id_qos_egress_map_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_egress_map_delete_reply>>()
{
  return ::vapi_msg_id_qos_egress_map_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_egress_map_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_egress_map_delete_reply>(vapi_msg_id_qos_egress_map_delete_reply);
}

template class Msg<vapi_msg_qos_egress_map_delete_reply>;

using Qos_egress_map_delete_reply = Msg<vapi_msg_qos_egress_map_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_egress_map_dump>(vapi_msg_qos_egress_map_dump *msg)
{
  vapi_msg_qos_egress_map_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_egress_map_dump>(vapi_msg_qos_egress_map_dump *msg)
{
  vapi_msg_qos_egress_map_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_egress_map_dump>()
{
  return ::vapi_msg_id_qos_egress_map_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_egress_map_dump>>()
{
  return ::vapi_msg_id_qos_egress_map_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_egress_map_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_egress_map_dump>(vapi_msg_id_qos_egress_map_dump);
}

template <> inline vapi_msg_qos_egress_map_dump* vapi_alloc<vapi_msg_qos_egress_map_dump>(Connection &con)
{
  vapi_msg_qos_egress_map_dump* result = vapi_alloc_qos_egress_map_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_egress_map_dump>;

template class Dump<vapi_msg_qos_egress_map_dump, vapi_msg_qos_egress_map_details>;

using Qos_egress_map_dump = Dump<vapi_msg_qos_egress_map_dump, vapi_msg_qos_egress_map_details>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_egress_map_details>(vapi_msg_qos_egress_map_details *msg)
{
  vapi_msg_qos_egress_map_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_egress_map_details>(vapi_msg_qos_egress_map_details *msg)
{
  vapi_msg_qos_egress_map_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_egress_map_details>()
{
  return ::vapi_msg_id_qos_egress_map_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_egress_map_details>>()
{
  return ::vapi_msg_id_qos_egress_map_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_egress_map_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_egress_map_details>(vapi_msg_id_qos_egress_map_details);
}

template class Msg<vapi_msg_qos_egress_map_details>;

using Qos_egress_map_details = Msg<vapi_msg_qos_egress_map_details>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_mark_enable_disable>(vapi_msg_qos_mark_enable_disable *msg)
{
  vapi_msg_qos_mark_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_mark_enable_disable>(vapi_msg_qos_mark_enable_disable *msg)
{
  vapi_msg_qos_mark_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_mark_enable_disable>()
{
  return ::vapi_msg_id_qos_mark_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_mark_enable_disable>>()
{
  return ::vapi_msg_id_qos_mark_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_mark_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_mark_enable_disable>(vapi_msg_id_qos_mark_enable_disable);
}

template <> inline vapi_msg_qos_mark_enable_disable* vapi_alloc<vapi_msg_qos_mark_enable_disable>(Connection &con)
{
  vapi_msg_qos_mark_enable_disable* result = vapi_alloc_qos_mark_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_mark_enable_disable>;

template class Request<vapi_msg_qos_mark_enable_disable, vapi_msg_qos_mark_enable_disable_reply>;

using Qos_mark_enable_disable = Request<vapi_msg_qos_mark_enable_disable, vapi_msg_qos_mark_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_mark_enable_disable_reply>(vapi_msg_qos_mark_enable_disable_reply *msg)
{
  vapi_msg_qos_mark_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_mark_enable_disable_reply>(vapi_msg_qos_mark_enable_disable_reply *msg)
{
  vapi_msg_qos_mark_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_mark_enable_disable_reply>()
{
  return ::vapi_msg_id_qos_mark_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_mark_enable_disable_reply>>()
{
  return ::vapi_msg_id_qos_mark_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_mark_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_mark_enable_disable_reply>(vapi_msg_id_qos_mark_enable_disable_reply);
}

template class Msg<vapi_msg_qos_mark_enable_disable_reply>;

using Qos_mark_enable_disable_reply = Msg<vapi_msg_qos_mark_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_qos_mark_dump>(vapi_msg_qos_mark_dump *msg)
{
  vapi_msg_qos_mark_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_mark_dump>(vapi_msg_qos_mark_dump *msg)
{
  vapi_msg_qos_mark_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_mark_dump>()
{
  return ::vapi_msg_id_qos_mark_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_mark_dump>>()
{
  return ::vapi_msg_id_qos_mark_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_mark_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_mark_dump>(vapi_msg_id_qos_mark_dump);
}

template <> inline vapi_msg_qos_mark_dump* vapi_alloc<vapi_msg_qos_mark_dump>(Connection &con)
{
  vapi_msg_qos_mark_dump* result = vapi_alloc_qos_mark_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_qos_mark_dump>;

template class Dump<vapi_msg_qos_mark_dump, vapi_msg_qos_mark_details>;

using Qos_mark_dump = Dump<vapi_msg_qos_mark_dump, vapi_msg_qos_mark_details>;

template <> inline void vapi_swap_to_be<vapi_msg_qos_mark_details>(vapi_msg_qos_mark_details *msg)
{
  vapi_msg_qos_mark_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_qos_mark_details>(vapi_msg_qos_mark_details *msg)
{
  vapi_msg_qos_mark_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_qos_mark_details>()
{
  return ::vapi_msg_id_qos_mark_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_qos_mark_details>>()
{
  return ::vapi_msg_id_qos_mark_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_qos_mark_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_qos_mark_details>(vapi_msg_id_qos_mark_details);
}

template class Msg<vapi_msg_qos_mark_details>;

using Qos_mark_details = Msg<vapi_msg_qos_mark_details>;
}
#endif
