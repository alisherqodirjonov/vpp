#ifndef __included_hpp_selog_api_json
#define __included_hpp_selog_api_json

#include <vapi/vapi.hpp>
#include <vapi/selog.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_selog_get_shm>(vapi_msg_selog_get_shm *msg)
{
  vapi_msg_selog_get_shm_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_get_shm>(vapi_msg_selog_get_shm *msg)
{
  vapi_msg_selog_get_shm_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_get_shm>()
{
  return ::vapi_msg_id_selog_get_shm; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_get_shm>>()
{
  return ::vapi_msg_id_selog_get_shm; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_get_shm()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_get_shm>(vapi_msg_id_selog_get_shm);
}

template <> inline vapi_msg_selog_get_shm* vapi_alloc<vapi_msg_selog_get_shm>(Connection &con)
{
  vapi_msg_selog_get_shm* result = vapi_alloc_selog_get_shm(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_selog_get_shm>;

template class Request<vapi_msg_selog_get_shm, vapi_msg_selog_get_shm_reply>;

using Selog_get_shm = Request<vapi_msg_selog_get_shm, vapi_msg_selog_get_shm_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_selog_get_shm_reply>(vapi_msg_selog_get_shm_reply *msg)
{
  vapi_msg_selog_get_shm_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_get_shm_reply>(vapi_msg_selog_get_shm_reply *msg)
{
  vapi_msg_selog_get_shm_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_get_shm_reply>()
{
  return ::vapi_msg_id_selog_get_shm_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_get_shm_reply>>()
{
  return ::vapi_msg_id_selog_get_shm_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_get_shm_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_get_shm_reply>(vapi_msg_id_selog_get_shm_reply);
}

template class Msg<vapi_msg_selog_get_shm_reply>;

using Selog_get_shm_reply = Msg<vapi_msg_selog_get_shm_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_selog_get_string_table>(vapi_msg_selog_get_string_table *msg)
{
  vapi_msg_selog_get_string_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_get_string_table>(vapi_msg_selog_get_string_table *msg)
{
  vapi_msg_selog_get_string_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_get_string_table>()
{
  return ::vapi_msg_id_selog_get_string_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_get_string_table>>()
{
  return ::vapi_msg_id_selog_get_string_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_get_string_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_get_string_table>(vapi_msg_id_selog_get_string_table);
}

template <> inline vapi_msg_selog_get_string_table* vapi_alloc<vapi_msg_selog_get_string_table>(Connection &con)
{
  vapi_msg_selog_get_string_table* result = vapi_alloc_selog_get_string_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_selog_get_string_table>;

template class Request<vapi_msg_selog_get_string_table, vapi_msg_selog_get_string_table_reply>;

using Selog_get_string_table = Request<vapi_msg_selog_get_string_table, vapi_msg_selog_get_string_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_selog_get_string_table_reply>(vapi_msg_selog_get_string_table_reply *msg)
{
  vapi_msg_selog_get_string_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_get_string_table_reply>(vapi_msg_selog_get_string_table_reply *msg)
{
  vapi_msg_selog_get_string_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_get_string_table_reply>()
{
  return ::vapi_msg_id_selog_get_string_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_get_string_table_reply>>()
{
  return ::vapi_msg_id_selog_get_string_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_get_string_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_get_string_table_reply>(vapi_msg_id_selog_get_string_table_reply);
}

template class Msg<vapi_msg_selog_get_string_table_reply>;

using Selog_get_string_table_reply = Msg<vapi_msg_selog_get_string_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_selog_track_dump>(vapi_msg_selog_track_dump *msg)
{
  vapi_msg_selog_track_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_track_dump>(vapi_msg_selog_track_dump *msg)
{
  vapi_msg_selog_track_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_track_dump>()
{
  return ::vapi_msg_id_selog_track_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_track_dump>>()
{
  return ::vapi_msg_id_selog_track_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_track_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_track_dump>(vapi_msg_id_selog_track_dump);
}

template <> inline vapi_msg_selog_track_dump* vapi_alloc<vapi_msg_selog_track_dump>(Connection &con)
{
  vapi_msg_selog_track_dump* result = vapi_alloc_selog_track_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_selog_track_dump>;

template class Dump<vapi_msg_selog_track_dump, vapi_msg_selog_track_details>;

using Selog_track_dump = Dump<vapi_msg_selog_track_dump, vapi_msg_selog_track_details>;

template <> inline void vapi_swap_to_be<vapi_msg_selog_track_details>(vapi_msg_selog_track_details *msg)
{
  vapi_msg_selog_track_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_track_details>(vapi_msg_selog_track_details *msg)
{
  vapi_msg_selog_track_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_track_details>()
{
  return ::vapi_msg_id_selog_track_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_track_details>>()
{
  return ::vapi_msg_id_selog_track_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_track_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_track_details>(vapi_msg_id_selog_track_details);
}

template class Msg<vapi_msg_selog_track_details>;

using Selog_track_details = Msg<vapi_msg_selog_track_details>;
template <> inline void vapi_swap_to_be<vapi_msg_selog_event_type_dump>(vapi_msg_selog_event_type_dump *msg)
{
  vapi_msg_selog_event_type_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_event_type_dump>(vapi_msg_selog_event_type_dump *msg)
{
  vapi_msg_selog_event_type_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_event_type_dump>()
{
  return ::vapi_msg_id_selog_event_type_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_event_type_dump>>()
{
  return ::vapi_msg_id_selog_event_type_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_event_type_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_event_type_dump>(vapi_msg_id_selog_event_type_dump);
}

template <> inline vapi_msg_selog_event_type_dump* vapi_alloc<vapi_msg_selog_event_type_dump>(Connection &con)
{
  vapi_msg_selog_event_type_dump* result = vapi_alloc_selog_event_type_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_selog_event_type_dump>;

template class Dump<vapi_msg_selog_event_type_dump, vapi_msg_selog_event_type_details>;

using Selog_event_type_dump = Dump<vapi_msg_selog_event_type_dump, vapi_msg_selog_event_type_details>;

template <> inline void vapi_swap_to_be<vapi_msg_selog_event_type_details>(vapi_msg_selog_event_type_details *msg)
{
  vapi_msg_selog_event_type_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_event_type_details>(vapi_msg_selog_event_type_details *msg)
{
  vapi_msg_selog_event_type_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_event_type_details>()
{
  return ::vapi_msg_id_selog_event_type_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_event_type_details>>()
{
  return ::vapi_msg_id_selog_event_type_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_event_type_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_event_type_details>(vapi_msg_id_selog_event_type_details);
}

template class Msg<vapi_msg_selog_event_type_details>;

using Selog_event_type_details = Msg<vapi_msg_selog_event_type_details>;
template <> inline void vapi_swap_to_be<vapi_msg_selog_event_type_string_dump>(vapi_msg_selog_event_type_string_dump *msg)
{
  vapi_msg_selog_event_type_string_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_event_type_string_dump>(vapi_msg_selog_event_type_string_dump *msg)
{
  vapi_msg_selog_event_type_string_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_event_type_string_dump>()
{
  return ::vapi_msg_id_selog_event_type_string_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_event_type_string_dump>>()
{
  return ::vapi_msg_id_selog_event_type_string_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_event_type_string_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_event_type_string_dump>(vapi_msg_id_selog_event_type_string_dump);
}

template <> inline vapi_msg_selog_event_type_string_dump* vapi_alloc<vapi_msg_selog_event_type_string_dump>(Connection &con)
{
  vapi_msg_selog_event_type_string_dump* result = vapi_alloc_selog_event_type_string_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_selog_event_type_string_dump>;

template class Dump<vapi_msg_selog_event_type_string_dump, vapi_msg_selog_event_type_string_details>;

using Selog_event_type_string_dump = Dump<vapi_msg_selog_event_type_string_dump, vapi_msg_selog_event_type_string_details>;

template <> inline void vapi_swap_to_be<vapi_msg_selog_event_type_string_details>(vapi_msg_selog_event_type_string_details *msg)
{
  vapi_msg_selog_event_type_string_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_selog_event_type_string_details>(vapi_msg_selog_event_type_string_details *msg)
{
  vapi_msg_selog_event_type_string_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_selog_event_type_string_details>()
{
  return ::vapi_msg_id_selog_event_type_string_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_selog_event_type_string_details>>()
{
  return ::vapi_msg_id_selog_event_type_string_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_selog_event_type_string_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_selog_event_type_string_details>(vapi_msg_id_selog_event_type_string_details);
}

template class Msg<vapi_msg_selog_event_type_string_details>;

using Selog_event_type_string_details = Msg<vapi_msg_selog_event_type_string_details>;
}
#endif
