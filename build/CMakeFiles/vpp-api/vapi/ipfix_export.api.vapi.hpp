#ifndef __included_hpp_ipfix_export_api_json
#define __included_hpp_ipfix_export_api_json

#include <vapi/vapi.hpp>
#include <vapi/ipfix_export.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_set_ipfix_exporter>(vapi_msg_set_ipfix_exporter *msg)
{
  vapi_msg_set_ipfix_exporter_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ipfix_exporter>(vapi_msg_set_ipfix_exporter *msg)
{
  vapi_msg_set_ipfix_exporter_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ipfix_exporter>()
{
  return ::vapi_msg_id_set_ipfix_exporter; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ipfix_exporter>>()
{
  return ::vapi_msg_id_set_ipfix_exporter; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ipfix_exporter()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ipfix_exporter>(vapi_msg_id_set_ipfix_exporter);
}

template <> inline vapi_msg_set_ipfix_exporter* vapi_alloc<vapi_msg_set_ipfix_exporter>(Connection &con)
{
  vapi_msg_set_ipfix_exporter* result = vapi_alloc_set_ipfix_exporter(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_ipfix_exporter>;

template class Request<vapi_msg_set_ipfix_exporter, vapi_msg_set_ipfix_exporter_reply>;

using Set_ipfix_exporter = Request<vapi_msg_set_ipfix_exporter, vapi_msg_set_ipfix_exporter_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ipfix_exporter_reply>(vapi_msg_set_ipfix_exporter_reply *msg)
{
  vapi_msg_set_ipfix_exporter_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ipfix_exporter_reply>(vapi_msg_set_ipfix_exporter_reply *msg)
{
  vapi_msg_set_ipfix_exporter_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ipfix_exporter_reply>()
{
  return ::vapi_msg_id_set_ipfix_exporter_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ipfix_exporter_reply>>()
{
  return ::vapi_msg_id_set_ipfix_exporter_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ipfix_exporter_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ipfix_exporter_reply>(vapi_msg_id_set_ipfix_exporter_reply);
}

template class Msg<vapi_msg_set_ipfix_exporter_reply>;

using Set_ipfix_exporter_reply = Msg<vapi_msg_set_ipfix_exporter_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_exporter_dump>(vapi_msg_ipfix_exporter_dump *msg)
{
  vapi_msg_ipfix_exporter_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_exporter_dump>(vapi_msg_ipfix_exporter_dump *msg)
{
  vapi_msg_ipfix_exporter_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_exporter_dump>()
{
  return ::vapi_msg_id_ipfix_exporter_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_exporter_dump>>()
{
  return ::vapi_msg_id_ipfix_exporter_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_exporter_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_exporter_dump>(vapi_msg_id_ipfix_exporter_dump);
}

template <> inline vapi_msg_ipfix_exporter_dump* vapi_alloc<vapi_msg_ipfix_exporter_dump>(Connection &con)
{
  vapi_msg_ipfix_exporter_dump* result = vapi_alloc_ipfix_exporter_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_exporter_dump>;

template class Dump<vapi_msg_ipfix_exporter_dump, vapi_msg_ipfix_exporter_details>;

using Ipfix_exporter_dump = Dump<vapi_msg_ipfix_exporter_dump, vapi_msg_ipfix_exporter_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_exporter_details>(vapi_msg_ipfix_exporter_details *msg)
{
  vapi_msg_ipfix_exporter_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_exporter_details>(vapi_msg_ipfix_exporter_details *msg)
{
  vapi_msg_ipfix_exporter_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_exporter_details>()
{
  return ::vapi_msg_id_ipfix_exporter_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_exporter_details>>()
{
  return ::vapi_msg_id_ipfix_exporter_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_exporter_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_exporter_details>(vapi_msg_id_ipfix_exporter_details);
}

template class Msg<vapi_msg_ipfix_exporter_details>;

using Ipfix_exporter_details = Msg<vapi_msg_ipfix_exporter_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_exporter_create_delete>(vapi_msg_ipfix_exporter_create_delete *msg)
{
  vapi_msg_ipfix_exporter_create_delete_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_exporter_create_delete>(vapi_msg_ipfix_exporter_create_delete *msg)
{
  vapi_msg_ipfix_exporter_create_delete_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_exporter_create_delete>()
{
  return ::vapi_msg_id_ipfix_exporter_create_delete; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_exporter_create_delete>>()
{
  return ::vapi_msg_id_ipfix_exporter_create_delete; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_exporter_create_delete()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_exporter_create_delete>(vapi_msg_id_ipfix_exporter_create_delete);
}

template <> inline vapi_msg_ipfix_exporter_create_delete* vapi_alloc<vapi_msg_ipfix_exporter_create_delete>(Connection &con)
{
  vapi_msg_ipfix_exporter_create_delete* result = vapi_alloc_ipfix_exporter_create_delete(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_exporter_create_delete>;

template class Request<vapi_msg_ipfix_exporter_create_delete, vapi_msg_ipfix_exporter_create_delete_reply>;

using Ipfix_exporter_create_delete = Request<vapi_msg_ipfix_exporter_create_delete, vapi_msg_ipfix_exporter_create_delete_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_exporter_create_delete_reply>(vapi_msg_ipfix_exporter_create_delete_reply *msg)
{
  vapi_msg_ipfix_exporter_create_delete_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_exporter_create_delete_reply>(vapi_msg_ipfix_exporter_create_delete_reply *msg)
{
  vapi_msg_ipfix_exporter_create_delete_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_exporter_create_delete_reply>()
{
  return ::vapi_msg_id_ipfix_exporter_create_delete_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_exporter_create_delete_reply>>()
{
  return ::vapi_msg_id_ipfix_exporter_create_delete_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_exporter_create_delete_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_exporter_create_delete_reply>(vapi_msg_id_ipfix_exporter_create_delete_reply);
}

template class Msg<vapi_msg_ipfix_exporter_create_delete_reply>;

using Ipfix_exporter_create_delete_reply = Msg<vapi_msg_ipfix_exporter_create_delete_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_all_exporter_get>(vapi_msg_ipfix_all_exporter_get *msg)
{
  vapi_msg_ipfix_all_exporter_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_all_exporter_get>(vapi_msg_ipfix_all_exporter_get *msg)
{
  vapi_msg_ipfix_all_exporter_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_all_exporter_get>()
{
  return ::vapi_msg_id_ipfix_all_exporter_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_all_exporter_get>>()
{
  return ::vapi_msg_id_ipfix_all_exporter_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_all_exporter_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_all_exporter_get>(vapi_msg_id_ipfix_all_exporter_get);
}

template <> inline vapi_msg_ipfix_all_exporter_get* vapi_alloc<vapi_msg_ipfix_all_exporter_get>(Connection &con)
{
  vapi_msg_ipfix_all_exporter_get* result = vapi_alloc_ipfix_all_exporter_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_all_exporter_get>;

template class Stream<vapi_msg_ipfix_all_exporter_get, vapi_msg_ipfix_all_exporter_get_reply, vapi_msg_ipfix_all_exporter_details>;

using Ipfix_all_exporter_get = Stream<vapi_msg_ipfix_all_exporter_get, vapi_msg_ipfix_all_exporter_get_reply, vapi_msg_ipfix_all_exporter_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_all_exporter_get_reply>(vapi_msg_ipfix_all_exporter_get_reply *msg)
{
  vapi_msg_ipfix_all_exporter_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_all_exporter_get_reply>(vapi_msg_ipfix_all_exporter_get_reply *msg)
{
  vapi_msg_ipfix_all_exporter_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_all_exporter_get_reply>()
{
  return ::vapi_msg_id_ipfix_all_exporter_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_all_exporter_get_reply>>()
{
  return ::vapi_msg_id_ipfix_all_exporter_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_all_exporter_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_all_exporter_get_reply>(vapi_msg_id_ipfix_all_exporter_get_reply);
}

template class Msg<vapi_msg_ipfix_all_exporter_get_reply>;

using Ipfix_all_exporter_get_reply = Msg<vapi_msg_ipfix_all_exporter_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_all_exporter_details>(vapi_msg_ipfix_all_exporter_details *msg)
{
  vapi_msg_ipfix_all_exporter_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_all_exporter_details>(vapi_msg_ipfix_all_exporter_details *msg)
{
  vapi_msg_ipfix_all_exporter_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_all_exporter_details>()
{
  return ::vapi_msg_id_ipfix_all_exporter_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_all_exporter_details>>()
{
  return ::vapi_msg_id_ipfix_all_exporter_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_all_exporter_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_all_exporter_details>(vapi_msg_id_ipfix_all_exporter_details);
}

template class Msg<vapi_msg_ipfix_all_exporter_details>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ipfix_classify_stream>(vapi_msg_set_ipfix_classify_stream *msg)
{
  vapi_msg_set_ipfix_classify_stream_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ipfix_classify_stream>(vapi_msg_set_ipfix_classify_stream *msg)
{
  vapi_msg_set_ipfix_classify_stream_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ipfix_classify_stream>()
{
  return ::vapi_msg_id_set_ipfix_classify_stream; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ipfix_classify_stream>>()
{
  return ::vapi_msg_id_set_ipfix_classify_stream; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ipfix_classify_stream()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ipfix_classify_stream>(vapi_msg_id_set_ipfix_classify_stream);
}

template <> inline vapi_msg_set_ipfix_classify_stream* vapi_alloc<vapi_msg_set_ipfix_classify_stream>(Connection &con)
{
  vapi_msg_set_ipfix_classify_stream* result = vapi_alloc_set_ipfix_classify_stream(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_set_ipfix_classify_stream>;

template class Request<vapi_msg_set_ipfix_classify_stream, vapi_msg_set_ipfix_classify_stream_reply>;

using Set_ipfix_classify_stream = Request<vapi_msg_set_ipfix_classify_stream, vapi_msg_set_ipfix_classify_stream_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_set_ipfix_classify_stream_reply>(vapi_msg_set_ipfix_classify_stream_reply *msg)
{
  vapi_msg_set_ipfix_classify_stream_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_set_ipfix_classify_stream_reply>(vapi_msg_set_ipfix_classify_stream_reply *msg)
{
  vapi_msg_set_ipfix_classify_stream_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_set_ipfix_classify_stream_reply>()
{
  return ::vapi_msg_id_set_ipfix_classify_stream_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_set_ipfix_classify_stream_reply>>()
{
  return ::vapi_msg_id_set_ipfix_classify_stream_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_set_ipfix_classify_stream_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_set_ipfix_classify_stream_reply>(vapi_msg_id_set_ipfix_classify_stream_reply);
}

template class Msg<vapi_msg_set_ipfix_classify_stream_reply>;

using Set_ipfix_classify_stream_reply = Msg<vapi_msg_set_ipfix_classify_stream_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_classify_stream_dump>(vapi_msg_ipfix_classify_stream_dump *msg)
{
  vapi_msg_ipfix_classify_stream_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_classify_stream_dump>(vapi_msg_ipfix_classify_stream_dump *msg)
{
  vapi_msg_ipfix_classify_stream_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_classify_stream_dump>()
{
  return ::vapi_msg_id_ipfix_classify_stream_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_classify_stream_dump>>()
{
  return ::vapi_msg_id_ipfix_classify_stream_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_classify_stream_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_classify_stream_dump>(vapi_msg_id_ipfix_classify_stream_dump);
}

template <> inline vapi_msg_ipfix_classify_stream_dump* vapi_alloc<vapi_msg_ipfix_classify_stream_dump>(Connection &con)
{
  vapi_msg_ipfix_classify_stream_dump* result = vapi_alloc_ipfix_classify_stream_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_classify_stream_dump>;

template class Dump<vapi_msg_ipfix_classify_stream_dump, vapi_msg_ipfix_classify_stream_details>;

using Ipfix_classify_stream_dump = Dump<vapi_msg_ipfix_classify_stream_dump, vapi_msg_ipfix_classify_stream_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_classify_stream_details>(vapi_msg_ipfix_classify_stream_details *msg)
{
  vapi_msg_ipfix_classify_stream_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_classify_stream_details>(vapi_msg_ipfix_classify_stream_details *msg)
{
  vapi_msg_ipfix_classify_stream_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_classify_stream_details>()
{
  return ::vapi_msg_id_ipfix_classify_stream_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_classify_stream_details>>()
{
  return ::vapi_msg_id_ipfix_classify_stream_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_classify_stream_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_classify_stream_details>(vapi_msg_id_ipfix_classify_stream_details);
}

template class Msg<vapi_msg_ipfix_classify_stream_details>;

using Ipfix_classify_stream_details = Msg<vapi_msg_ipfix_classify_stream_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_classify_table_add_del>(vapi_msg_ipfix_classify_table_add_del *msg)
{
  vapi_msg_ipfix_classify_table_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_classify_table_add_del>(vapi_msg_ipfix_classify_table_add_del *msg)
{
  vapi_msg_ipfix_classify_table_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_classify_table_add_del>()
{
  return ::vapi_msg_id_ipfix_classify_table_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_classify_table_add_del>>()
{
  return ::vapi_msg_id_ipfix_classify_table_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_classify_table_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_classify_table_add_del>(vapi_msg_id_ipfix_classify_table_add_del);
}

template <> inline vapi_msg_ipfix_classify_table_add_del* vapi_alloc<vapi_msg_ipfix_classify_table_add_del>(Connection &con)
{
  vapi_msg_ipfix_classify_table_add_del* result = vapi_alloc_ipfix_classify_table_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_classify_table_add_del>;

template class Request<vapi_msg_ipfix_classify_table_add_del, vapi_msg_ipfix_classify_table_add_del_reply>;

using Ipfix_classify_table_add_del = Request<vapi_msg_ipfix_classify_table_add_del, vapi_msg_ipfix_classify_table_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_classify_table_add_del_reply>(vapi_msg_ipfix_classify_table_add_del_reply *msg)
{
  vapi_msg_ipfix_classify_table_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_classify_table_add_del_reply>(vapi_msg_ipfix_classify_table_add_del_reply *msg)
{
  vapi_msg_ipfix_classify_table_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_classify_table_add_del_reply>()
{
  return ::vapi_msg_id_ipfix_classify_table_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_classify_table_add_del_reply>>()
{
  return ::vapi_msg_id_ipfix_classify_table_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_classify_table_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_classify_table_add_del_reply>(vapi_msg_id_ipfix_classify_table_add_del_reply);
}

template class Msg<vapi_msg_ipfix_classify_table_add_del_reply>;

using Ipfix_classify_table_add_del_reply = Msg<vapi_msg_ipfix_classify_table_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_classify_table_dump>(vapi_msg_ipfix_classify_table_dump *msg)
{
  vapi_msg_ipfix_classify_table_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_classify_table_dump>(vapi_msg_ipfix_classify_table_dump *msg)
{
  vapi_msg_ipfix_classify_table_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_classify_table_dump>()
{
  return ::vapi_msg_id_ipfix_classify_table_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_classify_table_dump>>()
{
  return ::vapi_msg_id_ipfix_classify_table_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_classify_table_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_classify_table_dump>(vapi_msg_id_ipfix_classify_table_dump);
}

template <> inline vapi_msg_ipfix_classify_table_dump* vapi_alloc<vapi_msg_ipfix_classify_table_dump>(Connection &con)
{
  vapi_msg_ipfix_classify_table_dump* result = vapi_alloc_ipfix_classify_table_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_classify_table_dump>;

template class Dump<vapi_msg_ipfix_classify_table_dump, vapi_msg_ipfix_classify_table_details>;

using Ipfix_classify_table_dump = Dump<vapi_msg_ipfix_classify_table_dump, vapi_msg_ipfix_classify_table_details>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_classify_table_details>(vapi_msg_ipfix_classify_table_details *msg)
{
  vapi_msg_ipfix_classify_table_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_classify_table_details>(vapi_msg_ipfix_classify_table_details *msg)
{
  vapi_msg_ipfix_classify_table_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_classify_table_details>()
{
  return ::vapi_msg_id_ipfix_classify_table_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_classify_table_details>>()
{
  return ::vapi_msg_id_ipfix_classify_table_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_classify_table_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_classify_table_details>(vapi_msg_id_ipfix_classify_table_details);
}

template class Msg<vapi_msg_ipfix_classify_table_details>;

using Ipfix_classify_table_details = Msg<vapi_msg_ipfix_classify_table_details>;
template <> inline void vapi_swap_to_be<vapi_msg_ipfix_flush>(vapi_msg_ipfix_flush *msg)
{
  vapi_msg_ipfix_flush_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_flush>(vapi_msg_ipfix_flush *msg)
{
  vapi_msg_ipfix_flush_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_flush>()
{
  return ::vapi_msg_id_ipfix_flush; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_flush>>()
{
  return ::vapi_msg_id_ipfix_flush; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_flush()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_flush>(vapi_msg_id_ipfix_flush);
}

template <> inline vapi_msg_ipfix_flush* vapi_alloc<vapi_msg_ipfix_flush>(Connection &con)
{
  vapi_msg_ipfix_flush* result = vapi_alloc_ipfix_flush(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_ipfix_flush>;

template class Request<vapi_msg_ipfix_flush, vapi_msg_ipfix_flush_reply>;

using Ipfix_flush = Request<vapi_msg_ipfix_flush, vapi_msg_ipfix_flush_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_ipfix_flush_reply>(vapi_msg_ipfix_flush_reply *msg)
{
  vapi_msg_ipfix_flush_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_ipfix_flush_reply>(vapi_msg_ipfix_flush_reply *msg)
{
  vapi_msg_ipfix_flush_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_ipfix_flush_reply>()
{
  return ::vapi_msg_id_ipfix_flush_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_ipfix_flush_reply>>()
{
  return ::vapi_msg_id_ipfix_flush_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_ipfix_flush_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_ipfix_flush_reply>(vapi_msg_id_ipfix_flush_reply);
}

template class Msg<vapi_msg_ipfix_flush_reply>;

using Ipfix_flush_reply = Msg<vapi_msg_ipfix_flush_reply>;
}
#endif
