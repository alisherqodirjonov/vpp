#ifndef __included_hpp_classify_api_json
#define __included_hpp_classify_api_json

#include <vapi/vapi.hpp>
#include <vapi/classify.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_classify_add_del_table>(vapi_msg_classify_add_del_table *msg)
{
  vapi_msg_classify_add_del_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_add_del_table>(vapi_msg_classify_add_del_table *msg)
{
  vapi_msg_classify_add_del_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_add_del_table>()
{
  return ::vapi_msg_id_classify_add_del_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_add_del_table>>()
{
  return ::vapi_msg_id_classify_add_del_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_add_del_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_add_del_table>(vapi_msg_id_classify_add_del_table);
}

template <> inline vapi_msg_classify_add_del_table* vapi_alloc<vapi_msg_classify_add_del_table, size_t>(Connection &con, size_t _mask_array_size)
{
  vapi_msg_classify_add_del_table* result = vapi_alloc_classify_add_del_table(con.vapi_ctx, _mask_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_add_del_table>;

template class Request<vapi_msg_classify_add_del_table, vapi_msg_classify_add_del_table_reply, size_t>;

using Classify_add_del_table = Request<vapi_msg_classify_add_del_table, vapi_msg_classify_add_del_table_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_add_del_table_reply>(vapi_msg_classify_add_del_table_reply *msg)
{
  vapi_msg_classify_add_del_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_add_del_table_reply>(vapi_msg_classify_add_del_table_reply *msg)
{
  vapi_msg_classify_add_del_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_add_del_table_reply>()
{
  return ::vapi_msg_id_classify_add_del_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_add_del_table_reply>>()
{
  return ::vapi_msg_id_classify_add_del_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_add_del_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_add_del_table_reply>(vapi_msg_id_classify_add_del_table_reply);
}

template class Msg<vapi_msg_classify_add_del_table_reply>;

using Classify_add_del_table_reply = Msg<vapi_msg_classify_add_del_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_add_del_session>(vapi_msg_classify_add_del_session *msg)
{
  vapi_msg_classify_add_del_session_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_add_del_session>(vapi_msg_classify_add_del_session *msg)
{
  vapi_msg_classify_add_del_session_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_add_del_session>()
{
  return ::vapi_msg_id_classify_add_del_session; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_add_del_session>>()
{
  return ::vapi_msg_id_classify_add_del_session; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_add_del_session()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_add_del_session>(vapi_msg_id_classify_add_del_session);
}

template <> inline vapi_msg_classify_add_del_session* vapi_alloc<vapi_msg_classify_add_del_session, size_t>(Connection &con, size_t _match_array_size)
{
  vapi_msg_classify_add_del_session* result = vapi_alloc_classify_add_del_session(con.vapi_ctx, _match_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_add_del_session>;

template class Request<vapi_msg_classify_add_del_session, vapi_msg_classify_add_del_session_reply, size_t>;

using Classify_add_del_session = Request<vapi_msg_classify_add_del_session, vapi_msg_classify_add_del_session_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_add_del_session_reply>(vapi_msg_classify_add_del_session_reply *msg)
{
  vapi_msg_classify_add_del_session_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_add_del_session_reply>(vapi_msg_classify_add_del_session_reply *msg)
{
  vapi_msg_classify_add_del_session_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_add_del_session_reply>()
{
  return ::vapi_msg_id_classify_add_del_session_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_add_del_session_reply>>()
{
  return ::vapi_msg_id_classify_add_del_session_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_add_del_session_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_add_del_session_reply>(vapi_msg_id_classify_add_del_session_reply);
}

template class Msg<vapi_msg_classify_add_del_session_reply>;

using Classify_add_del_session_reply = Msg<vapi_msg_classify_add_del_session_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_classify_set_interface>(vapi_msg_policer_classify_set_interface *msg)
{
  vapi_msg_policer_classify_set_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_classify_set_interface>(vapi_msg_policer_classify_set_interface *msg)
{
  vapi_msg_policer_classify_set_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_classify_set_interface>()
{
  return ::vapi_msg_id_policer_classify_set_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_classify_set_interface>>()
{
  return ::vapi_msg_id_policer_classify_set_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_classify_set_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_classify_set_interface>(vapi_msg_id_policer_classify_set_interface);
}

template <> inline vapi_msg_policer_classify_set_interface* vapi_alloc<vapi_msg_policer_classify_set_interface>(Connection &con)
{
  vapi_msg_policer_classify_set_interface* result = vapi_alloc_policer_classify_set_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_classify_set_interface>;

template class Request<vapi_msg_policer_classify_set_interface, vapi_msg_policer_classify_set_interface_reply>;

using Policer_classify_set_interface = Request<vapi_msg_policer_classify_set_interface, vapi_msg_policer_classify_set_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_classify_set_interface_reply>(vapi_msg_policer_classify_set_interface_reply *msg)
{
  vapi_msg_policer_classify_set_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_classify_set_interface_reply>(vapi_msg_policer_classify_set_interface_reply *msg)
{
  vapi_msg_policer_classify_set_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_classify_set_interface_reply>()
{
  return ::vapi_msg_id_policer_classify_set_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_classify_set_interface_reply>>()
{
  return ::vapi_msg_id_policer_classify_set_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_classify_set_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_classify_set_interface_reply>(vapi_msg_id_policer_classify_set_interface_reply);
}

template class Msg<vapi_msg_policer_classify_set_interface_reply>;

using Policer_classify_set_interface_reply = Msg<vapi_msg_policer_classify_set_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_policer_classify_dump>(vapi_msg_policer_classify_dump *msg)
{
  vapi_msg_policer_classify_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_classify_dump>(vapi_msg_policer_classify_dump *msg)
{
  vapi_msg_policer_classify_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_classify_dump>()
{
  return ::vapi_msg_id_policer_classify_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_classify_dump>>()
{
  return ::vapi_msg_id_policer_classify_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_classify_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_classify_dump>(vapi_msg_id_policer_classify_dump);
}

template <> inline vapi_msg_policer_classify_dump* vapi_alloc<vapi_msg_policer_classify_dump>(Connection &con)
{
  vapi_msg_policer_classify_dump* result = vapi_alloc_policer_classify_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_policer_classify_dump>;

template class Dump<vapi_msg_policer_classify_dump, vapi_msg_policer_classify_details>;

using Policer_classify_dump = Dump<vapi_msg_policer_classify_dump, vapi_msg_policer_classify_details>;

template <> inline void vapi_swap_to_be<vapi_msg_policer_classify_details>(vapi_msg_policer_classify_details *msg)
{
  vapi_msg_policer_classify_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_policer_classify_details>(vapi_msg_policer_classify_details *msg)
{
  vapi_msg_policer_classify_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_policer_classify_details>()
{
  return ::vapi_msg_id_policer_classify_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_policer_classify_details>>()
{
  return ::vapi_msg_id_policer_classify_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_policer_classify_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_policer_classify_details>(vapi_msg_id_policer_classify_details);
}

template class Msg<vapi_msg_policer_classify_details>;

using Policer_classify_details = Msg<vapi_msg_policer_classify_details>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_table_ids>(vapi_msg_classify_table_ids *msg)
{
  vapi_msg_classify_table_ids_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_table_ids>(vapi_msg_classify_table_ids *msg)
{
  vapi_msg_classify_table_ids_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_table_ids>()
{
  return ::vapi_msg_id_classify_table_ids; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_table_ids>>()
{
  return ::vapi_msg_id_classify_table_ids; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_table_ids()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_table_ids>(vapi_msg_id_classify_table_ids);
}

template <> inline vapi_msg_classify_table_ids* vapi_alloc<vapi_msg_classify_table_ids>(Connection &con)
{
  vapi_msg_classify_table_ids* result = vapi_alloc_classify_table_ids(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_table_ids>;

template class Request<vapi_msg_classify_table_ids, vapi_msg_classify_table_ids_reply>;

using Classify_table_ids = Request<vapi_msg_classify_table_ids, vapi_msg_classify_table_ids_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_table_ids_reply>(vapi_msg_classify_table_ids_reply *msg)
{
  vapi_msg_classify_table_ids_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_table_ids_reply>(vapi_msg_classify_table_ids_reply *msg)
{
  vapi_msg_classify_table_ids_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_table_ids_reply>()
{
  return ::vapi_msg_id_classify_table_ids_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_table_ids_reply>>()
{
  return ::vapi_msg_id_classify_table_ids_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_table_ids_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_table_ids_reply>(vapi_msg_id_classify_table_ids_reply);
}

template class Msg<vapi_msg_classify_table_ids_reply>;

using Classify_table_ids_reply = Msg<vapi_msg_classify_table_ids_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_table_by_interface>(vapi_msg_classify_table_by_interface *msg)
{
  vapi_msg_classify_table_by_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_table_by_interface>(vapi_msg_classify_table_by_interface *msg)
{
  vapi_msg_classify_table_by_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_table_by_interface>()
{
  return ::vapi_msg_id_classify_table_by_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_table_by_interface>>()
{
  return ::vapi_msg_id_classify_table_by_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_table_by_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_table_by_interface>(vapi_msg_id_classify_table_by_interface);
}

template <> inline vapi_msg_classify_table_by_interface* vapi_alloc<vapi_msg_classify_table_by_interface>(Connection &con)
{
  vapi_msg_classify_table_by_interface* result = vapi_alloc_classify_table_by_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_table_by_interface>;

template class Request<vapi_msg_classify_table_by_interface, vapi_msg_classify_table_by_interface_reply>;

using Classify_table_by_interface = Request<vapi_msg_classify_table_by_interface, vapi_msg_classify_table_by_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_table_by_interface_reply>(vapi_msg_classify_table_by_interface_reply *msg)
{
  vapi_msg_classify_table_by_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_table_by_interface_reply>(vapi_msg_classify_table_by_interface_reply *msg)
{
  vapi_msg_classify_table_by_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_table_by_interface_reply>()
{
  return ::vapi_msg_id_classify_table_by_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_table_by_interface_reply>>()
{
  return ::vapi_msg_id_classify_table_by_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_table_by_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_table_by_interface_reply>(vapi_msg_id_classify_table_by_interface_reply);
}

template class Msg<vapi_msg_classify_table_by_interface_reply>;

using Classify_table_by_interface_reply = Msg<vapi_msg_classify_table_by_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_table_info>(vapi_msg_classify_table_info *msg)
{
  vapi_msg_classify_table_info_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_table_info>(vapi_msg_classify_table_info *msg)
{
  vapi_msg_classify_table_info_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_table_info>()
{
  return ::vapi_msg_id_classify_table_info; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_table_info>>()
{
  return ::vapi_msg_id_classify_table_info; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_table_info()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_table_info>(vapi_msg_id_classify_table_info);
}

template <> inline vapi_msg_classify_table_info* vapi_alloc<vapi_msg_classify_table_info>(Connection &con)
{
  vapi_msg_classify_table_info* result = vapi_alloc_classify_table_info(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_table_info>;

template class Request<vapi_msg_classify_table_info, vapi_msg_classify_table_info_reply>;

using Classify_table_info = Request<vapi_msg_classify_table_info, vapi_msg_classify_table_info_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_table_info_reply>(vapi_msg_classify_table_info_reply *msg)
{
  vapi_msg_classify_table_info_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_table_info_reply>(vapi_msg_classify_table_info_reply *msg)
{
  vapi_msg_classify_table_info_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_table_info_reply>()
{
  return ::vapi_msg_id_classify_table_info_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_table_info_reply>>()
{
  return ::vapi_msg_id_classify_table_info_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_table_info_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_table_info_reply>(vapi_msg_id_classify_table_info_reply);
}

template class Msg<vapi_msg_classify_table_info_reply>;

using Classify_table_info_reply = Msg<vapi_msg_classify_table_info_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_session_dump>(vapi_msg_classify_session_dump *msg)
{
  vapi_msg_classify_session_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_session_dump>(vapi_msg_classify_session_dump *msg)
{
  vapi_msg_classify_session_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_session_dump>()
{
  return ::vapi_msg_id_classify_session_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_session_dump>>()
{
  return ::vapi_msg_id_classify_session_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_session_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_session_dump>(vapi_msg_id_classify_session_dump);
}

template <> inline vapi_msg_classify_session_dump* vapi_alloc<vapi_msg_classify_session_dump>(Connection &con)
{
  vapi_msg_classify_session_dump* result = vapi_alloc_classify_session_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_session_dump>;

template class Dump<vapi_msg_classify_session_dump, vapi_msg_classify_session_details>;

using Classify_session_dump = Dump<vapi_msg_classify_session_dump, vapi_msg_classify_session_details>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_session_details>(vapi_msg_classify_session_details *msg)
{
  vapi_msg_classify_session_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_session_details>(vapi_msg_classify_session_details *msg)
{
  vapi_msg_classify_session_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_session_details>()
{
  return ::vapi_msg_id_classify_session_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_session_details>>()
{
  return ::vapi_msg_id_classify_session_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_session_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_session_details>(vapi_msg_id_classify_session_details);
}

template class Msg<vapi_msg_classify_session_details>;

using Classify_session_details = Msg<vapi_msg_classify_session_details>;
template <> inline void vapi_swap_to_be<vapi_msg_flow_classify_set_interface>(vapi_msg_flow_classify_set_interface *msg)
{
  vapi_msg_flow_classify_set_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_classify_set_interface>(vapi_msg_flow_classify_set_interface *msg)
{
  vapi_msg_flow_classify_set_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_classify_set_interface>()
{
  return ::vapi_msg_id_flow_classify_set_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_classify_set_interface>>()
{
  return ::vapi_msg_id_flow_classify_set_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_classify_set_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_classify_set_interface>(vapi_msg_id_flow_classify_set_interface);
}

template <> inline vapi_msg_flow_classify_set_interface* vapi_alloc<vapi_msg_flow_classify_set_interface>(Connection &con)
{
  vapi_msg_flow_classify_set_interface* result = vapi_alloc_flow_classify_set_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_classify_set_interface>;

template class Request<vapi_msg_flow_classify_set_interface, vapi_msg_flow_classify_set_interface_reply>;

using Flow_classify_set_interface = Request<vapi_msg_flow_classify_set_interface, vapi_msg_flow_classify_set_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_classify_set_interface_reply>(vapi_msg_flow_classify_set_interface_reply *msg)
{
  vapi_msg_flow_classify_set_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_classify_set_interface_reply>(vapi_msg_flow_classify_set_interface_reply *msg)
{
  vapi_msg_flow_classify_set_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_classify_set_interface_reply>()
{
  return ::vapi_msg_id_flow_classify_set_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_classify_set_interface_reply>>()
{
  return ::vapi_msg_id_flow_classify_set_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_classify_set_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_classify_set_interface_reply>(vapi_msg_id_flow_classify_set_interface_reply);
}

template class Msg<vapi_msg_flow_classify_set_interface_reply>;

using Flow_classify_set_interface_reply = Msg<vapi_msg_flow_classify_set_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_flow_classify_dump>(vapi_msg_flow_classify_dump *msg)
{
  vapi_msg_flow_classify_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_classify_dump>(vapi_msg_flow_classify_dump *msg)
{
  vapi_msg_flow_classify_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_classify_dump>()
{
  return ::vapi_msg_id_flow_classify_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_classify_dump>>()
{
  return ::vapi_msg_id_flow_classify_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_classify_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_classify_dump>(vapi_msg_id_flow_classify_dump);
}

template <> inline vapi_msg_flow_classify_dump* vapi_alloc<vapi_msg_flow_classify_dump>(Connection &con)
{
  vapi_msg_flow_classify_dump* result = vapi_alloc_flow_classify_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_flow_classify_dump>;

template class Dump<vapi_msg_flow_classify_dump, vapi_msg_flow_classify_details>;

using Flow_classify_dump = Dump<vapi_msg_flow_classify_dump, vapi_msg_flow_classify_details>;

template <> inline void vapi_swap_to_be<vapi_msg_flow_classify_details>(vapi_msg_flow_classify_details *msg)
{
  vapi_msg_flow_classify_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_flow_classify_details>(vapi_msg_flow_classify_details *msg)
{
  vapi_msg_flow_classify_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_flow_classify_details>()
{
  return ::vapi_msg_id_flow_classify_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_flow_classify_details>>()
{
  return ::vapi_msg_id_flow_classify_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_flow_classify_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_flow_classify_details>(vapi_msg_id_flow_classify_details);
}

template class Msg<vapi_msg_flow_classify_details>;

using Flow_classify_details = Msg<vapi_msg_flow_classify_details>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_set_interface_ip_table>(vapi_msg_classify_set_interface_ip_table *msg)
{
  vapi_msg_classify_set_interface_ip_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_set_interface_ip_table>(vapi_msg_classify_set_interface_ip_table *msg)
{
  vapi_msg_classify_set_interface_ip_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_set_interface_ip_table>()
{
  return ::vapi_msg_id_classify_set_interface_ip_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_set_interface_ip_table>>()
{
  return ::vapi_msg_id_classify_set_interface_ip_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_set_interface_ip_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_set_interface_ip_table>(vapi_msg_id_classify_set_interface_ip_table);
}

template <> inline vapi_msg_classify_set_interface_ip_table* vapi_alloc<vapi_msg_classify_set_interface_ip_table>(Connection &con)
{
  vapi_msg_classify_set_interface_ip_table* result = vapi_alloc_classify_set_interface_ip_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_set_interface_ip_table>;

template class Request<vapi_msg_classify_set_interface_ip_table, vapi_msg_classify_set_interface_ip_table_reply>;

using Classify_set_interface_ip_table = Request<vapi_msg_classify_set_interface_ip_table, vapi_msg_classify_set_interface_ip_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_set_interface_ip_table_reply>(vapi_msg_classify_set_interface_ip_table_reply *msg)
{
  vapi_msg_classify_set_interface_ip_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_set_interface_ip_table_reply>(vapi_msg_classify_set_interface_ip_table_reply *msg)
{
  vapi_msg_classify_set_interface_ip_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_set_interface_ip_table_reply>()
{
  return ::vapi_msg_id_classify_set_interface_ip_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_set_interface_ip_table_reply>>()
{
  return ::vapi_msg_id_classify_set_interface_ip_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_set_interface_ip_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_set_interface_ip_table_reply>(vapi_msg_id_classify_set_interface_ip_table_reply);
}

template class Msg<vapi_msg_classify_set_interface_ip_table_reply>;

using Classify_set_interface_ip_table_reply = Msg<vapi_msg_classify_set_interface_ip_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_set_interface_l2_tables>(vapi_msg_classify_set_interface_l2_tables *msg)
{
  vapi_msg_classify_set_interface_l2_tables_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_set_interface_l2_tables>(vapi_msg_classify_set_interface_l2_tables *msg)
{
  vapi_msg_classify_set_interface_l2_tables_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_set_interface_l2_tables>()
{
  return ::vapi_msg_id_classify_set_interface_l2_tables; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_set_interface_l2_tables>>()
{
  return ::vapi_msg_id_classify_set_interface_l2_tables; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_set_interface_l2_tables()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_set_interface_l2_tables>(vapi_msg_id_classify_set_interface_l2_tables);
}

template <> inline vapi_msg_classify_set_interface_l2_tables* vapi_alloc<vapi_msg_classify_set_interface_l2_tables>(Connection &con)
{
  vapi_msg_classify_set_interface_l2_tables* result = vapi_alloc_classify_set_interface_l2_tables(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_set_interface_l2_tables>;

template class Request<vapi_msg_classify_set_interface_l2_tables, vapi_msg_classify_set_interface_l2_tables_reply>;

using Classify_set_interface_l2_tables = Request<vapi_msg_classify_set_interface_l2_tables, vapi_msg_classify_set_interface_l2_tables_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_set_interface_l2_tables_reply>(vapi_msg_classify_set_interface_l2_tables_reply *msg)
{
  vapi_msg_classify_set_interface_l2_tables_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_set_interface_l2_tables_reply>(vapi_msg_classify_set_interface_l2_tables_reply *msg)
{
  vapi_msg_classify_set_interface_l2_tables_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_set_interface_l2_tables_reply>()
{
  return ::vapi_msg_id_classify_set_interface_l2_tables_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_set_interface_l2_tables_reply>>()
{
  return ::vapi_msg_id_classify_set_interface_l2_tables_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_set_interface_l2_tables_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_set_interface_l2_tables_reply>(vapi_msg_id_classify_set_interface_l2_tables_reply);
}

template class Msg<vapi_msg_classify_set_interface_l2_tables_reply>;

using Classify_set_interface_l2_tables_reply = Msg<vapi_msg_classify_set_interface_l2_tables_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_input_acl_set_interface>(vapi_msg_input_acl_set_interface *msg)
{
  vapi_msg_input_acl_set_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_input_acl_set_interface>(vapi_msg_input_acl_set_interface *msg)
{
  vapi_msg_input_acl_set_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_input_acl_set_interface>()
{
  return ::vapi_msg_id_input_acl_set_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_input_acl_set_interface>>()
{
  return ::vapi_msg_id_input_acl_set_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_input_acl_set_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_input_acl_set_interface>(vapi_msg_id_input_acl_set_interface);
}

template <> inline vapi_msg_input_acl_set_interface* vapi_alloc<vapi_msg_input_acl_set_interface>(Connection &con)
{
  vapi_msg_input_acl_set_interface* result = vapi_alloc_input_acl_set_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_input_acl_set_interface>;

template class Request<vapi_msg_input_acl_set_interface, vapi_msg_input_acl_set_interface_reply>;

using Input_acl_set_interface = Request<vapi_msg_input_acl_set_interface, vapi_msg_input_acl_set_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_input_acl_set_interface_reply>(vapi_msg_input_acl_set_interface_reply *msg)
{
  vapi_msg_input_acl_set_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_input_acl_set_interface_reply>(vapi_msg_input_acl_set_interface_reply *msg)
{
  vapi_msg_input_acl_set_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_input_acl_set_interface_reply>()
{
  return ::vapi_msg_id_input_acl_set_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_input_acl_set_interface_reply>>()
{
  return ::vapi_msg_id_input_acl_set_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_input_acl_set_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_input_acl_set_interface_reply>(vapi_msg_id_input_acl_set_interface_reply);
}

template class Msg<vapi_msg_input_acl_set_interface_reply>;

using Input_acl_set_interface_reply = Msg<vapi_msg_input_acl_set_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_punt_acl_add_del>(vapi_msg_punt_acl_add_del *msg)
{
  vapi_msg_punt_acl_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_acl_add_del>(vapi_msg_punt_acl_add_del *msg)
{
  vapi_msg_punt_acl_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_acl_add_del>()
{
  return ::vapi_msg_id_punt_acl_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_acl_add_del>>()
{
  return ::vapi_msg_id_punt_acl_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_acl_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_acl_add_del>(vapi_msg_id_punt_acl_add_del);
}

template <> inline vapi_msg_punt_acl_add_del* vapi_alloc<vapi_msg_punt_acl_add_del>(Connection &con)
{
  vapi_msg_punt_acl_add_del* result = vapi_alloc_punt_acl_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_punt_acl_add_del>;

template class Request<vapi_msg_punt_acl_add_del, vapi_msg_punt_acl_add_del_reply>;

using Punt_acl_add_del = Request<vapi_msg_punt_acl_add_del, vapi_msg_punt_acl_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_punt_acl_add_del_reply>(vapi_msg_punt_acl_add_del_reply *msg)
{
  vapi_msg_punt_acl_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_acl_add_del_reply>(vapi_msg_punt_acl_add_del_reply *msg)
{
  vapi_msg_punt_acl_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_acl_add_del_reply>()
{
  return ::vapi_msg_id_punt_acl_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_acl_add_del_reply>>()
{
  return ::vapi_msg_id_punt_acl_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_acl_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_acl_add_del_reply>(vapi_msg_id_punt_acl_add_del_reply);
}

template class Msg<vapi_msg_punt_acl_add_del_reply>;

using Punt_acl_add_del_reply = Msg<vapi_msg_punt_acl_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_punt_acl_get>(vapi_msg_punt_acl_get *msg)
{
  vapi_msg_punt_acl_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_acl_get>(vapi_msg_punt_acl_get *msg)
{
  vapi_msg_punt_acl_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_acl_get>()
{
  return ::vapi_msg_id_punt_acl_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_acl_get>>()
{
  return ::vapi_msg_id_punt_acl_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_acl_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_acl_get>(vapi_msg_id_punt_acl_get);
}

template <> inline vapi_msg_punt_acl_get* vapi_alloc<vapi_msg_punt_acl_get>(Connection &con)
{
  vapi_msg_punt_acl_get* result = vapi_alloc_punt_acl_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_punt_acl_get>;

template class Request<vapi_msg_punt_acl_get, vapi_msg_punt_acl_get_reply>;

using Punt_acl_get = Request<vapi_msg_punt_acl_get, vapi_msg_punt_acl_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_punt_acl_get_reply>(vapi_msg_punt_acl_get_reply *msg)
{
  vapi_msg_punt_acl_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_punt_acl_get_reply>(vapi_msg_punt_acl_get_reply *msg)
{
  vapi_msg_punt_acl_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_punt_acl_get_reply>()
{
  return ::vapi_msg_id_punt_acl_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_punt_acl_get_reply>>()
{
  return ::vapi_msg_id_punt_acl_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_punt_acl_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_punt_acl_get_reply>(vapi_msg_id_punt_acl_get_reply);
}

template class Msg<vapi_msg_punt_acl_get_reply>;

using Punt_acl_get_reply = Msg<vapi_msg_punt_acl_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_output_acl_set_interface>(vapi_msg_output_acl_set_interface *msg)
{
  vapi_msg_output_acl_set_interface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_output_acl_set_interface>(vapi_msg_output_acl_set_interface *msg)
{
  vapi_msg_output_acl_set_interface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_output_acl_set_interface>()
{
  return ::vapi_msg_id_output_acl_set_interface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_output_acl_set_interface>>()
{
  return ::vapi_msg_id_output_acl_set_interface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_output_acl_set_interface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_output_acl_set_interface>(vapi_msg_id_output_acl_set_interface);
}

template <> inline vapi_msg_output_acl_set_interface* vapi_alloc<vapi_msg_output_acl_set_interface>(Connection &con)
{
  vapi_msg_output_acl_set_interface* result = vapi_alloc_output_acl_set_interface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_output_acl_set_interface>;

template class Request<vapi_msg_output_acl_set_interface, vapi_msg_output_acl_set_interface_reply>;

using Output_acl_set_interface = Request<vapi_msg_output_acl_set_interface, vapi_msg_output_acl_set_interface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_output_acl_set_interface_reply>(vapi_msg_output_acl_set_interface_reply *msg)
{
  vapi_msg_output_acl_set_interface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_output_acl_set_interface_reply>(vapi_msg_output_acl_set_interface_reply *msg)
{
  vapi_msg_output_acl_set_interface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_output_acl_set_interface_reply>()
{
  return ::vapi_msg_id_output_acl_set_interface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_output_acl_set_interface_reply>>()
{
  return ::vapi_msg_id_output_acl_set_interface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_output_acl_set_interface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_output_acl_set_interface_reply>(vapi_msg_id_output_acl_set_interface_reply);
}

template class Msg<vapi_msg_output_acl_set_interface_reply>;

using Output_acl_set_interface_reply = Msg<vapi_msg_output_acl_set_interface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_pcap_lookup_table>(vapi_msg_classify_pcap_lookup_table *msg)
{
  vapi_msg_classify_pcap_lookup_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_pcap_lookup_table>(vapi_msg_classify_pcap_lookup_table *msg)
{
  vapi_msg_classify_pcap_lookup_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_pcap_lookup_table>()
{
  return ::vapi_msg_id_classify_pcap_lookup_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_pcap_lookup_table>>()
{
  return ::vapi_msg_id_classify_pcap_lookup_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_pcap_lookup_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_pcap_lookup_table>(vapi_msg_id_classify_pcap_lookup_table);
}

template <> inline vapi_msg_classify_pcap_lookup_table* vapi_alloc<vapi_msg_classify_pcap_lookup_table, size_t>(Connection &con, size_t _mask_array_size)
{
  vapi_msg_classify_pcap_lookup_table* result = vapi_alloc_classify_pcap_lookup_table(con.vapi_ctx, _mask_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_pcap_lookup_table>;

template class Request<vapi_msg_classify_pcap_lookup_table, vapi_msg_classify_pcap_lookup_table_reply, size_t>;

using Classify_pcap_lookup_table = Request<vapi_msg_classify_pcap_lookup_table, vapi_msg_classify_pcap_lookup_table_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_pcap_lookup_table_reply>(vapi_msg_classify_pcap_lookup_table_reply *msg)
{
  vapi_msg_classify_pcap_lookup_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_pcap_lookup_table_reply>(vapi_msg_classify_pcap_lookup_table_reply *msg)
{
  vapi_msg_classify_pcap_lookup_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_pcap_lookup_table_reply>()
{
  return ::vapi_msg_id_classify_pcap_lookup_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_pcap_lookup_table_reply>>()
{
  return ::vapi_msg_id_classify_pcap_lookup_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_pcap_lookup_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_pcap_lookup_table_reply>(vapi_msg_id_classify_pcap_lookup_table_reply);
}

template class Msg<vapi_msg_classify_pcap_lookup_table_reply>;

using Classify_pcap_lookup_table_reply = Msg<vapi_msg_classify_pcap_lookup_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_pcap_set_table>(vapi_msg_classify_pcap_set_table *msg)
{
  vapi_msg_classify_pcap_set_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_pcap_set_table>(vapi_msg_classify_pcap_set_table *msg)
{
  vapi_msg_classify_pcap_set_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_pcap_set_table>()
{
  return ::vapi_msg_id_classify_pcap_set_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_pcap_set_table>>()
{
  return ::vapi_msg_id_classify_pcap_set_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_pcap_set_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_pcap_set_table>(vapi_msg_id_classify_pcap_set_table);
}

template <> inline vapi_msg_classify_pcap_set_table* vapi_alloc<vapi_msg_classify_pcap_set_table>(Connection &con)
{
  vapi_msg_classify_pcap_set_table* result = vapi_alloc_classify_pcap_set_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_pcap_set_table>;

template class Request<vapi_msg_classify_pcap_set_table, vapi_msg_classify_pcap_set_table_reply>;

using Classify_pcap_set_table = Request<vapi_msg_classify_pcap_set_table, vapi_msg_classify_pcap_set_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_pcap_set_table_reply>(vapi_msg_classify_pcap_set_table_reply *msg)
{
  vapi_msg_classify_pcap_set_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_pcap_set_table_reply>(vapi_msg_classify_pcap_set_table_reply *msg)
{
  vapi_msg_classify_pcap_set_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_pcap_set_table_reply>()
{
  return ::vapi_msg_id_classify_pcap_set_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_pcap_set_table_reply>>()
{
  return ::vapi_msg_id_classify_pcap_set_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_pcap_set_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_pcap_set_table_reply>(vapi_msg_id_classify_pcap_set_table_reply);
}

template class Msg<vapi_msg_classify_pcap_set_table_reply>;

using Classify_pcap_set_table_reply = Msg<vapi_msg_classify_pcap_set_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_pcap_get_tables>(vapi_msg_classify_pcap_get_tables *msg)
{
  vapi_msg_classify_pcap_get_tables_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_pcap_get_tables>(vapi_msg_classify_pcap_get_tables *msg)
{
  vapi_msg_classify_pcap_get_tables_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_pcap_get_tables>()
{
  return ::vapi_msg_id_classify_pcap_get_tables; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_pcap_get_tables>>()
{
  return ::vapi_msg_id_classify_pcap_get_tables; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_pcap_get_tables()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_pcap_get_tables>(vapi_msg_id_classify_pcap_get_tables);
}

template <> inline vapi_msg_classify_pcap_get_tables* vapi_alloc<vapi_msg_classify_pcap_get_tables>(Connection &con)
{
  vapi_msg_classify_pcap_get_tables* result = vapi_alloc_classify_pcap_get_tables(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_pcap_get_tables>;

template class Request<vapi_msg_classify_pcap_get_tables, vapi_msg_classify_pcap_get_tables_reply>;

using Classify_pcap_get_tables = Request<vapi_msg_classify_pcap_get_tables, vapi_msg_classify_pcap_get_tables_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_pcap_get_tables_reply>(vapi_msg_classify_pcap_get_tables_reply *msg)
{
  vapi_msg_classify_pcap_get_tables_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_pcap_get_tables_reply>(vapi_msg_classify_pcap_get_tables_reply *msg)
{
  vapi_msg_classify_pcap_get_tables_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_pcap_get_tables_reply>()
{
  return ::vapi_msg_id_classify_pcap_get_tables_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_pcap_get_tables_reply>>()
{
  return ::vapi_msg_id_classify_pcap_get_tables_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_pcap_get_tables_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_pcap_get_tables_reply>(vapi_msg_id_classify_pcap_get_tables_reply);
}

template class Msg<vapi_msg_classify_pcap_get_tables_reply>;

using Classify_pcap_get_tables_reply = Msg<vapi_msg_classify_pcap_get_tables_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_trace_lookup_table>(vapi_msg_classify_trace_lookup_table *msg)
{
  vapi_msg_classify_trace_lookup_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_trace_lookup_table>(vapi_msg_classify_trace_lookup_table *msg)
{
  vapi_msg_classify_trace_lookup_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_trace_lookup_table>()
{
  return ::vapi_msg_id_classify_trace_lookup_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_trace_lookup_table>>()
{
  return ::vapi_msg_id_classify_trace_lookup_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_trace_lookup_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_trace_lookup_table>(vapi_msg_id_classify_trace_lookup_table);
}

template <> inline vapi_msg_classify_trace_lookup_table* vapi_alloc<vapi_msg_classify_trace_lookup_table, size_t>(Connection &con, size_t _mask_array_size)
{
  vapi_msg_classify_trace_lookup_table* result = vapi_alloc_classify_trace_lookup_table(con.vapi_ctx, _mask_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_trace_lookup_table>;

template class Request<vapi_msg_classify_trace_lookup_table, vapi_msg_classify_trace_lookup_table_reply, size_t>;

using Classify_trace_lookup_table = Request<vapi_msg_classify_trace_lookup_table, vapi_msg_classify_trace_lookup_table_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_trace_lookup_table_reply>(vapi_msg_classify_trace_lookup_table_reply *msg)
{
  vapi_msg_classify_trace_lookup_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_trace_lookup_table_reply>(vapi_msg_classify_trace_lookup_table_reply *msg)
{
  vapi_msg_classify_trace_lookup_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_trace_lookup_table_reply>()
{
  return ::vapi_msg_id_classify_trace_lookup_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_trace_lookup_table_reply>>()
{
  return ::vapi_msg_id_classify_trace_lookup_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_trace_lookup_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_trace_lookup_table_reply>(vapi_msg_id_classify_trace_lookup_table_reply);
}

template class Msg<vapi_msg_classify_trace_lookup_table_reply>;

using Classify_trace_lookup_table_reply = Msg<vapi_msg_classify_trace_lookup_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_trace_set_table>(vapi_msg_classify_trace_set_table *msg)
{
  vapi_msg_classify_trace_set_table_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_trace_set_table>(vapi_msg_classify_trace_set_table *msg)
{
  vapi_msg_classify_trace_set_table_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_trace_set_table>()
{
  return ::vapi_msg_id_classify_trace_set_table; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_trace_set_table>>()
{
  return ::vapi_msg_id_classify_trace_set_table; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_trace_set_table()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_trace_set_table>(vapi_msg_id_classify_trace_set_table);
}

template <> inline vapi_msg_classify_trace_set_table* vapi_alloc<vapi_msg_classify_trace_set_table>(Connection &con)
{
  vapi_msg_classify_trace_set_table* result = vapi_alloc_classify_trace_set_table(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_trace_set_table>;

template class Request<vapi_msg_classify_trace_set_table, vapi_msg_classify_trace_set_table_reply>;

using Classify_trace_set_table = Request<vapi_msg_classify_trace_set_table, vapi_msg_classify_trace_set_table_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_trace_set_table_reply>(vapi_msg_classify_trace_set_table_reply *msg)
{
  vapi_msg_classify_trace_set_table_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_trace_set_table_reply>(vapi_msg_classify_trace_set_table_reply *msg)
{
  vapi_msg_classify_trace_set_table_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_trace_set_table_reply>()
{
  return ::vapi_msg_id_classify_trace_set_table_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_trace_set_table_reply>>()
{
  return ::vapi_msg_id_classify_trace_set_table_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_trace_set_table_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_trace_set_table_reply>(vapi_msg_id_classify_trace_set_table_reply);
}

template class Msg<vapi_msg_classify_trace_set_table_reply>;

using Classify_trace_set_table_reply = Msg<vapi_msg_classify_trace_set_table_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_classify_trace_get_tables>(vapi_msg_classify_trace_get_tables *msg)
{
  vapi_msg_classify_trace_get_tables_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_trace_get_tables>(vapi_msg_classify_trace_get_tables *msg)
{
  vapi_msg_classify_trace_get_tables_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_trace_get_tables>()
{
  return ::vapi_msg_id_classify_trace_get_tables; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_trace_get_tables>>()
{
  return ::vapi_msg_id_classify_trace_get_tables; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_trace_get_tables()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_trace_get_tables>(vapi_msg_id_classify_trace_get_tables);
}

template <> inline vapi_msg_classify_trace_get_tables* vapi_alloc<vapi_msg_classify_trace_get_tables>(Connection &con)
{
  vapi_msg_classify_trace_get_tables* result = vapi_alloc_classify_trace_get_tables(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_classify_trace_get_tables>;

template class Request<vapi_msg_classify_trace_get_tables, vapi_msg_classify_trace_get_tables_reply>;

using Classify_trace_get_tables = Request<vapi_msg_classify_trace_get_tables, vapi_msg_classify_trace_get_tables_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_classify_trace_get_tables_reply>(vapi_msg_classify_trace_get_tables_reply *msg)
{
  vapi_msg_classify_trace_get_tables_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_classify_trace_get_tables_reply>(vapi_msg_classify_trace_get_tables_reply *msg)
{
  vapi_msg_classify_trace_get_tables_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_classify_trace_get_tables_reply>()
{
  return ::vapi_msg_id_classify_trace_get_tables_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_classify_trace_get_tables_reply>>()
{
  return ::vapi_msg_id_classify_trace_get_tables_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_classify_trace_get_tables_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_classify_trace_get_tables_reply>(vapi_msg_id_classify_trace_get_tables_reply);
}

template class Msg<vapi_msg_classify_trace_get_tables_reply>;

using Classify_trace_get_tables_reply = Msg<vapi_msg_classify_trace_get_tables_reply>;
}
#endif
