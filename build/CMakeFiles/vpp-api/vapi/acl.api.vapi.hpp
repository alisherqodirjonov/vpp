#ifndef __included_hpp_acl_api_json
#define __included_hpp_acl_api_json

#include <vapi/vapi.hpp>
#include <vapi/acl.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_get_version>(vapi_msg_acl_plugin_get_version *msg)
{
  vapi_msg_acl_plugin_get_version_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_get_version>(vapi_msg_acl_plugin_get_version *msg)
{
  vapi_msg_acl_plugin_get_version_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_get_version>()
{
  return ::vapi_msg_id_acl_plugin_get_version; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_get_version>>()
{
  return ::vapi_msg_id_acl_plugin_get_version; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_get_version()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_get_version>(vapi_msg_id_acl_plugin_get_version);
}

template <> inline vapi_msg_acl_plugin_get_version* vapi_alloc<vapi_msg_acl_plugin_get_version>(Connection &con)
{
  vapi_msg_acl_plugin_get_version* result = vapi_alloc_acl_plugin_get_version(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_plugin_get_version>;

template class Request<vapi_msg_acl_plugin_get_version, vapi_msg_acl_plugin_get_version_reply>;

using Acl_plugin_get_version = Request<vapi_msg_acl_plugin_get_version, vapi_msg_acl_plugin_get_version_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_get_version_reply>(vapi_msg_acl_plugin_get_version_reply *msg)
{
  vapi_msg_acl_plugin_get_version_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_get_version_reply>(vapi_msg_acl_plugin_get_version_reply *msg)
{
  vapi_msg_acl_plugin_get_version_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_get_version_reply>()
{
  return ::vapi_msg_id_acl_plugin_get_version_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_get_version_reply>>()
{
  return ::vapi_msg_id_acl_plugin_get_version_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_get_version_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_get_version_reply>(vapi_msg_id_acl_plugin_get_version_reply);
}

template class Msg<vapi_msg_acl_plugin_get_version_reply>;

using Acl_plugin_get_version_reply = Msg<vapi_msg_acl_plugin_get_version_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_control_ping>(vapi_msg_acl_plugin_control_ping *msg)
{
  vapi_msg_acl_plugin_control_ping_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_control_ping>(vapi_msg_acl_plugin_control_ping *msg)
{
  vapi_msg_acl_plugin_control_ping_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_control_ping>()
{
  return ::vapi_msg_id_acl_plugin_control_ping; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_control_ping>>()
{
  return ::vapi_msg_id_acl_plugin_control_ping; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_control_ping()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_control_ping>(vapi_msg_id_acl_plugin_control_ping);
}

template <> inline vapi_msg_acl_plugin_control_ping* vapi_alloc<vapi_msg_acl_plugin_control_ping>(Connection &con)
{
  vapi_msg_acl_plugin_control_ping* result = vapi_alloc_acl_plugin_control_ping(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_plugin_control_ping>;

template class Request<vapi_msg_acl_plugin_control_ping, vapi_msg_acl_plugin_control_ping_reply>;

using Acl_plugin_control_ping = Request<vapi_msg_acl_plugin_control_ping, vapi_msg_acl_plugin_control_ping_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_control_ping_reply>(vapi_msg_acl_plugin_control_ping_reply *msg)
{
  vapi_msg_acl_plugin_control_ping_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_control_ping_reply>(vapi_msg_acl_plugin_control_ping_reply *msg)
{
  vapi_msg_acl_plugin_control_ping_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_control_ping_reply>()
{
  return ::vapi_msg_id_acl_plugin_control_ping_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_control_ping_reply>>()
{
  return ::vapi_msg_id_acl_plugin_control_ping_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_control_ping_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_control_ping_reply>(vapi_msg_id_acl_plugin_control_ping_reply);
}

template class Msg<vapi_msg_acl_plugin_control_ping_reply>;

using Acl_plugin_control_ping_reply = Msg<vapi_msg_acl_plugin_control_ping_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_get_conn_table_max_entries>(vapi_msg_acl_plugin_get_conn_table_max_entries *msg)
{
  vapi_msg_acl_plugin_get_conn_table_max_entries_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_get_conn_table_max_entries>(vapi_msg_acl_plugin_get_conn_table_max_entries *msg)
{
  vapi_msg_acl_plugin_get_conn_table_max_entries_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_get_conn_table_max_entries>()
{
  return ::vapi_msg_id_acl_plugin_get_conn_table_max_entries; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_get_conn_table_max_entries>>()
{
  return ::vapi_msg_id_acl_plugin_get_conn_table_max_entries; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_get_conn_table_max_entries()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_get_conn_table_max_entries>(vapi_msg_id_acl_plugin_get_conn_table_max_entries);
}

template <> inline vapi_msg_acl_plugin_get_conn_table_max_entries* vapi_alloc<vapi_msg_acl_plugin_get_conn_table_max_entries>(Connection &con)
{
  vapi_msg_acl_plugin_get_conn_table_max_entries* result = vapi_alloc_acl_plugin_get_conn_table_max_entries(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_plugin_get_conn_table_max_entries>;

template class Request<vapi_msg_acl_plugin_get_conn_table_max_entries, vapi_msg_acl_plugin_get_conn_table_max_entries_reply>;

using Acl_plugin_get_conn_table_max_entries = Request<vapi_msg_acl_plugin_get_conn_table_max_entries, vapi_msg_acl_plugin_get_conn_table_max_entries_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>(vapi_msg_acl_plugin_get_conn_table_max_entries_reply *msg)
{
  vapi_msg_acl_plugin_get_conn_table_max_entries_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>(vapi_msg_acl_plugin_get_conn_table_max_entries_reply *msg)
{
  vapi_msg_acl_plugin_get_conn_table_max_entries_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>()
{
  return ::vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>>()
{
  return ::vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_get_conn_table_max_entries_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>(vapi_msg_id_acl_plugin_get_conn_table_max_entries_reply);
}

template class Msg<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>;

using Acl_plugin_get_conn_table_max_entries_reply = Msg<vapi_msg_acl_plugin_get_conn_table_max_entries_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_add_replace>(vapi_msg_acl_add_replace *msg)
{
  vapi_msg_acl_add_replace_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_add_replace>(vapi_msg_acl_add_replace *msg)
{
  vapi_msg_acl_add_replace_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_add_replace>()
{
  return ::vapi_msg_id_acl_add_replace; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_add_replace>>()
{
  return ::vapi_msg_id_acl_add_replace; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_add_replace()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_add_replace>(vapi_msg_id_acl_add_replace);
}

template <> inline vapi_msg_acl_add_replace* vapi_alloc<vapi_msg_acl_add_replace, size_t>(Connection &con, size_t _r_array_size)
{
  vapi_msg_acl_add_replace* result = vapi_alloc_acl_add_replace(con.vapi_ctx, _r_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_add_replace>;

template class Request<vapi_msg_acl_add_replace, vapi_msg_acl_add_replace_reply, size_t>;

using Acl_add_replace = Request<vapi_msg_acl_add_replace, vapi_msg_acl_add_replace_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_add_replace_reply>(vapi_msg_acl_add_replace_reply *msg)
{
  vapi_msg_acl_add_replace_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_add_replace_reply>(vapi_msg_acl_add_replace_reply *msg)
{
  vapi_msg_acl_add_replace_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_add_replace_reply>()
{
  return ::vapi_msg_id_acl_add_replace_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_add_replace_reply>>()
{
  return ::vapi_msg_id_acl_add_replace_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_add_replace_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_add_replace_reply>(vapi_msg_id_acl_add_replace_reply);
}

template class Msg<vapi_msg_acl_add_replace_reply>;

using Acl_add_replace_reply = Msg<vapi_msg_acl_add_replace_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_del>(vapi_msg_acl_del *msg)
{
  vapi_msg_acl_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_del>(vapi_msg_acl_del *msg)
{
  vapi_msg_acl_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_del>()
{
  return ::vapi_msg_id_acl_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_del>>()
{
  return ::vapi_msg_id_acl_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_del>(vapi_msg_id_acl_del);
}

template <> inline vapi_msg_acl_del* vapi_alloc<vapi_msg_acl_del>(Connection &con)
{
  vapi_msg_acl_del* result = vapi_alloc_acl_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_del>;

template class Request<vapi_msg_acl_del, vapi_msg_acl_del_reply>;

using Acl_del = Request<vapi_msg_acl_del, vapi_msg_acl_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_del_reply>(vapi_msg_acl_del_reply *msg)
{
  vapi_msg_acl_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_del_reply>(vapi_msg_acl_del_reply *msg)
{
  vapi_msg_acl_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_del_reply>()
{
  return ::vapi_msg_id_acl_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_del_reply>>()
{
  return ::vapi_msg_id_acl_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_del_reply>(vapi_msg_id_acl_del_reply);
}

template class Msg<vapi_msg_acl_del_reply>;

using Acl_del_reply = Msg<vapi_msg_acl_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_add_del>(vapi_msg_acl_interface_add_del *msg)
{
  vapi_msg_acl_interface_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_add_del>(vapi_msg_acl_interface_add_del *msg)
{
  vapi_msg_acl_interface_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_add_del>()
{
  return ::vapi_msg_id_acl_interface_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_add_del>>()
{
  return ::vapi_msg_id_acl_interface_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_add_del>(vapi_msg_id_acl_interface_add_del);
}

template <> inline vapi_msg_acl_interface_add_del* vapi_alloc<vapi_msg_acl_interface_add_del>(Connection &con)
{
  vapi_msg_acl_interface_add_del* result = vapi_alloc_acl_interface_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_interface_add_del>;

template class Request<vapi_msg_acl_interface_add_del, vapi_msg_acl_interface_add_del_reply>;

using Acl_interface_add_del = Request<vapi_msg_acl_interface_add_del, vapi_msg_acl_interface_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_add_del_reply>(vapi_msg_acl_interface_add_del_reply *msg)
{
  vapi_msg_acl_interface_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_add_del_reply>(vapi_msg_acl_interface_add_del_reply *msg)
{
  vapi_msg_acl_interface_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_add_del_reply>()
{
  return ::vapi_msg_id_acl_interface_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_add_del_reply>>()
{
  return ::vapi_msg_id_acl_interface_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_add_del_reply>(vapi_msg_id_acl_interface_add_del_reply);
}

template class Msg<vapi_msg_acl_interface_add_del_reply>;

using Acl_interface_add_del_reply = Msg<vapi_msg_acl_interface_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_set_acl_list>(vapi_msg_acl_interface_set_acl_list *msg)
{
  vapi_msg_acl_interface_set_acl_list_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_set_acl_list>(vapi_msg_acl_interface_set_acl_list *msg)
{
  vapi_msg_acl_interface_set_acl_list_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_set_acl_list>()
{
  return ::vapi_msg_id_acl_interface_set_acl_list; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_set_acl_list>>()
{
  return ::vapi_msg_id_acl_interface_set_acl_list; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_set_acl_list()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_set_acl_list>(vapi_msg_id_acl_interface_set_acl_list);
}

template <> inline vapi_msg_acl_interface_set_acl_list* vapi_alloc<vapi_msg_acl_interface_set_acl_list, size_t>(Connection &con, size_t _acls_array_size)
{
  vapi_msg_acl_interface_set_acl_list* result = vapi_alloc_acl_interface_set_acl_list(con.vapi_ctx, _acls_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_interface_set_acl_list>;

template class Request<vapi_msg_acl_interface_set_acl_list, vapi_msg_acl_interface_set_acl_list_reply, size_t>;

using Acl_interface_set_acl_list = Request<vapi_msg_acl_interface_set_acl_list, vapi_msg_acl_interface_set_acl_list_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_set_acl_list_reply>(vapi_msg_acl_interface_set_acl_list_reply *msg)
{
  vapi_msg_acl_interface_set_acl_list_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_set_acl_list_reply>(vapi_msg_acl_interface_set_acl_list_reply *msg)
{
  vapi_msg_acl_interface_set_acl_list_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_set_acl_list_reply>()
{
  return ::vapi_msg_id_acl_interface_set_acl_list_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_set_acl_list_reply>>()
{
  return ::vapi_msg_id_acl_interface_set_acl_list_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_set_acl_list_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_set_acl_list_reply>(vapi_msg_id_acl_interface_set_acl_list_reply);
}

template class Msg<vapi_msg_acl_interface_set_acl_list_reply>;

using Acl_interface_set_acl_list_reply = Msg<vapi_msg_acl_interface_set_acl_list_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_dump>(vapi_msg_acl_dump *msg)
{
  vapi_msg_acl_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_dump>(vapi_msg_acl_dump *msg)
{
  vapi_msg_acl_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_dump>()
{
  return ::vapi_msg_id_acl_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_dump>>()
{
  return ::vapi_msg_id_acl_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_dump>(vapi_msg_id_acl_dump);
}

template <> inline vapi_msg_acl_dump* vapi_alloc<vapi_msg_acl_dump>(Connection &con)
{
  vapi_msg_acl_dump* result = vapi_alloc_acl_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_dump>;

template class Dump<vapi_msg_acl_dump, vapi_msg_acl_details>;

using Acl_dump = Dump<vapi_msg_acl_dump, vapi_msg_acl_details>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_details>(vapi_msg_acl_details *msg)
{
  vapi_msg_acl_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_details>(vapi_msg_acl_details *msg)
{
  vapi_msg_acl_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_details>()
{
  return ::vapi_msg_id_acl_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_details>>()
{
  return ::vapi_msg_id_acl_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_details>(vapi_msg_id_acl_details);
}

template class Msg<vapi_msg_acl_details>;

using Acl_details = Msg<vapi_msg_acl_details>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_list_dump>(vapi_msg_acl_interface_list_dump *msg)
{
  vapi_msg_acl_interface_list_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_list_dump>(vapi_msg_acl_interface_list_dump *msg)
{
  vapi_msg_acl_interface_list_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_list_dump>()
{
  return ::vapi_msg_id_acl_interface_list_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_list_dump>>()
{
  return ::vapi_msg_id_acl_interface_list_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_list_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_list_dump>(vapi_msg_id_acl_interface_list_dump);
}

template <> inline vapi_msg_acl_interface_list_dump* vapi_alloc<vapi_msg_acl_interface_list_dump>(Connection &con)
{
  vapi_msg_acl_interface_list_dump* result = vapi_alloc_acl_interface_list_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_interface_list_dump>;

template class Dump<vapi_msg_acl_interface_list_dump, vapi_msg_acl_interface_list_details>;

using Acl_interface_list_dump = Dump<vapi_msg_acl_interface_list_dump, vapi_msg_acl_interface_list_details>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_list_details>(vapi_msg_acl_interface_list_details *msg)
{
  vapi_msg_acl_interface_list_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_list_details>(vapi_msg_acl_interface_list_details *msg)
{
  vapi_msg_acl_interface_list_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_list_details>()
{
  return ::vapi_msg_id_acl_interface_list_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_list_details>>()
{
  return ::vapi_msg_id_acl_interface_list_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_list_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_list_details>(vapi_msg_id_acl_interface_list_details);
}

template class Msg<vapi_msg_acl_interface_list_details>;

using Acl_interface_list_details = Msg<vapi_msg_acl_interface_list_details>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_add>(vapi_msg_macip_acl_add *msg)
{
  vapi_msg_macip_acl_add_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_add>(vapi_msg_macip_acl_add *msg)
{
  vapi_msg_macip_acl_add_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_add>()
{
  return ::vapi_msg_id_macip_acl_add; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_add>>()
{
  return ::vapi_msg_id_macip_acl_add; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_add()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_add>(vapi_msg_id_macip_acl_add);
}

template <> inline vapi_msg_macip_acl_add* vapi_alloc<vapi_msg_macip_acl_add, size_t>(Connection &con, size_t _r_array_size)
{
  vapi_msg_macip_acl_add* result = vapi_alloc_macip_acl_add(con.vapi_ctx, _r_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_add>;

template class Request<vapi_msg_macip_acl_add, vapi_msg_macip_acl_add_reply, size_t>;

using Macip_acl_add = Request<vapi_msg_macip_acl_add, vapi_msg_macip_acl_add_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_add_reply>(vapi_msg_macip_acl_add_reply *msg)
{
  vapi_msg_macip_acl_add_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_add_reply>(vapi_msg_macip_acl_add_reply *msg)
{
  vapi_msg_macip_acl_add_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_add_reply>()
{
  return ::vapi_msg_id_macip_acl_add_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_add_reply>>()
{
  return ::vapi_msg_id_macip_acl_add_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_add_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_add_reply>(vapi_msg_id_macip_acl_add_reply);
}

template class Msg<vapi_msg_macip_acl_add_reply>;

using Macip_acl_add_reply = Msg<vapi_msg_macip_acl_add_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_add_replace>(vapi_msg_macip_acl_add_replace *msg)
{
  vapi_msg_macip_acl_add_replace_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_add_replace>(vapi_msg_macip_acl_add_replace *msg)
{
  vapi_msg_macip_acl_add_replace_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_add_replace>()
{
  return ::vapi_msg_id_macip_acl_add_replace; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_add_replace>>()
{
  return ::vapi_msg_id_macip_acl_add_replace; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_add_replace()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_add_replace>(vapi_msg_id_macip_acl_add_replace);
}

template <> inline vapi_msg_macip_acl_add_replace* vapi_alloc<vapi_msg_macip_acl_add_replace, size_t>(Connection &con, size_t _r_array_size)
{
  vapi_msg_macip_acl_add_replace* result = vapi_alloc_macip_acl_add_replace(con.vapi_ctx, _r_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_add_replace>;

template class Request<vapi_msg_macip_acl_add_replace, vapi_msg_macip_acl_add_replace_reply, size_t>;

using Macip_acl_add_replace = Request<vapi_msg_macip_acl_add_replace, vapi_msg_macip_acl_add_replace_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_add_replace_reply>(vapi_msg_macip_acl_add_replace_reply *msg)
{
  vapi_msg_macip_acl_add_replace_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_add_replace_reply>(vapi_msg_macip_acl_add_replace_reply *msg)
{
  vapi_msg_macip_acl_add_replace_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_add_replace_reply>()
{
  return ::vapi_msg_id_macip_acl_add_replace_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_add_replace_reply>>()
{
  return ::vapi_msg_id_macip_acl_add_replace_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_add_replace_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_add_replace_reply>(vapi_msg_id_macip_acl_add_replace_reply);
}

template class Msg<vapi_msg_macip_acl_add_replace_reply>;

using Macip_acl_add_replace_reply = Msg<vapi_msg_macip_acl_add_replace_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_del>(vapi_msg_macip_acl_del *msg)
{
  vapi_msg_macip_acl_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_del>(vapi_msg_macip_acl_del *msg)
{
  vapi_msg_macip_acl_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_del>()
{
  return ::vapi_msg_id_macip_acl_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_del>>()
{
  return ::vapi_msg_id_macip_acl_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_del>(vapi_msg_id_macip_acl_del);
}

template <> inline vapi_msg_macip_acl_del* vapi_alloc<vapi_msg_macip_acl_del>(Connection &con)
{
  vapi_msg_macip_acl_del* result = vapi_alloc_macip_acl_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_del>;

template class Request<vapi_msg_macip_acl_del, vapi_msg_macip_acl_del_reply>;

using Macip_acl_del = Request<vapi_msg_macip_acl_del, vapi_msg_macip_acl_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_del_reply>(vapi_msg_macip_acl_del_reply *msg)
{
  vapi_msg_macip_acl_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_del_reply>(vapi_msg_macip_acl_del_reply *msg)
{
  vapi_msg_macip_acl_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_del_reply>()
{
  return ::vapi_msg_id_macip_acl_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_del_reply>>()
{
  return ::vapi_msg_id_macip_acl_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_del_reply>(vapi_msg_id_macip_acl_del_reply);
}

template class Msg<vapi_msg_macip_acl_del_reply>;

using Macip_acl_del_reply = Msg<vapi_msg_macip_acl_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_interface_add_del>(vapi_msg_macip_acl_interface_add_del *msg)
{
  vapi_msg_macip_acl_interface_add_del_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_interface_add_del>(vapi_msg_macip_acl_interface_add_del *msg)
{
  vapi_msg_macip_acl_interface_add_del_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_interface_add_del>()
{
  return ::vapi_msg_id_macip_acl_interface_add_del; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_interface_add_del>>()
{
  return ::vapi_msg_id_macip_acl_interface_add_del; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_interface_add_del()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_interface_add_del>(vapi_msg_id_macip_acl_interface_add_del);
}

template <> inline vapi_msg_macip_acl_interface_add_del* vapi_alloc<vapi_msg_macip_acl_interface_add_del>(Connection &con)
{
  vapi_msg_macip_acl_interface_add_del* result = vapi_alloc_macip_acl_interface_add_del(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_interface_add_del>;

template class Request<vapi_msg_macip_acl_interface_add_del, vapi_msg_macip_acl_interface_add_del_reply>;

using Macip_acl_interface_add_del = Request<vapi_msg_macip_acl_interface_add_del, vapi_msg_macip_acl_interface_add_del_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_interface_add_del_reply>(vapi_msg_macip_acl_interface_add_del_reply *msg)
{
  vapi_msg_macip_acl_interface_add_del_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_interface_add_del_reply>(vapi_msg_macip_acl_interface_add_del_reply *msg)
{
  vapi_msg_macip_acl_interface_add_del_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_interface_add_del_reply>()
{
  return ::vapi_msg_id_macip_acl_interface_add_del_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_interface_add_del_reply>>()
{
  return ::vapi_msg_id_macip_acl_interface_add_del_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_interface_add_del_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_interface_add_del_reply>(vapi_msg_id_macip_acl_interface_add_del_reply);
}

template class Msg<vapi_msg_macip_acl_interface_add_del_reply>;

using Macip_acl_interface_add_del_reply = Msg<vapi_msg_macip_acl_interface_add_del_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_dump>(vapi_msg_macip_acl_dump *msg)
{
  vapi_msg_macip_acl_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_dump>(vapi_msg_macip_acl_dump *msg)
{
  vapi_msg_macip_acl_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_dump>()
{
  return ::vapi_msg_id_macip_acl_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_dump>>()
{
  return ::vapi_msg_id_macip_acl_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_dump>(vapi_msg_id_macip_acl_dump);
}

template <> inline vapi_msg_macip_acl_dump* vapi_alloc<vapi_msg_macip_acl_dump>(Connection &con)
{
  vapi_msg_macip_acl_dump* result = vapi_alloc_macip_acl_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_dump>;

template class Dump<vapi_msg_macip_acl_dump, vapi_msg_macip_acl_details>;

using Macip_acl_dump = Dump<vapi_msg_macip_acl_dump, vapi_msg_macip_acl_details>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_details>(vapi_msg_macip_acl_details *msg)
{
  vapi_msg_macip_acl_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_details>(vapi_msg_macip_acl_details *msg)
{
  vapi_msg_macip_acl_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_details>()
{
  return ::vapi_msg_id_macip_acl_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_details>>()
{
  return ::vapi_msg_id_macip_acl_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_details>(vapi_msg_id_macip_acl_details);
}

template class Msg<vapi_msg_macip_acl_details>;

using Macip_acl_details = Msg<vapi_msg_macip_acl_details>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_interface_get>(vapi_msg_macip_acl_interface_get *msg)
{
  vapi_msg_macip_acl_interface_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_interface_get>(vapi_msg_macip_acl_interface_get *msg)
{
  vapi_msg_macip_acl_interface_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_interface_get>()
{
  return ::vapi_msg_id_macip_acl_interface_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_interface_get>>()
{
  return ::vapi_msg_id_macip_acl_interface_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_interface_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_interface_get>(vapi_msg_id_macip_acl_interface_get);
}

template <> inline vapi_msg_macip_acl_interface_get* vapi_alloc<vapi_msg_macip_acl_interface_get>(Connection &con)
{
  vapi_msg_macip_acl_interface_get* result = vapi_alloc_macip_acl_interface_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_interface_get>;

template class Request<vapi_msg_macip_acl_interface_get, vapi_msg_macip_acl_interface_get_reply>;

using Macip_acl_interface_get = Request<vapi_msg_macip_acl_interface_get, vapi_msg_macip_acl_interface_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_interface_get_reply>(vapi_msg_macip_acl_interface_get_reply *msg)
{
  vapi_msg_macip_acl_interface_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_interface_get_reply>(vapi_msg_macip_acl_interface_get_reply *msg)
{
  vapi_msg_macip_acl_interface_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_interface_get_reply>()
{
  return ::vapi_msg_id_macip_acl_interface_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_interface_get_reply>>()
{
  return ::vapi_msg_id_macip_acl_interface_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_interface_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_interface_get_reply>(vapi_msg_id_macip_acl_interface_get_reply);
}

template class Msg<vapi_msg_macip_acl_interface_get_reply>;

using Macip_acl_interface_get_reply = Msg<vapi_msg_macip_acl_interface_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_interface_list_dump>(vapi_msg_macip_acl_interface_list_dump *msg)
{
  vapi_msg_macip_acl_interface_list_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_interface_list_dump>(vapi_msg_macip_acl_interface_list_dump *msg)
{
  vapi_msg_macip_acl_interface_list_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_interface_list_dump>()
{
  return ::vapi_msg_id_macip_acl_interface_list_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_interface_list_dump>>()
{
  return ::vapi_msg_id_macip_acl_interface_list_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_interface_list_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_interface_list_dump>(vapi_msg_id_macip_acl_interface_list_dump);
}

template <> inline vapi_msg_macip_acl_interface_list_dump* vapi_alloc<vapi_msg_macip_acl_interface_list_dump>(Connection &con)
{
  vapi_msg_macip_acl_interface_list_dump* result = vapi_alloc_macip_acl_interface_list_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_macip_acl_interface_list_dump>;

template class Dump<vapi_msg_macip_acl_interface_list_dump, vapi_msg_macip_acl_interface_list_details>;

using Macip_acl_interface_list_dump = Dump<vapi_msg_macip_acl_interface_list_dump, vapi_msg_macip_acl_interface_list_details>;

template <> inline void vapi_swap_to_be<vapi_msg_macip_acl_interface_list_details>(vapi_msg_macip_acl_interface_list_details *msg)
{
  vapi_msg_macip_acl_interface_list_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_macip_acl_interface_list_details>(vapi_msg_macip_acl_interface_list_details *msg)
{
  vapi_msg_macip_acl_interface_list_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_macip_acl_interface_list_details>()
{
  return ::vapi_msg_id_macip_acl_interface_list_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_macip_acl_interface_list_details>>()
{
  return ::vapi_msg_id_macip_acl_interface_list_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_macip_acl_interface_list_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_macip_acl_interface_list_details>(vapi_msg_id_macip_acl_interface_list_details);
}

template class Msg<vapi_msg_macip_acl_interface_list_details>;

using Macip_acl_interface_list_details = Msg<vapi_msg_macip_acl_interface_list_details>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_set_etype_whitelist>(vapi_msg_acl_interface_set_etype_whitelist *msg)
{
  vapi_msg_acl_interface_set_etype_whitelist_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_set_etype_whitelist>(vapi_msg_acl_interface_set_etype_whitelist *msg)
{
  vapi_msg_acl_interface_set_etype_whitelist_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_set_etype_whitelist>()
{
  return ::vapi_msg_id_acl_interface_set_etype_whitelist; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_set_etype_whitelist>>()
{
  return ::vapi_msg_id_acl_interface_set_etype_whitelist; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_set_etype_whitelist()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_set_etype_whitelist>(vapi_msg_id_acl_interface_set_etype_whitelist);
}

template <> inline vapi_msg_acl_interface_set_etype_whitelist* vapi_alloc<vapi_msg_acl_interface_set_etype_whitelist, size_t>(Connection &con, size_t _whitelist_array_size)
{
  vapi_msg_acl_interface_set_etype_whitelist* result = vapi_alloc_acl_interface_set_etype_whitelist(con.vapi_ctx, _whitelist_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_interface_set_etype_whitelist>;

template class Request<vapi_msg_acl_interface_set_etype_whitelist, vapi_msg_acl_interface_set_etype_whitelist_reply, size_t>;

using Acl_interface_set_etype_whitelist = Request<vapi_msg_acl_interface_set_etype_whitelist, vapi_msg_acl_interface_set_etype_whitelist_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_set_etype_whitelist_reply>(vapi_msg_acl_interface_set_etype_whitelist_reply *msg)
{
  vapi_msg_acl_interface_set_etype_whitelist_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_set_etype_whitelist_reply>(vapi_msg_acl_interface_set_etype_whitelist_reply *msg)
{
  vapi_msg_acl_interface_set_etype_whitelist_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_set_etype_whitelist_reply>()
{
  return ::vapi_msg_id_acl_interface_set_etype_whitelist_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_set_etype_whitelist_reply>>()
{
  return ::vapi_msg_id_acl_interface_set_etype_whitelist_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_set_etype_whitelist_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_set_etype_whitelist_reply>(vapi_msg_id_acl_interface_set_etype_whitelist_reply);
}

template class Msg<vapi_msg_acl_interface_set_etype_whitelist_reply>;

using Acl_interface_set_etype_whitelist_reply = Msg<vapi_msg_acl_interface_set_etype_whitelist_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_etype_whitelist_dump>(vapi_msg_acl_interface_etype_whitelist_dump *msg)
{
  vapi_msg_acl_interface_etype_whitelist_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_etype_whitelist_dump>(vapi_msg_acl_interface_etype_whitelist_dump *msg)
{
  vapi_msg_acl_interface_etype_whitelist_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_etype_whitelist_dump>()
{
  return ::vapi_msg_id_acl_interface_etype_whitelist_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_etype_whitelist_dump>>()
{
  return ::vapi_msg_id_acl_interface_etype_whitelist_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_etype_whitelist_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_etype_whitelist_dump>(vapi_msg_id_acl_interface_etype_whitelist_dump);
}

template <> inline vapi_msg_acl_interface_etype_whitelist_dump* vapi_alloc<vapi_msg_acl_interface_etype_whitelist_dump>(Connection &con)
{
  vapi_msg_acl_interface_etype_whitelist_dump* result = vapi_alloc_acl_interface_etype_whitelist_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_interface_etype_whitelist_dump>;

template class Dump<vapi_msg_acl_interface_etype_whitelist_dump, vapi_msg_acl_interface_etype_whitelist_details>;

using Acl_interface_etype_whitelist_dump = Dump<vapi_msg_acl_interface_etype_whitelist_dump, vapi_msg_acl_interface_etype_whitelist_details>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_interface_etype_whitelist_details>(vapi_msg_acl_interface_etype_whitelist_details *msg)
{
  vapi_msg_acl_interface_etype_whitelist_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_interface_etype_whitelist_details>(vapi_msg_acl_interface_etype_whitelist_details *msg)
{
  vapi_msg_acl_interface_etype_whitelist_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_interface_etype_whitelist_details>()
{
  return ::vapi_msg_id_acl_interface_etype_whitelist_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_interface_etype_whitelist_details>>()
{
  return ::vapi_msg_id_acl_interface_etype_whitelist_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_interface_etype_whitelist_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_interface_etype_whitelist_details>(vapi_msg_id_acl_interface_etype_whitelist_details);
}

template class Msg<vapi_msg_acl_interface_etype_whitelist_details>;

using Acl_interface_etype_whitelist_details = Msg<vapi_msg_acl_interface_etype_whitelist_details>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_stats_intf_counters_enable>(vapi_msg_acl_stats_intf_counters_enable *msg)
{
  vapi_msg_acl_stats_intf_counters_enable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_stats_intf_counters_enable>(vapi_msg_acl_stats_intf_counters_enable *msg)
{
  vapi_msg_acl_stats_intf_counters_enable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_stats_intf_counters_enable>()
{
  return ::vapi_msg_id_acl_stats_intf_counters_enable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_stats_intf_counters_enable>>()
{
  return ::vapi_msg_id_acl_stats_intf_counters_enable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_stats_intf_counters_enable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_stats_intf_counters_enable>(vapi_msg_id_acl_stats_intf_counters_enable);
}

template <> inline vapi_msg_acl_stats_intf_counters_enable* vapi_alloc<vapi_msg_acl_stats_intf_counters_enable>(Connection &con)
{
  vapi_msg_acl_stats_intf_counters_enable* result = vapi_alloc_acl_stats_intf_counters_enable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_stats_intf_counters_enable>;

template class Request<vapi_msg_acl_stats_intf_counters_enable, vapi_msg_acl_stats_intf_counters_enable_reply>;

using Acl_stats_intf_counters_enable = Request<vapi_msg_acl_stats_intf_counters_enable, vapi_msg_acl_stats_intf_counters_enable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_stats_intf_counters_enable_reply>(vapi_msg_acl_stats_intf_counters_enable_reply *msg)
{
  vapi_msg_acl_stats_intf_counters_enable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_stats_intf_counters_enable_reply>(vapi_msg_acl_stats_intf_counters_enable_reply *msg)
{
  vapi_msg_acl_stats_intf_counters_enable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_stats_intf_counters_enable_reply>()
{
  return ::vapi_msg_id_acl_stats_intf_counters_enable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_stats_intf_counters_enable_reply>>()
{
  return ::vapi_msg_id_acl_stats_intf_counters_enable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_stats_intf_counters_enable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_stats_intf_counters_enable_reply>(vapi_msg_id_acl_stats_intf_counters_enable_reply);
}

template class Msg<vapi_msg_acl_stats_intf_counters_enable_reply>;

using Acl_stats_intf_counters_enable_reply = Msg<vapi_msg_acl_stats_intf_counters_enable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_use_hash_lookup_set>(vapi_msg_acl_plugin_use_hash_lookup_set *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_set_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_use_hash_lookup_set>(vapi_msg_acl_plugin_use_hash_lookup_set *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_set_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_use_hash_lookup_set>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_set; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_use_hash_lookup_set>>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_set; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_use_hash_lookup_set()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_use_hash_lookup_set>(vapi_msg_id_acl_plugin_use_hash_lookup_set);
}

template <> inline vapi_msg_acl_plugin_use_hash_lookup_set* vapi_alloc<vapi_msg_acl_plugin_use_hash_lookup_set>(Connection &con)
{
  vapi_msg_acl_plugin_use_hash_lookup_set* result = vapi_alloc_acl_plugin_use_hash_lookup_set(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_plugin_use_hash_lookup_set>;

template class Request<vapi_msg_acl_plugin_use_hash_lookup_set, vapi_msg_acl_plugin_use_hash_lookup_set_reply>;

using Acl_plugin_use_hash_lookup_set = Request<vapi_msg_acl_plugin_use_hash_lookup_set, vapi_msg_acl_plugin_use_hash_lookup_set_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_use_hash_lookup_set_reply>(vapi_msg_acl_plugin_use_hash_lookup_set_reply *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_set_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_use_hash_lookup_set_reply>(vapi_msg_acl_plugin_use_hash_lookup_set_reply *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_set_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_use_hash_lookup_set_reply>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_set_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_use_hash_lookup_set_reply>>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_set_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_use_hash_lookup_set_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_use_hash_lookup_set_reply>(vapi_msg_id_acl_plugin_use_hash_lookup_set_reply);
}

template class Msg<vapi_msg_acl_plugin_use_hash_lookup_set_reply>;

using Acl_plugin_use_hash_lookup_set_reply = Msg<vapi_msg_acl_plugin_use_hash_lookup_set_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_use_hash_lookup_get>(vapi_msg_acl_plugin_use_hash_lookup_get *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_use_hash_lookup_get>(vapi_msg_acl_plugin_use_hash_lookup_get *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_use_hash_lookup_get>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_use_hash_lookup_get>>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_use_hash_lookup_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_use_hash_lookup_get>(vapi_msg_id_acl_plugin_use_hash_lookup_get);
}

template <> inline vapi_msg_acl_plugin_use_hash_lookup_get* vapi_alloc<vapi_msg_acl_plugin_use_hash_lookup_get>(Connection &con)
{
  vapi_msg_acl_plugin_use_hash_lookup_get* result = vapi_alloc_acl_plugin_use_hash_lookup_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_acl_plugin_use_hash_lookup_get>;

template class Request<vapi_msg_acl_plugin_use_hash_lookup_get, vapi_msg_acl_plugin_use_hash_lookup_get_reply>;

using Acl_plugin_use_hash_lookup_get = Request<vapi_msg_acl_plugin_use_hash_lookup_get, vapi_msg_acl_plugin_use_hash_lookup_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_acl_plugin_use_hash_lookup_get_reply>(vapi_msg_acl_plugin_use_hash_lookup_get_reply *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_acl_plugin_use_hash_lookup_get_reply>(vapi_msg_acl_plugin_use_hash_lookup_get_reply *msg)
{
  vapi_msg_acl_plugin_use_hash_lookup_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_acl_plugin_use_hash_lookup_get_reply>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_acl_plugin_use_hash_lookup_get_reply>>()
{
  return ::vapi_msg_id_acl_plugin_use_hash_lookup_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_acl_plugin_use_hash_lookup_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_acl_plugin_use_hash_lookup_get_reply>(vapi_msg_id_acl_plugin_use_hash_lookup_get_reply);
}

template class Msg<vapi_msg_acl_plugin_use_hash_lookup_get_reply>;

using Acl_plugin_use_hash_lookup_get_reply = Msg<vapi_msg_acl_plugin_use_hash_lookup_get_reply>;
}
#endif
