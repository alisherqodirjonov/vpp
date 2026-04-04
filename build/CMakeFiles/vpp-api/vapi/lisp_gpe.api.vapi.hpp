#ifndef __included_hpp_lisp_gpe_api_json
#define __included_hpp_lisp_gpe_api_json

#include <vapi/vapi.hpp>
#include <vapi/lisp_gpe.api.vapi.h>

namespace vapi {

template <> inline void vapi_swap_to_be<vapi_msg_gpe_add_del_fwd_entry>(vapi_msg_gpe_add_del_fwd_entry *msg)
{
  vapi_msg_gpe_add_del_fwd_entry_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_add_del_fwd_entry>(vapi_msg_gpe_add_del_fwd_entry *msg)
{
  vapi_msg_gpe_add_del_fwd_entry_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_add_del_fwd_entry>()
{
  return ::vapi_msg_id_gpe_add_del_fwd_entry; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_add_del_fwd_entry>>()
{
  return ::vapi_msg_id_gpe_add_del_fwd_entry; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_add_del_fwd_entry()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_add_del_fwd_entry>(vapi_msg_id_gpe_add_del_fwd_entry);
}

template <> inline vapi_msg_gpe_add_del_fwd_entry* vapi_alloc<vapi_msg_gpe_add_del_fwd_entry, size_t>(Connection &con, size_t _locs_array_size)
{
  vapi_msg_gpe_add_del_fwd_entry* result = vapi_alloc_gpe_add_del_fwd_entry(con.vapi_ctx, _locs_array_size);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_add_del_fwd_entry>;

template class Request<vapi_msg_gpe_add_del_fwd_entry, vapi_msg_gpe_add_del_fwd_entry_reply, size_t>;

using Gpe_add_del_fwd_entry = Request<vapi_msg_gpe_add_del_fwd_entry, vapi_msg_gpe_add_del_fwd_entry_reply, size_t>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_add_del_fwd_entry_reply>(vapi_msg_gpe_add_del_fwd_entry_reply *msg)
{
  vapi_msg_gpe_add_del_fwd_entry_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_add_del_fwd_entry_reply>(vapi_msg_gpe_add_del_fwd_entry_reply *msg)
{
  vapi_msg_gpe_add_del_fwd_entry_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_add_del_fwd_entry_reply>()
{
  return ::vapi_msg_id_gpe_add_del_fwd_entry_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_add_del_fwd_entry_reply>>()
{
  return ::vapi_msg_id_gpe_add_del_fwd_entry_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_add_del_fwd_entry_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_add_del_fwd_entry_reply>(vapi_msg_id_gpe_add_del_fwd_entry_reply);
}

template class Msg<vapi_msg_gpe_add_del_fwd_entry_reply>;

using Gpe_add_del_fwd_entry_reply = Msg<vapi_msg_gpe_add_del_fwd_entry_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_enable_disable>(vapi_msg_gpe_enable_disable *msg)
{
  vapi_msg_gpe_enable_disable_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_enable_disable>(vapi_msg_gpe_enable_disable *msg)
{
  vapi_msg_gpe_enable_disable_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_enable_disable>()
{
  return ::vapi_msg_id_gpe_enable_disable; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_enable_disable>>()
{
  return ::vapi_msg_id_gpe_enable_disable; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_enable_disable()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_enable_disable>(vapi_msg_id_gpe_enable_disable);
}

template <> inline vapi_msg_gpe_enable_disable* vapi_alloc<vapi_msg_gpe_enable_disable>(Connection &con)
{
  vapi_msg_gpe_enable_disable* result = vapi_alloc_gpe_enable_disable(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_enable_disable>;

template class Request<vapi_msg_gpe_enable_disable, vapi_msg_gpe_enable_disable_reply>;

using Gpe_enable_disable = Request<vapi_msg_gpe_enable_disable, vapi_msg_gpe_enable_disable_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_enable_disable_reply>(vapi_msg_gpe_enable_disable_reply *msg)
{
  vapi_msg_gpe_enable_disable_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_enable_disable_reply>(vapi_msg_gpe_enable_disable_reply *msg)
{
  vapi_msg_gpe_enable_disable_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_enable_disable_reply>()
{
  return ::vapi_msg_id_gpe_enable_disable_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_enable_disable_reply>>()
{
  return ::vapi_msg_id_gpe_enable_disable_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_enable_disable_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_enable_disable_reply>(vapi_msg_id_gpe_enable_disable_reply);
}

template class Msg<vapi_msg_gpe_enable_disable_reply>;

using Gpe_enable_disable_reply = Msg<vapi_msg_gpe_enable_disable_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_add_del_iface>(vapi_msg_gpe_add_del_iface *msg)
{
  vapi_msg_gpe_add_del_iface_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_add_del_iface>(vapi_msg_gpe_add_del_iface *msg)
{
  vapi_msg_gpe_add_del_iface_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_add_del_iface>()
{
  return ::vapi_msg_id_gpe_add_del_iface; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_add_del_iface>>()
{
  return ::vapi_msg_id_gpe_add_del_iface; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_add_del_iface()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_add_del_iface>(vapi_msg_id_gpe_add_del_iface);
}

template <> inline vapi_msg_gpe_add_del_iface* vapi_alloc<vapi_msg_gpe_add_del_iface>(Connection &con)
{
  vapi_msg_gpe_add_del_iface* result = vapi_alloc_gpe_add_del_iface(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_add_del_iface>;

template class Request<vapi_msg_gpe_add_del_iface, vapi_msg_gpe_add_del_iface_reply>;

using Gpe_add_del_iface = Request<vapi_msg_gpe_add_del_iface, vapi_msg_gpe_add_del_iface_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_add_del_iface_reply>(vapi_msg_gpe_add_del_iface_reply *msg)
{
  vapi_msg_gpe_add_del_iface_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_add_del_iface_reply>(vapi_msg_gpe_add_del_iface_reply *msg)
{
  vapi_msg_gpe_add_del_iface_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_add_del_iface_reply>()
{
  return ::vapi_msg_id_gpe_add_del_iface_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_add_del_iface_reply>>()
{
  return ::vapi_msg_id_gpe_add_del_iface_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_add_del_iface_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_add_del_iface_reply>(vapi_msg_id_gpe_add_del_iface_reply);
}

template class Msg<vapi_msg_gpe_add_del_iface_reply>;

using Gpe_add_del_iface_reply = Msg<vapi_msg_gpe_add_del_iface_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_fwd_entry_vnis_get>(vapi_msg_gpe_fwd_entry_vnis_get *msg)
{
  vapi_msg_gpe_fwd_entry_vnis_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_fwd_entry_vnis_get>(vapi_msg_gpe_fwd_entry_vnis_get *msg)
{
  vapi_msg_gpe_fwd_entry_vnis_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_fwd_entry_vnis_get>()
{
  return ::vapi_msg_id_gpe_fwd_entry_vnis_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_fwd_entry_vnis_get>>()
{
  return ::vapi_msg_id_gpe_fwd_entry_vnis_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_fwd_entry_vnis_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_fwd_entry_vnis_get>(vapi_msg_id_gpe_fwd_entry_vnis_get);
}

template <> inline vapi_msg_gpe_fwd_entry_vnis_get* vapi_alloc<vapi_msg_gpe_fwd_entry_vnis_get>(Connection &con)
{
  vapi_msg_gpe_fwd_entry_vnis_get* result = vapi_alloc_gpe_fwd_entry_vnis_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_fwd_entry_vnis_get>;

template class Request<vapi_msg_gpe_fwd_entry_vnis_get, vapi_msg_gpe_fwd_entry_vnis_get_reply>;

using Gpe_fwd_entry_vnis_get = Request<vapi_msg_gpe_fwd_entry_vnis_get, vapi_msg_gpe_fwd_entry_vnis_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_fwd_entry_vnis_get_reply>(vapi_msg_gpe_fwd_entry_vnis_get_reply *msg)
{
  vapi_msg_gpe_fwd_entry_vnis_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_fwd_entry_vnis_get_reply>(vapi_msg_gpe_fwd_entry_vnis_get_reply *msg)
{
  vapi_msg_gpe_fwd_entry_vnis_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_fwd_entry_vnis_get_reply>()
{
  return ::vapi_msg_id_gpe_fwd_entry_vnis_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_fwd_entry_vnis_get_reply>>()
{
  return ::vapi_msg_id_gpe_fwd_entry_vnis_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_fwd_entry_vnis_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_fwd_entry_vnis_get_reply>(vapi_msg_id_gpe_fwd_entry_vnis_get_reply);
}

template class Msg<vapi_msg_gpe_fwd_entry_vnis_get_reply>;

using Gpe_fwd_entry_vnis_get_reply = Msg<vapi_msg_gpe_fwd_entry_vnis_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_fwd_entries_get>(vapi_msg_gpe_fwd_entries_get *msg)
{
  vapi_msg_gpe_fwd_entries_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_fwd_entries_get>(vapi_msg_gpe_fwd_entries_get *msg)
{
  vapi_msg_gpe_fwd_entries_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_fwd_entries_get>()
{
  return ::vapi_msg_id_gpe_fwd_entries_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_fwd_entries_get>>()
{
  return ::vapi_msg_id_gpe_fwd_entries_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_fwd_entries_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_fwd_entries_get>(vapi_msg_id_gpe_fwd_entries_get);
}

template <> inline vapi_msg_gpe_fwd_entries_get* vapi_alloc<vapi_msg_gpe_fwd_entries_get>(Connection &con)
{
  vapi_msg_gpe_fwd_entries_get* result = vapi_alloc_gpe_fwd_entries_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_fwd_entries_get>;

template class Request<vapi_msg_gpe_fwd_entries_get, vapi_msg_gpe_fwd_entries_get_reply>;

using Gpe_fwd_entries_get = Request<vapi_msg_gpe_fwd_entries_get, vapi_msg_gpe_fwd_entries_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_fwd_entries_get_reply>(vapi_msg_gpe_fwd_entries_get_reply *msg)
{
  vapi_msg_gpe_fwd_entries_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_fwd_entries_get_reply>(vapi_msg_gpe_fwd_entries_get_reply *msg)
{
  vapi_msg_gpe_fwd_entries_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_fwd_entries_get_reply>()
{
  return ::vapi_msg_id_gpe_fwd_entries_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_fwd_entries_get_reply>>()
{
  return ::vapi_msg_id_gpe_fwd_entries_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_fwd_entries_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_fwd_entries_get_reply>(vapi_msg_id_gpe_fwd_entries_get_reply);
}

template class Msg<vapi_msg_gpe_fwd_entries_get_reply>;

using Gpe_fwd_entries_get_reply = Msg<vapi_msg_gpe_fwd_entries_get_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_fwd_entry_path_dump>(vapi_msg_gpe_fwd_entry_path_dump *msg)
{
  vapi_msg_gpe_fwd_entry_path_dump_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_fwd_entry_path_dump>(vapi_msg_gpe_fwd_entry_path_dump *msg)
{
  vapi_msg_gpe_fwd_entry_path_dump_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_fwd_entry_path_dump>()
{
  return ::vapi_msg_id_gpe_fwd_entry_path_dump; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_fwd_entry_path_dump>>()
{
  return ::vapi_msg_id_gpe_fwd_entry_path_dump; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_fwd_entry_path_dump()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_fwd_entry_path_dump>(vapi_msg_id_gpe_fwd_entry_path_dump);
}

template <> inline vapi_msg_gpe_fwd_entry_path_dump* vapi_alloc<vapi_msg_gpe_fwd_entry_path_dump>(Connection &con)
{
  vapi_msg_gpe_fwd_entry_path_dump* result = vapi_alloc_gpe_fwd_entry_path_dump(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_fwd_entry_path_dump>;

template class Dump<vapi_msg_gpe_fwd_entry_path_dump, vapi_msg_gpe_fwd_entry_path_details>;

using Gpe_fwd_entry_path_dump = Dump<vapi_msg_gpe_fwd_entry_path_dump, vapi_msg_gpe_fwd_entry_path_details>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_fwd_entry_path_details>(vapi_msg_gpe_fwd_entry_path_details *msg)
{
  vapi_msg_gpe_fwd_entry_path_details_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_fwd_entry_path_details>(vapi_msg_gpe_fwd_entry_path_details *msg)
{
  vapi_msg_gpe_fwd_entry_path_details_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_fwd_entry_path_details>()
{
  return ::vapi_msg_id_gpe_fwd_entry_path_details; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_fwd_entry_path_details>>()
{
  return ::vapi_msg_id_gpe_fwd_entry_path_details; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_fwd_entry_path_details()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_fwd_entry_path_details>(vapi_msg_id_gpe_fwd_entry_path_details);
}

template class Msg<vapi_msg_gpe_fwd_entry_path_details>;

using Gpe_fwd_entry_path_details = Msg<vapi_msg_gpe_fwd_entry_path_details>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_set_encap_mode>(vapi_msg_gpe_set_encap_mode *msg)
{
  vapi_msg_gpe_set_encap_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_set_encap_mode>(vapi_msg_gpe_set_encap_mode *msg)
{
  vapi_msg_gpe_set_encap_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_set_encap_mode>()
{
  return ::vapi_msg_id_gpe_set_encap_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_set_encap_mode>>()
{
  return ::vapi_msg_id_gpe_set_encap_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_set_encap_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_set_encap_mode>(vapi_msg_id_gpe_set_encap_mode);
}

template <> inline vapi_msg_gpe_set_encap_mode* vapi_alloc<vapi_msg_gpe_set_encap_mode>(Connection &con)
{
  vapi_msg_gpe_set_encap_mode* result = vapi_alloc_gpe_set_encap_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_set_encap_mode>;

template class Request<vapi_msg_gpe_set_encap_mode, vapi_msg_gpe_set_encap_mode_reply>;

using Gpe_set_encap_mode = Request<vapi_msg_gpe_set_encap_mode, vapi_msg_gpe_set_encap_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_set_encap_mode_reply>(vapi_msg_gpe_set_encap_mode_reply *msg)
{
  vapi_msg_gpe_set_encap_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_set_encap_mode_reply>(vapi_msg_gpe_set_encap_mode_reply *msg)
{
  vapi_msg_gpe_set_encap_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_set_encap_mode_reply>()
{
  return ::vapi_msg_id_gpe_set_encap_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_set_encap_mode_reply>>()
{
  return ::vapi_msg_id_gpe_set_encap_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_set_encap_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_set_encap_mode_reply>(vapi_msg_id_gpe_set_encap_mode_reply);
}

template class Msg<vapi_msg_gpe_set_encap_mode_reply>;

using Gpe_set_encap_mode_reply = Msg<vapi_msg_gpe_set_encap_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_get_encap_mode>(vapi_msg_gpe_get_encap_mode *msg)
{
  vapi_msg_gpe_get_encap_mode_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_get_encap_mode>(vapi_msg_gpe_get_encap_mode *msg)
{
  vapi_msg_gpe_get_encap_mode_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_get_encap_mode>()
{
  return ::vapi_msg_id_gpe_get_encap_mode; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_get_encap_mode>>()
{
  return ::vapi_msg_id_gpe_get_encap_mode; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_get_encap_mode()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_get_encap_mode>(vapi_msg_id_gpe_get_encap_mode);
}

template <> inline vapi_msg_gpe_get_encap_mode* vapi_alloc<vapi_msg_gpe_get_encap_mode>(Connection &con)
{
  vapi_msg_gpe_get_encap_mode* result = vapi_alloc_gpe_get_encap_mode(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_get_encap_mode>;

template class Request<vapi_msg_gpe_get_encap_mode, vapi_msg_gpe_get_encap_mode_reply>;

using Gpe_get_encap_mode = Request<vapi_msg_gpe_get_encap_mode, vapi_msg_gpe_get_encap_mode_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_get_encap_mode_reply>(vapi_msg_gpe_get_encap_mode_reply *msg)
{
  vapi_msg_gpe_get_encap_mode_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_get_encap_mode_reply>(vapi_msg_gpe_get_encap_mode_reply *msg)
{
  vapi_msg_gpe_get_encap_mode_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_get_encap_mode_reply>()
{
  return ::vapi_msg_id_gpe_get_encap_mode_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_get_encap_mode_reply>>()
{
  return ::vapi_msg_id_gpe_get_encap_mode_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_get_encap_mode_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_get_encap_mode_reply>(vapi_msg_id_gpe_get_encap_mode_reply);
}

template class Msg<vapi_msg_gpe_get_encap_mode_reply>;

using Gpe_get_encap_mode_reply = Msg<vapi_msg_gpe_get_encap_mode_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_add_del_native_fwd_rpath>(vapi_msg_gpe_add_del_native_fwd_rpath *msg)
{
  vapi_msg_gpe_add_del_native_fwd_rpath_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_add_del_native_fwd_rpath>(vapi_msg_gpe_add_del_native_fwd_rpath *msg)
{
  vapi_msg_gpe_add_del_native_fwd_rpath_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_add_del_native_fwd_rpath>()
{
  return ::vapi_msg_id_gpe_add_del_native_fwd_rpath; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_add_del_native_fwd_rpath>>()
{
  return ::vapi_msg_id_gpe_add_del_native_fwd_rpath; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_add_del_native_fwd_rpath()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_add_del_native_fwd_rpath>(vapi_msg_id_gpe_add_del_native_fwd_rpath);
}

template <> inline vapi_msg_gpe_add_del_native_fwd_rpath* vapi_alloc<vapi_msg_gpe_add_del_native_fwd_rpath>(Connection &con)
{
  vapi_msg_gpe_add_del_native_fwd_rpath* result = vapi_alloc_gpe_add_del_native_fwd_rpath(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_add_del_native_fwd_rpath>;

template class Request<vapi_msg_gpe_add_del_native_fwd_rpath, vapi_msg_gpe_add_del_native_fwd_rpath_reply>;

using Gpe_add_del_native_fwd_rpath = Request<vapi_msg_gpe_add_del_native_fwd_rpath, vapi_msg_gpe_add_del_native_fwd_rpath_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_add_del_native_fwd_rpath_reply>(vapi_msg_gpe_add_del_native_fwd_rpath_reply *msg)
{
  vapi_msg_gpe_add_del_native_fwd_rpath_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_add_del_native_fwd_rpath_reply>(vapi_msg_gpe_add_del_native_fwd_rpath_reply *msg)
{
  vapi_msg_gpe_add_del_native_fwd_rpath_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_add_del_native_fwd_rpath_reply>()
{
  return ::vapi_msg_id_gpe_add_del_native_fwd_rpath_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_add_del_native_fwd_rpath_reply>>()
{
  return ::vapi_msg_id_gpe_add_del_native_fwd_rpath_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_add_del_native_fwd_rpath_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_add_del_native_fwd_rpath_reply>(vapi_msg_id_gpe_add_del_native_fwd_rpath_reply);
}

template class Msg<vapi_msg_gpe_add_del_native_fwd_rpath_reply>;

using Gpe_add_del_native_fwd_rpath_reply = Msg<vapi_msg_gpe_add_del_native_fwd_rpath_reply>;
template <> inline void vapi_swap_to_be<vapi_msg_gpe_native_fwd_rpaths_get>(vapi_msg_gpe_native_fwd_rpaths_get *msg)
{
  vapi_msg_gpe_native_fwd_rpaths_get_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_native_fwd_rpaths_get>(vapi_msg_gpe_native_fwd_rpaths_get *msg)
{
  vapi_msg_gpe_native_fwd_rpaths_get_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_native_fwd_rpaths_get>()
{
  return ::vapi_msg_id_gpe_native_fwd_rpaths_get; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_native_fwd_rpaths_get>>()
{
  return ::vapi_msg_id_gpe_native_fwd_rpaths_get; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_native_fwd_rpaths_get()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_native_fwd_rpaths_get>(vapi_msg_id_gpe_native_fwd_rpaths_get);
}

template <> inline vapi_msg_gpe_native_fwd_rpaths_get* vapi_alloc<vapi_msg_gpe_native_fwd_rpaths_get>(Connection &con)
{
  vapi_msg_gpe_native_fwd_rpaths_get* result = vapi_alloc_gpe_native_fwd_rpaths_get(con.vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
  con.on_shm_data_alloc(result);
#endif
  return result;
}

template class Msg<vapi_msg_gpe_native_fwd_rpaths_get>;

template class Request<vapi_msg_gpe_native_fwd_rpaths_get, vapi_msg_gpe_native_fwd_rpaths_get_reply>;

using Gpe_native_fwd_rpaths_get = Request<vapi_msg_gpe_native_fwd_rpaths_get, vapi_msg_gpe_native_fwd_rpaths_get_reply>;

template <> inline void vapi_swap_to_be<vapi_msg_gpe_native_fwd_rpaths_get_reply>(vapi_msg_gpe_native_fwd_rpaths_get_reply *msg)
{
  vapi_msg_gpe_native_fwd_rpaths_get_reply_hton(msg);
}

template <> inline void vapi_swap_to_host<vapi_msg_gpe_native_fwd_rpaths_get_reply>(vapi_msg_gpe_native_fwd_rpaths_get_reply *msg)
{
  vapi_msg_gpe_native_fwd_rpaths_get_reply_ntoh(msg);
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<vapi_msg_gpe_native_fwd_rpaths_get_reply>()
{
  return ::vapi_msg_id_gpe_native_fwd_rpaths_get_reply; 
}

template <> inline vapi_msg_id_t vapi_get_msg_id_t<Msg<vapi_msg_gpe_native_fwd_rpaths_get_reply>>()
{
  return ::vapi_msg_id_gpe_native_fwd_rpaths_get_reply; 
}

static void __attribute__((constructor)) __vapi_cpp_constructor_gpe_native_fwd_rpaths_get_reply()
{
  vapi::vapi_msg_set_msg_id<vapi_msg_gpe_native_fwd_rpaths_get_reply>(vapi_msg_id_gpe_native_fwd_rpaths_get_reply);
}

template class Msg<vapi_msg_gpe_native_fwd_rpaths_get_reply>;

using Gpe_native_fwd_rpaths_get_reply = Msg<vapi_msg_gpe_native_fwd_rpaths_get_reply>;
}
#endif
