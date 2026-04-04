#define vl_endianfun		/* define message structures */
#include "auto_sdl.api.h"
#undef vl_endianfun

#define vl_calcsizefun
#include "auto_sdl.api.h"
#undef vl_calsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include "auto_sdl.api.h"
#undef vl_printfun

#include "auto_sdl.api_json.h"
static u16
setup_message_id_table (void) {
   api_main_t *am = my_api_main;
   vl_msg_api_msg_config_t c;
   u16 msg_id_base = vl_msg_api_get_msg_ids ("auto_sdl_434063e5", VL_MSG_AUTO_SDL_LAST);
   vec_add1(am->json_api_repr, (u8 *)json_api_repr_auto_sdl);
   vl_msg_api_add_msg_name_crc (am, "auto_sdl_config_14f30db8",
                                VL_API_AUTO_SDL_CONFIG + msg_id_base);
   vl_msg_api_add_msg_name_crc (am, "auto_sdl_config_reply_e8d4e804",
                                VL_API_AUTO_SDL_CONFIG_REPLY + msg_id_base);
   c = (vl_msg_api_msg_config_t)  {.id = VL_API_AUTO_SDL_CONFIG + msg_id_base,
   .name = "auto_sdl_config",
   .handler = vl_api_auto_sdl_config_t_handler,
   .endian = vl_api_auto_sdl_config_t_endian,
   .format_fn = vl_api_auto_sdl_config_t_format,
   .traced = 1,
   .replay = 1,
   .tojson = vl_api_auto_sdl_config_t_tojson,
   .fromjson = vl_api_auto_sdl_config_t_fromjson,
   .calc_size = vl_api_auto_sdl_config_t_calc_size,
   .is_autoendian = 0};
   vl_msg_api_config (&c);
   c = (vl_msg_api_msg_config_t) {.id = VL_API_AUTO_SDL_CONFIG_REPLY + msg_id_base,
  .name = "auto_sdl_config_reply",
  .handler = 0,
  .endian = vl_api_auto_sdl_config_reply_t_endian,
  .format_fn = vl_api_auto_sdl_config_reply_t_format,
  .traced = 1,
  .replay = 1,
  .tojson = vl_api_auto_sdl_config_reply_t_tojson,
  .fromjson = vl_api_auto_sdl_config_reply_t_fromjson,
  .calc_size = vl_api_auto_sdl_config_reply_t_calc_size,
  .is_autoendian = 0};
   vl_msg_api_config (&c);
   return msg_id_base;
}
