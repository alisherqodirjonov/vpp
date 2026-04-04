#ifndef included_auto_sdl_api_types_h
#define included_auto_sdl_api_types_h
#define VL_API_AUTO_SDL_API_VERSION_MAJOR 1
#define VL_API_AUTO_SDL_API_VERSION_MINOR 0
#define VL_API_AUTO_SDL_API_VERSION_PATCH 0
/* Imported API files */
typedef struct __attribute__ ((packed)) _vl_api_auto_sdl_config {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 threshold;
    u32 remove_timeout;
    bool enable;
} vl_api_auto_sdl_config_t;
#define VL_API_AUTO_SDL_CONFIG_IS_CONSTANT_SIZE (1)

typedef struct __attribute__ ((packed)) _vl_api_auto_sdl_config_reply {
    u16 _vl_msg_id;
    u32 context;
    i32 retval;
} vl_api_auto_sdl_config_reply_t;
#define VL_API_AUTO_SDL_CONFIG_REPLY_IS_CONSTANT_SIZE (1)

#define VL_API_AUTO_SDL_CONFIG_CRC "auto_sdl_config_14f30db8"
#define VL_API_AUTO_SDL_CONFIG_REPLY_CRC "auto_sdl_config_reply_e8d4e804"

#endif
