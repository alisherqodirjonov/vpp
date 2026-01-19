#include <vlib/vlib.h>
#include <vppinfra/format.h>

#include "dp_log.h"

/* dp_log_main is in dp_log.c (static there), so CLI reads only exported pieces.
 * If you want richer stats (drops per thread), export accessors or make dp_log_main non-static.
 * Here we keep it minimal: enabled flag only.
 */

static clib_error_t *
dp_log_cli_enable_disable (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (unformat (input, "enable"))
    __atomic_store_n (&dp_log_enabled, 1, __ATOMIC_RELAXED);
  else if (unformat (input, "disable"))
    __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
  else
    return clib_error_return (0, "usage: dp-log enable|disable");

  vlib_cli_output (vm, "dp-log %s", dp_log_is_enabled () ? "enabled" : "disabled");
  return 0;
}

VLIB_CLI_COMMAND (dp_log_enable_disable_cmd, static) = {
  .path = "dp-log",
  .short_help = "dp-log enable|disable",
  .function = dp_log_cli_enable_disable,
};

static clib_error_t *
dp_log_cli_show (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "dp-log: %s", dp_log_is_enabled () ? "enabled" : "disabled");
  return 0;
}

VLIB_CLI_COMMAND (dp_log_show_cmd, static) = {
  .path = "show dp-log",
  .short_help = "show dp-log",
  .function = dp_log_cli_show,
};
