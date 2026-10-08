#include <vlib/vlib.h>
#include <vppinfra/format.h>

#include "dp_log.h"

/* dp_log_main is in dp_log.c (static there), so CLI reads only exported pieces.
 * If you want richer stats (drops per thread), export accessors or make dp_log_main non-static.
 * Here we keep it minimal: enabled flag only.
 */

static const char *
dp_log_dns_mode_name (int mode)
{
  switch (mode)
    {
    case DP_LOG_DNS_ALL:
      return "all";
    case DP_LOG_DNS_BLOCKED:
      return "blocked";
    default:
      return "off";
    }
}

static clib_error_t *
dp_log_cli_enable_disable (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  /* "dp-log dns ..." selects the DNS query log, which is switched
     independently of the ACL drop log. */
  if (unformat (input, "dns"))
    {
      if (unformat (input, "off") || unformat (input, "disable"))
	__atomic_store_n (&dp_log_dns_mode, DP_LOG_DNS_OFF, __ATOMIC_RELAXED);
      else if (unformat (input, "blocked"))
	__atomic_store_n (&dp_log_dns_mode, DP_LOG_DNS_BLOCKED,
			  __ATOMIC_RELAXED);
      else if (unformat (input, "all"))
	__atomic_store_n (&dp_log_dns_mode, DP_LOG_DNS_ALL, __ATOMIC_RELAXED);
      else
	return clib_error_return (0, "usage: dp-log dns off|blocked|all");

      vlib_cli_output (vm, "dp-log dns %s",
		       dp_log_dns_mode_name (dp_log_dns_mode_get ()));
      return 0;
    }

  /* "dp-log acl ..." widens or narrows what the ACL log covers beyond the
     per-rule log flag, which stays the primary control. */
  if (unformat (input, "acl"))
    {
      u8 bit;
      int on;

      if (unformat (input, "unmatched"))
	bit = DP_LOG_ACL_F_UNMATCHED;
      else if (unformat (input, "all-deny"))
	bit = DP_LOG_ACL_F_ALL_DENY;
      else
	return clib_error_return (
	  0, "usage: dp-log acl unmatched|all-deny on|off");

      if (unformat (input, "on") || unformat (input, "enable"))
	on = 1;
      else if (unformat (input, "off") || unformat (input, "disable"))
	on = 0;
      else
	return clib_error_return (
	  0, "usage: dp-log acl unmatched|all-deny on|off");

      if (on)
	__atomic_fetch_or (&dp_log_acl_flags, bit, __ATOMIC_RELAXED);
      else
	__atomic_fetch_and (&dp_log_acl_flags, (u8) ~bit, __ATOMIC_RELAXED);

      vlib_cli_output (vm, "dp-log acl unmatched %s, all-deny %s",
		       dp_log_acl_flags_get () & DP_LOG_ACL_F_UNMATCHED ? "on"
									: "off",
		       dp_log_acl_flags_get () & DP_LOG_ACL_F_ALL_DENY ? "on"
								       : "off");
      return 0;
    }

  if (unformat (input, "enable"))
    __atomic_store_n (&dp_log_enabled, 1, __ATOMIC_RELAXED);
  else if (unformat (input, "disable"))
    __atomic_store_n (&dp_log_enabled, 0, __ATOMIC_RELAXED);
  else
    return clib_error_return (
      0, "usage: dp-log enable|disable | dp-log dns off|blocked|all | "
	 "dp-log acl unmatched|all-deny on|off");

  vlib_cli_output (vm, "dp-log %s", dp_log_is_enabled () ? "enabled" : "disabled");
  return 0;
}

VLIB_CLI_COMMAND (dp_log_enable_disable_cmd, static) = {
  .path = "dp-log",
  .short_help = "dp-log enable|disable | dp-log dns off|blocked|all | "
		"dp-log acl unmatched|all-deny on|off",
  .function = dp_log_cli_enable_disable,
};

static clib_error_t *
dp_log_cli_show (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "dp-log:     %s",
		   dp_log_is_enabled () ? "enabled" : "disabled");
  vlib_cli_output (vm, "dp-log dns: %s",
		   dp_log_dns_mode_name (dp_log_dns_mode_get ()));
  vlib_cli_output (vm, "dp-log acl: per-rule flag always, unmatched %s, "
		       "all-deny %s",
		   dp_log_acl_flags_get () & DP_LOG_ACL_F_UNMATCHED ? "on"
								    : "off",
		   dp_log_acl_flags_get () & DP_LOG_ACL_F_ALL_DENY ? "on"
								  : "off");
  return 0;
}

VLIB_CLI_COMMAND (dp_log_show_cmd, static) = {
  .path = "show dp-log",
  .short_help = "show dp-log",
  .function = dp_log_cli_show,
};
