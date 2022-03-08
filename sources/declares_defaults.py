



from tools import *

from declares_http import *
from declares_tcp import *




def declare_defaults (_configuration) :
	declare_defaults_network (_configuration)
	declare_defaults_timeouts (_configuration)
	declare_defaults_servers (_configuration)
	declare_defaults_http (_configuration)
	declare_defaults_tcp (_configuration)
	declare_defaults_logging (_configuration)
	declare_defaults_stats (_configuration)
	declare_defaults_error_pages (_configuration)
	declare_defaults_miscellaneous (_configuration)




def declare_defaults_network (_configuration) :
	_configuration.declare_group (
			"Protocol",
			("mode", "tcp"),
			statement_choose_if_false ("$?minimal_configure", "disabled"),
		)
	_configuration.declare_group (
			"Connections",
			("maxconn", "$+defaults_frontend_max_connections_active_count"),
			("backlog", "$+defaults_frontend_max_connections_backlog_count"),
			("rate-limit", "sessions", "$+defaults_frontend_max_sessions_rate"),
			("balance", "roundrobin"),
			("retries", "4"),
			enabled_if = "$?defaults_connections_configure",
	)
	_configuration.declare_group (
			"Connections TCP-Keep-Alive",
			("option", "clitcpka"),
			("option", "srvtcpka"),
			enabled_if = "$?defaults_connections_configure",
	)
	_configuration.declare_group (
			"Connections splicing",
			("option", "splice-request"),
			("option", "splice-response"),
			("no", "option", "splice-auto"),
			enabled_if = "$?defaults_connections_configure",
	)


def declare_defaults_timeouts (_configuration) :
	_configuration.declare_group (
			"Timeouts",
			("timeout", "server", statement_seconds ("$+defaults_timeout_activity_server")),
			("timeout", "server-fin", statement_seconds ("$+defaults_timeout_fin")),
			("timeout", "client", statement_seconds ("$+defaults_timeout_activity_client")),
			("timeout", "client-fin", statement_seconds ("$+defaults_timeout_fin")),
			("timeout", "tunnel", statement_seconds ("$+defaults_timeout_activity_tunnel")),
			("timeout", "connect", statement_seconds ("$+defaults_timeout_connect")),
			("timeout", "queue", statement_seconds ("$+defaults_timeout_queue")),
			("timeout", "check", statement_seconds ("$+defaults_timeout_check")),
			("timeout", "tarpit", statement_seconds ("$+defaults_timeout_tarpit")),
			enabled_if = "$?defaults_timeouts_configure",
	)


def declare_defaults_servers (_configuration) :
	_configuration.declare_group (
			"Servers",
			("fullconn", "$+defaults_server_max_connections_full_count"),
			("default-server", "minconn", "$+defaults_server_min_connections_active_count"),
			("default-server", "maxconn", "$+defaults_server_max_connections_active_count"),
			("default-server", "maxqueue", "$+defaults_server_max_connections_queue_count"),
			("default-server", "inter", statement_seconds ("$+defaults_server_check_interval_normal")),
			("default-server", "fastinter", statement_seconds ("$+defaults_server_check_interval_rising")),
			("default-server", "downinter", statement_seconds ("$+defaults_server_check_interval_failed")),
			("default-server", "rise", "$+defaults_server_check_count_rising"),
			("default-server", "fall", "$+defaults_server_check_count_failed"),
			("default-server", "on-error", "fastinter"),
			("default-server", "error-limit", "$+defaults_server_check_count_errors"),
			enabled_if = "$?defaults_servers_configure",
	)


def declare_defaults_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			statement_choose_if ("$?syslog_pg_enabled",
					("log", "global")),
			statement_choose_if ("$?syslog_p_enabled",
					("log", "$\'syslog_p_endpoint", "len", 65535, "format", "$\'syslog_p_protocol", "daemon", "info", "err")),
			("option", "log-separate-errors"),
			("option", "log-health-checks"),
			("no", "option", "checkcache"),
			("no", "option", "dontlognull"),
			enabled_if = "$?defaults_logging_configure",
	)


def declare_defaults_stats (_configuration) :
	_configuration.declare_group (
			"Stats",
			("option", "contstats"),
			("option", "socket-stats"),
			enabled_if = "$?defaults_stats_configure",
	)


def declare_defaults_error_pages (_configuration) :
	_configuration.declare_group (
			"Error pages",
			("errorfile", 200, statement_quote ("\'", statement_format ("%s/monitor.http", "$error_pages_store"))),
			# FIXME:  Make this deferable!
			[
				("errorfile", statement_enforce_int (_code), statement_quote ("\'", statement_format ("%s/%d.http", "$error_pages_store", _code)))
				for _code in _configuration._resolve_token ("$error_pages_codes")
			],
			enabled_if = statement_and ("$?error_pages_enabled", "$?defaults_errors_configure"),
	)


def declare_defaults_miscellaneous (_configuration) :
	_configuration.declare_group (
			"State",
			# FIXME:  Add `server-state-file-name`!
			("load-server-state-from-file", "global"),
			enabled_if = "$?defaults_state_configure",
	)




