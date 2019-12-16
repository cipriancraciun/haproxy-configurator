



from tools import *

from declares_servers import *




def declare_http_frontend (_configuration) :
	declare_http_frontend_connections (_configuration)
	declare_http_frontend_timeouts (_configuration)
	declare_http_frontend_monitor (_configuration)
	declare_http_frontend_stats (_configuration)
	declare_http_frontend_logging (_configuration)
	declare_http_frontend_stick (_configuration)


def declare_http_backend (_configuration) :
	declare_http_backend_connections (_configuration)
	declare_http_backend_check (_configuration)
	declare_http_backend_server_defaults (_configuration)
	declare_http_backend_server_timeouts (_configuration)




def declare_defaults_http (_configuration) :
	_configuration.declare_group (
			"HTTP",
			("http-reuse", "safe"),
			("http-check", "disable-on-404"),
			("http-check", "send-state"),
			("option", "http-keep-alive"),
			("max-keep-alive-queue", 0),
			("timeout", "http-request", statement_seconds ("$+defaults_timeout_request")),
			("timeout", "http-keep-alive", statement_seconds ("$+defaults_timeout_keep_alive")),
			("unique-id-format", "#\"%[req.hdr(X-HA-Request-Id)]"),
			("unique-id-header", "#\'X-HA-Request-Id-2"),
			enabled_if = "$?defaults_http_configure",
	)
	_configuration.declare_group (
			"HTTP compression",
			("compression", "algo", "gzip"),
			("compression", "type", "$\'defaults_compression_content_types"),
			statement_choose_if ("$?defaults_compression_offload",
				("compression", "offload")),
			enabled_if = statement_and ("$?defaults_http_configure", "$?defaults_compression_configure"),
	)


def declare_http_frontend_connections (_configuration) :
	_configuration.declare_group (
			"Protocol",
			("mode", "http"),
			statement_choose_if ("$?frontend_enabled", "enabled", "disabled"),
			order = 2000 + 100,
		)
	_configuration.declare_group (
			"Connections",
			("maxconn", "$+frontend_max_connections_active_count"),
			("backlog", "$+frontend_max_connections_backlog_count"),
			# FIXME:  Verify that this is actually not allowed!
			#statement_choose_match ("$frontend_http_keep_alive_reuse",
			#		("safe", ("http-reuse", "safe")),
			#		("aggressive", ("http-reuse", "aggressive")),
			#		("always", ("http-reuse", "always")),
			#		("never", ("http-reuse", "never"))),
			statement_choose_match ("$frontend_http_keep_alive_mode",
					("keep-alive", ("option", "http-keep-alive")),
					("close", ("option", "forceclose"))),
			enabled_if = "$?frontend_connections_configure",
			order = 2000 + 100,
	)


def declare_http_frontend_timeouts (_configuration) :
	_configuration.declare_group (
			"Timeouts",
			statement_choose_if_non_null ("$frontend_http_keep_alive_timeout", ("timeout", "http-keep-alive", statement_seconds ("$+frontend_http_keep_alive_timeout"))),
			enabled_if = "$?frontend_timeouts_configure",
			order = 2000 + 101,
	)


def declare_http_frontend_monitor (_configuration) :
	_configuration.declare_group (
			"Monitoring",
			("monitor-uri", "$\'frontend_monitor_path"),
			("monitor-net", "$\'frontend_monitor_network"),
			("monitor", "fail", "if", "$~frontend_monitor_fail_acl"),
			enabled_if = statement_and ("$?frontend_monitor_enabled", "$?frontend_monitor_configure"),
			order = 7000 + 100,
	)


def declare_http_frontend_stats (_configuration) :
	_configuration.declare_group (
			"Stats",
			("stats", "enable"),
			("stats", "uri", "$\'frontend_stats_path"),
			("stats", "realm", "$\'frontend_stats_auth_realm"),
			statement_choose_if_non_null ("$frontend_stats_auth_credentials", ("stats", "auth", "$\'frontend_stats_auth_credentials")),
			statement_choose_if_non_null ("$frontend_stats_admin_acl", ("stats", "admin", "if", "$~frontend_stats_admin_acl")),
			("stats", "show-node", "$\'daemon_node"),
			("stats", "show-desc", "$\'daemon_description"),
			("stats", "show-legends"),
			statement_choose_if_false ("$?frontend_stats_version", ("stats", "hide-version")),
			("stats", "refresh", statement_seconds ("$+frontend_stats_refresh")),
			enabled_if = statement_and ("$?frontend_stats_enabled", "$?frontend_stats_configure"),
			order = 7000 + 200,
	)


def declare_http_frontend_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			("option", "httplog"),
			("log-format", "$\"logging_http_format"),
			enabled_if = "$?frontend_logging_configure",
			order = 7000 + 400,
	)


def declare_http_frontend_stick (_configuration) :
	# FIXME:  Make this configurable!
	_configuration.declare_group (
			"Stick tables",
			("stick-table",
					"type", "ip",
					"size", 1024 * 1024,
					"expire", "3600s",
					"store", ",".join ((
							"conn_cur",
							"conn_cnt",
							"conn_rate(60s)",
							"sess_cnt",
							"sess_rate(60s)",
							"http_req_cnt",
							"http_req_rate(60s)",
							"http_err_cnt",
							"http_err_rate(60s)",
							"bytes_in_cnt",
							"bytes_in_rate(60s)",
							"bytes_out_cnt",
							"bytes_out_rate(60s)",
						))
			),
			statement_choose_if ("$?frontend_http_stick_track",
				("http-request", "track-sc0",
						statement_choose_match ("$frontend_http_stick_source",
								("src", "src"),
								("X-Forwarded-For", statement_format ("req.hdr(%s,1)", "$logging_http_header_forwarded_for")),
						)
				),
			),
			enabled_if = "$?frontend_stick_configure",
			order = 5000 + 290,
		)




def declare_http_backend_connections (_configuration) :
	_configuration.declare_group (
			"Protocol",
			("mode", "http"),
			statement_choose_if ("$?backend_enabled", "enabled", "disabled"),
		)
	_configuration.declare_group (
			"Connections",
			# FIXME:  Extract this into common function!
			statement_choose_match ("$backend_balance",
					("round-robin", ("balance", "roundrobin")),
					("first", ("balance", "first")),
					(None, None)),
			statement_choose_match ("$backend_http_keep_alive_reuse",
					("safe", ("http-reuse", "safe")),
					("aggressive", ("http-reuse", "aggressive")),
					("always", ("http-reuse", "always")),
					("never", ("http-reuse", "never"))),
			statement_choose_match ("$backend_http_keep_alive_mode",
					("keep-alive", ("option", "http-keep-alive")),
					("server-close", ("option", "http-server-close")),
					("close", ("option", "forceclose"))),
			# FIXME:  Make this configurable!
			("option", "forwardfor", "header", "$logging_http_header_forwarded_for", "if-none"),
			enabled_if = "$?backend_connections_configure",
	)


def declare_http_backend_check (_configuration) :
	_configuration.declare_group (
			"Check",
			("option", "httpchk", "$\'backend_http_check_request_method", "$\'backend_http_check_request_uri", "$\'backend_http_check_request_extra"),
			("http-check", "expect", "$~backend_http_check_expect_matcher", "$\'backend_http_check_expect_pattern"),
			enabled_if = statement_and ("$?backend_http_check_enabled", "$?backend_check_configure"),
	)


def declare_http_backend_server_defaults (_configuration) :
	declare_backend_server_defaults (_configuration, [
			# FIXME: ...
	])


def declare_http_backend_server_timeouts (_configuration) :
	declare_backend_server_timeouts (_configuration, [
			statement_choose_if_non_null ("$backend_server_timeout_request", ("timeout", "http-request", statement_seconds ("$+backend_server_timeout_request"))),
			statement_choose_if_non_null ("$backend_server_timeout_keep_alive", ("timeout", "http-keep-alive", statement_seconds ("$+backend_server_timeout_keep_alive"))),
			statement_choose_if_non_null ("$backend_http_keep_alive_timeout", ("timeout", "http-keep-alive", statement_seconds ("$+backend_http_keep_alive_timeout"))),
	])




