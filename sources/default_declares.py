



from errors import *
from tools import *




def declare_globals (_configuration) :
	declare_globals_daemon (_configuration)
	declare_globals_network (_configuration)
	declare_globals_tls (_configuration)
	declare_globals_logging (_configuration)
	declare_globals_stats (_configuration)


def declare_defaults (_configuration) :
	declare_defaults_network (_configuration)
	declare_defaults_timeouts (_configuration)
	declare_defaults_servers (_configuration)
	declare_defaults_http (_configuration)
	declare_defaults_logging (_configuration)
	declare_defaults_stats (_configuration)
	declare_defaults_error_pages (_configuration)
	declare_defaults_miscellaneous (_configuration)


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


def declare_tcp_backend (_configuration) :
	declare_tcp_backend_connections (_configuration)
	declare_tcp_backend_check (_configuration)
	declare_tcp_backend_server_defaults (_configuration)
	declare_tcp_backend_server_timeouts (_configuration)




def declare_globals_daemon (_configuration) :
	_configuration.declare_group (
			"Identity",
			("node", "$\'daemon_node"),
			("description", "$\'daemon_description"),
	)
	_configuration.declare_group (
			"Daemon",
			("nbproc", "$+daemon_processes_count"),
			("nbthread", "$+daemon_threads_count"),
			statement_choose_if_non_null ("$~daemon_processes_affinity", ("cpu-map", "$~daemon_processes_affinity")),
			statement_choose_if_non_null ("$+daemon_ulimit", ("ulimit-n", "$+daemon_ulimit")),
			("user", "$\'daemon_user"),
			("group", "$\'daemon_group"),
			("pidfile", "$\'daemon_pid"),
			statement_choose_if ("$?daemon_chroot_enabled", ("chroot", "$\'daemon_chroot")),
			("server-state-base", "$\'daemon_paths_states_prefix"),
			("server-state-file", "$\'daemon_paths_state_global"),
	)


def declare_globals_network (_configuration) :
	_configuration.declare_group (
			"Connections",
			("maxconn", "$+global_max_connections_count"),
			("maxconnrate", "$+global_max_connections_rate"),
			("maxsessrate", "$+global_max_sessions_rate"),
			("maxsslconn", "$+global_max_tls_connections_count"),
			("maxsslrate", "$+global_max_tls_connections_rate"),
			("maxpipes", "$+global_max_pipes"),
	)
	_configuration.declare_group (
			"Checks",
			("max-spread-checks", 6),
			("spread-checks", 25),
	)
	_configuration.declare_group (
			"Compression",
			("maxcomprate", 0),
			("maxcompcpuusage", 25),
			("maxzlibmem", 512),
			("tune.comp.maxlevel", 9),
			("tune.zlib.memlevel", 9),
			("tune.zlib.windowsize", 15),
	)
	_configuration.declare_group (
			"Sockets",
			("tune.bufsize", 128 * 1024),
			("tune.maxrewrite", 16 * 1024),
			#("tune.rcvbuf.client", 128 * 1024),
			# FIXME:  Why do this break the dowload speed?
			##("tune.sndbuf.client", 16 * 1024),
			#("tune.rcvbuf.server", 128 * 1024),
			#("tune.sndbuf.server", 128 * 1024),
			#("tune.pipesize", 128 * 1024),
			#("tune.idletimer", 1000),
	)
	_configuration.declare_group (
			"HTTP/2",
			("tune.h2.header-table-size", 16 * 1024),
			("tune.h2.initial-window-size", 128 * 1024),
			("tune.h2.max-concurrent-streams", "128"),
	)


def declare_globals_tls (_configuration) :
	_configuration.declare_group (
			"TLS default certificates",
			statement_choose_if_non_null ("$tls_ca_base", ("ca-base", "$\'tls_ca_base")),
			statement_choose_if_non_null ("$tls_crt_base", ("crt-base", "$\'tls_crt_base")),
	)
	_configuration.declare_group (
			"TLS default configuration",
			("ssl-default-bind-ciphers", "$\'tls_ciphers_descriptor"),
			("ssl-default-bind-options", "$~tls_options"),
			("ssl-default-server-ciphers", "$\'tls_ciphers_descriptor"),
			("ssl-default-server-options", "$~tls_options"),
			("ssl-server-verify", "required"),
			statement_choose_if_non_null ("$tls_dh_params", ("ssl-dh-param-file", "$\'tls_dh_params")),
	)
	_configuration.declare_group (
			"TLS advanced configuration",
			("tune.ssl.default-dh-param", 2048),
			("tune.ssl.maxrecord", 16 * 1024),
			("tune.ssl.cachesize", 262144),
			("tune.ssl.lifetime", statement_seconds (3600)),
	)


def declare_globals_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			statement_choose_if ("$?syslog_1_enabled", ("log", "$\'syslog_1_endpoint", "len", 65535, "format", "$\'syslog_1_protocol", "daemon", "info", "err")),
			statement_choose_if ("$?syslog_2_enabled", ("log", "$\'syslog_2_endpoint", "len", 65535, "format", "$\'syslog_2_protocol", "daemon", "info", "err")),
			statement_choose_if ("$syslog_source_node", ("log-send-hostname", "$\'syslog_source_node")),
			("log-tag", "$\'syslog_source_tag"),
			("quiet"),
	)


def declare_globals_stats (_configuration) :
	_configuration.declare_group (
			"Statistics",
			statement_choose_if_non_null ("$daemon_socket", ("stats", "socket", "$\'daemon_socket", "user", "$\'daemon_user", "group", "$\'daemon_group", "mode", "0600", "level", "admin")),
			("stats", "bind-process", "all"),
			("stats", "maxconn", 4),
			("stats", "timeout", statement_seconds (60)),
	)




def declare_defaults_network (_configuration) :
	_configuration.declare_group (
			"Connections",
			("disabled"),
			("mode", "tcp"),
			("bind-process", "all"),
			("maxconn", "$+defaults_frontend_max_connections_active_count"),
			("backlog", "$+defaults_frontend_max_connections_backlog_count"),
			("rate-limit", "sessions", "$+defaults_frontend_max_sessions_rate"),
			("balance", "roundrobin"),
			("retries", "4"),
	)
	if True :
		_configuration.declare_group (
				"Connections splicing",
				("option", "splice-request"),
				("option", "splice-response"),
				("no", "option", "splice-auto"),
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
	)


def declare_defaults_servers (_configuration) :
	_configuration.declare_group (
			"Servers",
			("default-server", "maxconn", "$+defaults_server_max_connections_active_count"),
			("default-server", "maxqueue", "$+defaults_server_max_connections_queue_count"),
			("default-server", "inter", statement_seconds ("$+defaults_server_check_interval_normal")),
			("default-server", "fastinter", statement_seconds ("$+defaults_server_check_interval_rising")),
			("default-server", "downinter", statement_seconds ("$+defaults_server_check_interval_failed")),
			("default-server", "rise", "$+defaults_server_check_count_rising"),
			("default-server", "fall", "$+defaults_server_check_count_failed"),
			("default-server", "on-error", "fastinter"),
			("default-server", "error-limit", "$+defaults_server_check_count_errors"),
	)


def declare_defaults_http (_configuration) :
	_configuration.declare_group (
			"HTTP",
			("http-reuse", "safe"),
			("http-check", "disable-on-404"),
			("http-check", "send-state"),
			("timeout", "http-request", statement_seconds ("$+defaults_timeout_request")),
			("timeout", "http-keep-alive", statement_seconds ("$+defaults_timeout_keep_alive")),
			("unique-id-format", "#\"%[req.hdr(X-HA-Request-Id)]"),
			("unique-id-header", "#\'X-HA-Request-Id-2"),
	)
	_configuration.declare_group (
			"HTTP compression",
			("compression", "algo", "gzip", "deflate"),
			("compression", "type", "$\'defaults_compression_content_types"),
			("compression", "offload"),
	)


def declare_defaults_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			("log", "global"),
			("option", "log-separate-errors"),
			("option", "log-health-checks"),
			("no", "option", "checkcache"),
			("no", "option", "dontlognull"),
	)


def declare_defaults_stats (_configuration) :
	_configuration.declare_group (
			"Stats",
			("option", "contstats"),
			("option", "socket-stats"),
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
			enabled_if = "$?error_pages_enabled",
	)


def declare_defaults_miscellaneous (_configuration) :
	_configuration.declare_group (
			"Miscellaneous",
			("option", "clitcpka"),
			("option", "srvtcpka"),
			("load-server-state-from-file", "global"),
			# FIXME:  Add `server-state-file-name`!
	)




def declare_http_frontend_connections (_configuration) :
	_configuration.declare_group (
			"Connections",
			statement_choose_if ("$?frontend_enabled", "enabled", "disabled"),
			("maxconn", "$+frontend_max_connections_active_count"),
			("backlog", "$+frontend_max_connections_backlog_count"),
			("mode", "http"),
			statement_choose_match ("$frontend_http_keep_alive_reuse",
					("safe", ("http-reuse", "safe")),
					("aggressive", ("http-reuse", "aggressive")),
					("always", ("http-reuse", "always")),
					("never", ("http-reuse", "never"))),
			statement_choose_match ("$frontend_http_keep_alive_mode",
					("keep-alive", ("option", "http-keep-alive")),
					("close", ("option", "forceclose"))),
			order = 2000 + 100,
	)


def declare_http_frontend_timeouts (_configuration) :
	_configuration.declare_group (
			"Timeouts",
			statement_choose_if_non_null ("$frontend_http_keep_alive_timeout", ("timeout", "http-keep-alive", statement_seconds ("$+frontend_http_keep_alive_timeout"))),
			order = 2000 + 101,
	)


def declare_http_frontend_monitor (_configuration) :
	_configuration.declare_group (
			"Monitoring",
			("monitor-uri", "$\'frontend_monitor_path"),
			("monitor-net", "$\'frontend_monitor_network"),
			("monitor", "fail", "if", "$~frontend_monitor_fail_acl"),
			enabled_if = statement_and ("$?frontend_monitor_enabled", "$?!frontend_minimal"),
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
			enabled_if = statement_and ("$?frontend_stats_enabled", "$?!frontend_minimal"),
			order = 7000 + 200,
	)


def declare_http_frontend_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			("option", "httplog"),
			("log-format", "$\"logging_http_format"),
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
								("source", "src"),
								("X-Forwarded-For", statement_format ("req.hdr(%s,1)", "$logging_http_header_forwarded_for")),
						)
				),
			),
			order = 5000 + 290,
		)




def declare_http_backend_connections (_configuration) :
	_configuration.declare_group (
			"Connections",
			statement_choose_if ("$?backend_enabled", "enabled", "disabled"),
			("mode", "http"),
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
	)

def declare_http_backend_check (_configuration) :
	_configuration.declare_group (
			"Check",
			("option", "httpchk", "$\'backend_http_check_request_method", "$\'backend_http_check_request_uri", "$\'backend_http_check_request_extra"),
			("http-check", "expect", "$~backend_http_check_expect_matcher", "$\'backend_http_check_expect_pattern"),
			enabled_if = "$?backend_http_check_enabled",
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




def declare_tcp_backend_connections (_configuration) :
	_configuration.declare_group (
			"Connections",
			statement_choose_if ("$?backend_enabled", "enabled", "disabled"),
			("mode", "tcp"),
			# FIXME:  Extract this into common function!
			statement_choose_match ("$backend_balance",
					("round-robin", ("balance", "roundrobin")),
					("first", ("balance", "first")),
					(None, None)),
	)

def declare_tcp_backend_check (_configuration) :
	# FIXME: ...
	pass

def declare_tcp_backend_server_defaults (_configuration) :
	declare_backend_server_defaults (_configuration, [
			# FIXME: ...
	])

def declare_tcp_backend_server_timeouts (_configuration) :
	declare_backend_server_timeouts (_configuration, [
			# FIXME: ...
	])




def declare_backend_server_defaults (_configuration, _extra_statements = None) :
	_configuration.declare_group (
			"Servers",
			statement_choose_if_non_null ("$backend_server_max_connections_active_count", ("default-server", "maxconn", "$+backend_server_max_connections_active_count")),
			statement_choose_if_non_null ("$backend_server_max_connections_queue_count", ("default-server", "maxqueue", "$+backend_server_max_connections_queue_count")),
			statement_choose_if_non_null ("$backend_server_check_interval_normal", ("default-server", "inter", statement_seconds ("$+backend_server_check_interval_normal"))),
			statement_choose_if_non_null ("$backend_server_check_interval_rising", ("default-server", "fastinter", statement_seconds ("$+backend_server_check_interval_rising"))),
			statement_choose_if_non_null ("$backend_server_check_interval_failed", ("default-server", "downinter", statement_seconds ("$+backend_server_check_interval_failed"))),
			_extra_statements
	)

def declare_backend_server_timeouts (_configuration, _extra_statements = None) :
	_configuration.declare_group (
			"Timeouts",
			statement_choose_if_non_null ("$backend_server_timeout_activity_server", ("timeout", "server", statement_seconds ("$+backend_server_timeout_activity_server"))),
			statement_choose_if_non_null ("$backend_server_timeout_fin", ("timeout", "server-fin", statement_seconds ("$+backend_server_timeout_fin"))),
			statement_choose_if_non_null ("$backend_server_timeout_activity_client", ("timeout", "client", statement_seconds ("$+backend_server_timeout_activity_client"))),
			statement_choose_if_non_null ("$backend_server_timeout_fin", ("timeout", "client-fin", statement_seconds ("$+backend_server_timeout_fin"))),
			statement_choose_if_non_null ("$backend_server_timeout_activity_tunnel", ("timeout", "tunnel", statement_seconds ("$+backend_server_timeout_activity_tunnel"))),
			statement_choose_if_non_null ("$backend_server_timeout_connect", ("timeout", "connect", statement_seconds ("$+backend_server_timeout_connect"))),
			statement_choose_if_non_null ("$backend_server_timeout_queue", ("timeout", "queue", statement_seconds ("$+backend_server_timeout_queue"))),
			statement_choose_if_non_null ("$backend_server_timeout_check", ("timeout", "check", statement_seconds ("$+backend_server_timeout_check"))),
			statement_choose_if_non_null ("$backend_server_timeout_tarpit", ("timeout", "tarpit", statement_seconds ("$+backend_server_timeout_tarpit"))),
			_extra_statements,
	)




