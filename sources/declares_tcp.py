



from tools import *

from declares_servers import *




def declare_tcp_frontend (_configuration) :
	declare_tcp_frontend_connections (_configuration)
	declare_tcp_frontend_timeouts (_configuration)
	declare_tcp_frontend_logging (_configuration)
	declare_tcp_frontend_stick (_configuration)


def declare_tcp_backend (_configuration) :
	declare_tcp_backend_connections (_configuration)
	declare_tcp_backend_check (_configuration)
	declare_tcp_backend_server_defaults (_configuration)
	declare_tcp_backend_server_timeouts (_configuration)




def declare_defaults_tcp (_configuration) :
	_configuration.declare_group (
			"TCP",
			# FIXME: ...
	)


def declare_tcp_frontend_connections (_configuration) :
	_configuration.declare_group (
			"Protocol",
			("mode", "tcp"),
			statement_choose_if ("$?frontend_enabled", "enabled", "disabled"),
			order = 2000 + 100,
		)
	_configuration.declare_group (
			"Connections",
			("maxconn", "$+frontend_max_connections_active_count"),
			("backlog", "$+frontend_max_connections_backlog_count"),
			enabled_if = "$?frontend_connections_configure",
			order = 2000 + 100,
	)


def declare_tcp_frontend_timeouts (_configuration) :
	_configuration.declare_group (
			"Timeouts",
			enabled_if = "$?frontend_timeouts_configure",
			order = 2000 + 101,
	)


def declare_tcp_frontend_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			("option", "tcplog"),
			("log-format", "$\"logging_tcp_format"),
			enabled_if = "$?frontend_logging_configure",
			order = 7000 + 400,
	)


def declare_tcp_frontend_stick (_configuration) :
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
							"bytes_in_cnt",
							"bytes_in_rate(60s)",
							"bytes_out_cnt",
							"bytes_out_rate(60s)",
						))
			),
			statement_choose_if ("$?frontend_tcp_stick_track",
				("tcp-request", "connection", "track-sc0",
						statement_choose_match ("$frontend_tcp_stick_source",
								("src", "src"),
						)
				),
			),
			enabled_if = "$?frontend_stick_configure",
			order = 5000 + 290,
		)




def declare_tcp_backend_connections (_configuration) :
	_configuration.declare_group (
			"Protocol",
			("mode", "tcp"),
			statement_choose_if ("$?backend_enabled", "enabled", "disabled"),
		)
	_configuration.declare_group (
			"Connections",
			# FIXME:  Extract this into common function!
			statement_choose_match ("$backend_balance",
					("round-robin", ("balance", "roundrobin")),
					("first", ("balance", "first")),
					(None, None)),
			enabled_if = "$?backend_connections_configure",
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




