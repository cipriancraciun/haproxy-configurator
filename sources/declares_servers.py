



from tools import *




def declare_backend_server_defaults (_configuration, _extra_statements = None) :
	_configuration.declare_group (
			"Servers",
			statement_choose_if_non_null ("$backend_server_max_connections_full_count", ("fullconn", "$+backend_server_max_connections_full_count")),
			statement_choose_if_non_null ("$backend_server_min_connections_active_count", ("default-server", "minconn", "$+backend_server_min_connections_active_count")),
			statement_choose_if_non_null ("$backend_server_max_connections_active_count", ("default-server", "maxconn", "$+backend_server_max_connections_active_count")),
			statement_choose_if_non_null ("$backend_server_max_connections_queue_count", ("default-server", "maxqueue", "$+backend_server_max_connections_queue_count")),
			statement_choose_if_non_null ("$backend_server_check_interval_normal", ("default-server", "inter", statement_seconds ("$+backend_server_check_interval_normal"))),
			statement_choose_if_non_null ("$backend_server_check_interval_rising", ("default-server", "fastinter", statement_seconds ("$+backend_server_check_interval_rising"))),
			statement_choose_if_non_null ("$backend_server_check_interval_failed", ("default-server", "downinter", statement_seconds ("$+backend_server_check_interval_failed"))),
			statement_choose_if_false ("$?backend_minimal", ("default-server", "init-addr", "none")),
			_extra_statements,
			enabled_if = "$?backend_servers_configure",
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
			enabled_if = "$?backend_timeouts_configure",
	)




