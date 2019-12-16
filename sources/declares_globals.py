



from tools import *




def declare_globals (_configuration) :
	declare_globals_daemon (_configuration)
	declare_globals_network (_configuration)
	declare_globals_tls (_configuration)
	declare_globals_logging (_configuration)
	declare_globals_stats (_configuration)




def declare_globals_daemon (_configuration) :
	_configuration.declare_group (
			"Identity",
			("node", "$\'daemon_node"),
			("description", "$\'daemon_description"),
			enabled_if = "$?global_identity_configure",
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
			enabled_if = "$?global_daemon_configure",
	)
	_configuration.declare_group (
			"State",
			("server-state-base", "$\'daemon_paths_states_prefix"),
			("server-state-file", "$\'daemon_paths_state_global"),
			enabled_if = "$?global_state_configure",
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
			enabled_if = "$?global_connections_configure",
	)
	_configuration.declare_group (
			"Checks",
			("max-spread-checks", 6),
			("spread-checks", 25),
			enabled_if = "$?global_checks_configure",
	)
	_configuration.declare_group (
			"Compression",
			("maxcomprate", 0),
			("maxcompcpuusage", 25),
			("maxzlibmem", 512),
			("tune.comp.maxlevel", 9),
			("tune.zlib.memlevel", 9),
			("tune.zlib.windowsize", 15),
			enabled_if = "$?global_compression_configure",
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
			enabled_if = "$?global_tune_sockets_configure",
	)
	_configuration.declare_group (
			"HTTP/2",
			("tune.h2.header-table-size", 16 * 1024),
			("tune.h2.initial-window-size", 128 * 1024),
			("tune.h2.max-concurrent-streams", "128"),
			enabled_if = "$?global_tune_http2_configure",
	)


def declare_globals_tls (_configuration) :
	_configuration.declare_group (
			"TLS default certificates",
			statement_choose_if_non_null ("$tls_ca_base", ("ca-base", "$\'tls_ca_base")),
			statement_choose_if_non_null ("$tls_ca_file", ("ca-file", "$\'tls_ca_file")),
			statement_choose_if_non_null ("$tls_crt_base", ("crt-base", "$\'tls_crt_base")),
			statement_choose_if_non_null ("$tls_crt_file", ("crt", "$\'tls_crt_file")),
			enabled_if = "$?global_tls_configure",
	)
	_configuration.declare_group (
			"TLS default configuration",
			("ssl-default-bind-ciphers", "$\'tls_ciphers_descriptor"),
			("ssl-default-bind-options", "$~tls_options"),
			("ssl-default-server-ciphers", "$\'tls_ciphers_descriptor"),
			("ssl-default-server-options", "$~tls_options"),
			("ssl-server-verify", "required"),
			statement_choose_if_non_null ("$tls_dh_params", ("ssl-dh-param-file", "$\'tls_dh_params")),
			enabled_if = "$?global_tls_configure",
	)
	_configuration.declare_group (
			"TLS advanced configuration",
			("tune.ssl.default-dh-param", 2048),
			("tune.ssl.maxrecord", 16 * 1024),
			("tune.ssl.cachesize", 128 * 1024),
			("tune.ssl.lifetime", statement_seconds (3600)),
			enabled_if = "$?global_tune_tls_configure",
	)


def declare_globals_logging (_configuration) :
	_configuration.declare_group (
			"Logging",
			statement_choose_if ("$?syslog_1_enabled", ("log", "$\'syslog_1_endpoint", "len", 65535, "format", "$\'syslog_1_protocol", "daemon", "info", "err")),
			statement_choose_if ("$?syslog_2_enabled", ("log", "$\'syslog_2_endpoint", "len", 65535, "format", "$\'syslog_2_protocol", "daemon", "info", "err")),
			statement_choose_if ("$syslog_source_node", ("log-send-hostname", "$\'syslog_source_node")),
			("log-tag", "$\'syslog_source_tag"),
			("quiet"),
			enabled_if = "$?global_logging_configure",
	)


def declare_globals_stats (_configuration) :
	_configuration.declare_group (
			"Statistics",
			statement_choose_if_non_null ("$daemon_socket", ("stats", "socket", "$\'daemon_socket", "user", "$\'daemon_user", "group", "$\'daemon_group", "mode", "0600", "level", "admin")),
			("stats", "bind-process", "all"),
			("stats", "maxconn", 4),
			("stats", "timeout", statement_seconds (60)),
			enabled_if = "$?global_stats_configure",
	)

