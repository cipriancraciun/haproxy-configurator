



from errors import *
from tools import *




tls_mode = "normal"

tls_ciphers_paranoid = (
	
		"ECDHE-RSA-CHACHA20-POLY1305",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES256-SHA384",
		"ECDHE-RSA-AES128-SHA256",
	)

tls_ciphers_normal = (
		
		"ECDHE-RSA-CHACHA20-POLY1305",
		
		"ECDHE-RSA-AES256-GCM-SHA384",
		"ECDHE-RSA-AES256-SHA384",
		
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES128-SHA256",
		
		"DHE-RSA-AES256-GCM-SHA384",
		"DHE-RSA-AES256-SHA256",
		
		"DHE-RSA-AES128-GCM-SHA256",
		"DHE-RSA-AES128-SHA256",
		
		"ECDHE-RSA-AES256-SHA",
		"DHE-RSA-AES256-SHA",
		
		"ECDHE-RSA-AES128-SHA",
		"DHE-RSA-AES128-SHA",
		
		"ECDHE-RSA-DES-CBC3-SHA",
		"EDH-RSA-DES-CBC3-SHA",
		
		"AES256-GCM-SHA384",
		"AES256-SHA256",
		
		"AES128-GCM-SHA256",
		"AES128-SHA256",
		
		"AES256-SHA",
		"AES128-SHA",
		
		"DES-CBC3-SHA",
		
	)

tls_ciphers_backdoor = (
		
		# "AES256-GCM-SHA384",
		"AES256-SHA256",
		
		# "AES128-GCM-SHA256",
		"AES128-SHA256",
		
		"AES256-SHA",
		"AES128-SHA",
		
		# "DES-CBC3-SHA",
		
)


tls_options_paranoid = (
		"no-tlsv11",
		"no-tlsv10",
		"no-sslv3",
		"no-tls-tickets",
		"strict-sni",
		# FIXME:  ???
		# ("ecdhe", "prime256v1"),
	)

tls_options_normal = (
		"no-sslv3",
		"no-tls-tickets",
		# FIXME:  ???
		# ("ecdhe", "prime256v1"),
	)

tls_options_backdoor = tls_options_normal




http_status_codes = {
		
		"content_standard" : (200, 201, 202, 204, 206,),
		"content_strict" : (200, 204,),
		"redirect" : (301, 302, 303, 307, 308,),
		"caching" : (304,),
		
		"get_standard" : (200, 204, 206,),
		"get_strict" : (200, 304,),
		"get_redirect" : (301, 302,),
		"get_caching" : (304,),
		
		"post_strict" : (200, 201, 202, 204,),
		"post_standard" : (200, 201, 202, 204,),
		"post_redirect" : (303,),
		"post_caching" : (),
	}


http_status_codes["harden_allowed_strict"] = \
	tuple (
		list (http_status_codes["content_strict"]) +
		list (http_status_codes["redirect"]) +
		list (http_status_codes["caching"])
	)

http_status_codes["harden_allowed_standard"] = \
	tuple (
		list (http_status_codes["content_standard"]) +
		list (http_status_codes["redirect"]) +
		list (http_status_codes["caching"])
	)


http_status_codes["harden_allowed_get_strict"] = \
	tuple (
		list (http_status_codes["get_strict"]) +
		list (http_status_codes["get_redirect"]) +
		list (http_status_codes["get_caching"])
	)

http_status_codes["harden_allowed_get_standard"] = \
	tuple (
		list (http_status_codes["get_standard"]) +
		list (http_status_codes["get_redirect"]) +
		list (http_status_codes["get_caching"])
	)


http_status_codes["harden_allowed_post_strict"] = \
	tuple (
		list (http_status_codes["post_strict"]) +
		list (http_status_codes["post_redirect"]) +
		list (http_status_codes["post_caching"])
	)

http_status_codes["harden_allowed_post_standard"] = \
	tuple (
		list (http_status_codes["post_standard"]) +
		list (http_status_codes["post_redirect"]) +
		list (http_status_codes["post_caching"])
	)




compression_content_types = (
		
		"text/html",
		"text/css",
		"application/javascript", "text/javascript",
		
		"application/xml", "text/xml",
		"application/xhtml+xml",
		"application/rss+xml", "application/atom+xml",
		
		"application/json", "text/json",
		
		"text/plain",
		"text/csv",
		"text/tab-separated-values",
		
		"image/svg+xml",
		"image/vnd.microsoft.icon", "image/x-icon",
		
		"font/collection",
		"font/otf", "application/font-otf", "application/x-font-otf", "application/x-font-opentype",
		"font/ttf", "application/font-ttf", "application/x-font-ttf", "application/x-font-truetype",
		"font/sfnt", "application/font-sfnt", "application/x-font-sfnt",
		"font/woff", "application/font-woff", "application/x-font-woff",
		"font/woff2", "application/font-woff2", "application/x-font-woff2",
		"font/eot", "application/font-eot", "application/x-font-eot", "application/vnd.ms-fontobject",
		
	)




logging_type = "json"

logging_tcp_format_text = """{tcp:20161201:01} f-id:%f b-id:%b,%s c-sck:%ci,%cp f-sck:%fi,%fp b-sck:%bi,%bp s-sck:%si,%sp i-sz:%U o-sz:%B w:%Ts.%ms,%Tw,%Tc,%Tt f-cnt:%ac,%fc,%bc,%sc,%rc,%ts b-cnt:%bq,%sq g-cnt:%lc,%rt ssl:%sslv,%sslc ssl-x:%[ssl_fc],%[ssl_fc_protocol],%[ssl_fc_cipher],%[ssl_fc_unique_id,hex],%[ssl_fc_session_id,hex],%[ssl_fc_is_resumed],%[ssl_fc_has_sni],[%{Q}[ssl_fc_sni]],[%{Q}[ssl_fc_alpn]],[%{Q}[ssl_fc_npn]] ssl-xf:%[ssl_fc],%[ssl_f_version],%[ssl_f_sha1,hex],[%{Q}[ssl_f_s_dn]] ssl-xc:%[ssl_c_used],%[ssl_c_version],%[ssl_c_sha1,hex],%[ssl_c_verify],%[ssl_c_err],%[ssl_c_ca_err],%[ssl_c_ca_err_depth],[%{Q}[ssl_c_s_dn]],[%{Q}[ssl_c_i_dn]]"""
logging_http_format_text = """{http:20161201:01} h-v:[%{Q}HV] h-m:[%{Q}HM] h-p:[%{Q}HP] h-q:[%{Q}HQ] h-s:%ST f-id:%f b-id:%b,%s c-sck:%ci,%cp f-sck:%fi,%fp b-sck:%bi,%bp s-sck:%si,%sp h-r-id:[%{Q}ID] h-i-hdr:[%{Q}hrl] h-o-hdr:[%{Q}hsl] h-i-ck:[%{Q}CC] h-o-ck:[%{Q}CS] i-sz:%U o-sz:%B w:%Ts.%ms,%Tq,%Tw,%Tc,%Tr,%Tt f-cnt:%ac,%fc,%bc,%sc,%rc,%tsc b-cnt:%bq,%sq g-cnt:%lc,%rt ssl:%sslv,%sslc ssl-x:%[ssl_fc],%[ssl_fc_protocol],%[ssl_fc_cipher],%[ssl_fc_unique_id,hex],%[ssl_fc_session_id,hex],%[ssl_fc_is_resumed],%[ssl_fc_has_sni],[%{Q}[ssl_fc_sni]],[%{Q}[ssl_fc_alpn]],[%{Q}[ssl_fc_npn]] ssl-xf:%[ssl_fc],%[ssl_f_version],%[ssl_f_sha1,hex],[%{Q}[ssl_f_s_dn]] ssl-xc:%[ssl_c_used],%[ssl_c_version],%[ssl_c_sha1,hex],%[ssl_c_verify],%[ssl_c_err],%[ssl_c_ca_err],%[ssl_c_ca_err_depth],[%{Q}[ssl_c_s_dn]],[%{Q}[ssl_c_i_dn]]"""




def _expand_logging_format_json (_format, _parameters) :
	
	def _expand_value (_value) :
		if isinstance (_value, basestring) :
			_token = list ()
			if _value.startswith ("=") :
				_token.append (_value[1:])
			elif _value.startswith ("'") or _value.startswith ("+") :
				_quote = (_value[0] == "'")
				_value = _value[1:]
				if _quote :
					_token.append ("\"")
				if _value.startswith ("%") :
					if _quote :
						_token.append ("%{Q}")
					else :
						_token.append ("%")
					_token.append (_value[1:])
				elif _value.startswith ("@") :
					_token.append ("%[")
					_token.append (_value[1:])
					_token.append ("]")
				elif _value.startswith ("'") :
					_token.append (_value[1:])
				elif _value.startswith ("$") :
					_value = expand_token (_value, _parameters)
					_token.append (_value)
				else :
					raise_error ("62d234ed", _value)
				if _quote :
					_token.append ("\"")
			_token = "".join (_token)
		elif isinstance (_value, list) :
			_token = list ()
			_token.append ("[")
			_sub_tokens = [_expand_value (_value) for _value in _value]
			_sub_tokens = ",".join (_sub_tokens)
			_token.append (_sub_tokens)
			_token.append ("]")
			_token = "".join (_token)
		else :
			raise_error ("2336219b", _value)
		return _token
	
	_tokens = list ()
	for _key, _value in _format :
		_value = _expand_value (_value)
		_token = ["\"", _key, "\"", ":", _value]
		_token = "".join (_token)
		_tokens.append (_token)
	_tokens = ",  ".join (_tokens)
	_tokens = "{  " + _tokens + "  }"
	
	return _tokens


logging_tcp_format_json = None

logging_http_format_json_template = [
		
		("s", "''20190405:01"),
		("ss", "'$logging_http_format_subschema"),
		("t", "=%Ts.%ms"),
		
		("f_id", "'%f"), #!
		("b_id", "'%b"), #!
		("s_id", "'%s"), #!
		
		("h_v", "'%HV"), #!
		("h_vm", "+@fc_http_major"),
		("h_m", "'%HM"), #!
		("h_p", "'%HP"), #!
		("h_q", "'%HQ"), #!
		("h_s", "+%ST"),
		
		# FIXME:  Make this configurable!
		("h_h", "'@var(txn.logging_http_host),json()"),
		
		# FIXME:  Make this configurable!
		("h_f_h", "'@var(txn.logging_http_forwarded_host),json()"),
		("h_f_f", "'@var(txn.logging_http_forwarded_for),json()"),
		("h_f_p", "'@var(txn.logging_http_forwarded_proto),json()"),
		
		("h_r_t", "'%trg"), #!
		("h_r_i", "'%ID"), #!
		
		# FIXME:  Make this configurable!
		("h_r_s", "'@var(txn.logging_http_session),json()"),
		("h_h_a", "'@var(txn.logging_http_agent),json()"),
		("h_h_r", "'@var(txn.logging_http_referrer),json()"),
		("h_h_l", "'@var(txn.logging_http_location),json()"),
		("h_h_ct", "'@var(txn.logging_http_content_type),json()"),
		("h_h_ce", "'@var(txn.logging_http_content_encoding),json()"),
		("h_h_cl", "'@var(txn.logging_http_content_length),json()"),
		("h_h_cc", "'@var(txn.logging_http_cache_control),json()"),
		("h_h_cv", "'@var(txn.logging_http_cache_etag),json()"),
		
		("h_i_hdr", "'%hrl"), #!
		("h_o_hdr", "'%hsl"), #!
		
		("h_i_ck", "'%CC"), #!
		("h_o_ck", "'%CS"), #!
		
		("h_o_comp", ["+@res.comp", "'@res.comp_algo"]),
		
		("c_sck", ["'%ci", "'%cp"]),
		("f_sck", ["'%fi", "'%fp"]),
		("b_sck", ["'%bi", "'%bp"]),
		("s_sck", ["'%si", "'%sp"]),
		
		("i_sz", "+%U"),
		("o_sz", "+%B"),
		
		("w", ["+%Tt", "+%Tq", "+%Ta"]),
		("w_x", ["+%Th", "+%Ti", "+%TR", "+%Tw", "+%Tc", "+%Tr", "+%Td"]),
		
		("f_ld", ["+%ac", "+%fc", "+%bc", "+%bq", "+%sc", "+%sq", "+%rc"]),
		("f_st", "'%tsc"),
		("g_cnt", ["+%lc", "+%rt"]),
		
		("ssl", ["'%sslv", "'%sslc"]),
		("ssl_x", [
				"+@ssl_fc",
				"'@ssl_fc_protocol,json()",
				"'@ssl_fc_cipher,json()",
				"'@ssl_fc_unique_id,hex",
				"'@ssl_fc_session_id,hex",
				"+@ssl_fc_is_resumed",
				"+@ssl_fc_has_sni",
				"'@ssl_fc_sni,json()",
				"'@ssl_fc_alpn,json()",
				"'@ssl_fc_npn,json()",
		]),
		("ssl_xf", [
				"+@ssl_fc",
				"'@ssl_f_version,json()",
				"'@ssl_f_sha1,hex",
				"'@ssl_f_s_dn,json()",
		]),
		("ssl_xc", [
				"'@ssl_c_used",
				"'@ssl_c_version,json()",
				"'@ssl_c_sha1,hex",
				"'@ssl_c_verify,json()",
				"'@ssl_c_err,json()",
				"'@ssl_c_ca_err,json()",
				"'@ssl_c_ca_err_depth,json()",
				"'@ssl_c_s_dn,json()",
				"'@ssl_c_i_dn,json()",
				
		]),
		
		("stick", [
				"'@sc0_conn_cur()",
				"'@sc0_conn_cnt()",
				"'@sc0_conn_rate()",
				"'@sc0_sess_cnt()",
				"'@sc0_sess_rate()",
				"'@sc0_http_req_cnt()",
				"'@sc0_http_req_rate()",
				"'@sc0_http_err_cnt()",
				"'@sc0_http_err_rate()",
				"'@sc0_kbytes_in()",
				"'@sc0_bytes_in_rate()",
				"'@sc0_kbytes_out()",
				"'@sc0_bytes_out_rate()",
		]),
		
	]

logging_http_format_json = lambda (_parameters) : _expand_logging_format_json (logging_http_format_json_template, _parameters)




parameters = {
		
		
		
		
		"proxy_identifier" : parameters_get ("daemon_node"),
		
		
		
		
		"frontend_enabled" : True,
		"frontend_minimal" : False,
		
		"frontend_http_bind_endpoint" : parameters_get ("defaults_frontend_http_bind_endpoint"),
		"frontend_http_bind_endpoint_tls" : parameters_get ("defaults_frontend_http_bind_endpoint_tls"),
		
		"frontend_max_connections_active_count" : parameters_get ("defaults_frontend_max_connections_active_count"),
		"frontend_max_connections_backlog_count" : parameters_get ("defaults_frontend_max_connections_backlog_count"),
		
		"frontend_bind_options" : (
				"defer-accept",
				"mss", 1400,
				parameters_choose_if_non_null (
						parameters_get ("frontend_max_connections_active_count"),
						("maxconn", parameters_get ("frontend_max_connections_active_count"))),
				parameters_choose_if_non_null (
						parameters_get ("frontend_max_connections_backlog_count"),
						("backlog", parameters_get ("frontend_max_connections_backlog_count"))),
				parameters_choose_if (
						parameters_get ("frontend_accept_proxy_enabled"),
						"accept-proxy"),
				parameters_choose_if_non_null (
						parameters_get ("frontend_bind_interface"),
						("interface", parameters_get ("frontend_bind_interface"))),
			),
		"frontend_bind_tls_certificate" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_tls"), "/default.pem"),
		"frontend_bind_tls_certificate_rules" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_tls"), "/default.conf"),
		"frontend_bind_tls_options" : (
				parameters_get ("frontend_bind_options"),
				parameters_get ("frontend_bind_tls_options_actual"),
			),
		"frontend_bind_interface" : None,
		
		# FIXME:  Rename this!
		"frontend_bind_tls_options_actual" : (
				parameters_get ("frontend_tls_options"),
				parameters_choose_if_non_null (
						parameters_get ("frontend_tls_ciphers_descriptor"),
						("ciphers", parameters_get ("frontend_tls_ciphers_descriptor"))),
			),
		"frontend_tls_mode" : None,
		"frontend_tls_ciphers" : parameters_choose_match (
				parameters_get ("frontend_tls_mode"),
				(None, None),
				("normal", parameters_get ("tls_ciphers_normal")),
				("paranoid", parameters_get ("tls_ciphers_paranoid")),
				("backdoor", parameters_get ("tls_ciphers_backdoor")),
			),
		"frontend_tls_ciphers_descriptor" : parameters_choose_if_non_null ("frontend_tls_ciphers", parameters_join (":", parameters_get ("frontend_tls_ciphers"))),
		"frontend_tls_options" : parameters_choose_match (
				parameters_get ("frontend_tls_mode"),
				(None, (
						parameters_get ("tls_options"))),
				("normal", (
						parameters_get ("tls_options_normal"),
						parameters_get ("tls_alpn_descriptor"),
						parameters_get ("tls_npn_descriptor"))),
				("paranoid", (
						parameters_get ("tls_options_paranoid"),
						parameters_get ("tls_alpn_descriptor"),
						parameters_get ("tls_npn_descriptor"))),
				("backdoor", (
						parameters_get ("tls_options_backdoor"),
						parameters_get ("tls_alpn_descriptor"),
						parameters_get ("tls_npn_descriptor"))),
			),
		
		"frontend_monitor_enabled" : True,
		"frontend_monitor_path" : parameters_get ("heartbeat_proxy_path"),
		"frontend_monitor_fail_acl" : "FALSE",
		"frontend_monitor_network" : "0.0.0.0/0",
		
		"frontend_stats_enabled" : True,
		"frontend_stats_token" : "beb36ad8a85568b7e89e314b2e03244f",
		"frontend_stats_path" : parameters_format ("%s%s", parameters_get ("haproxy_internals_path_prefix"), parameters_get ("frontend_stats_token")),
		"frontend_stats_auth_realm" : parameters_get ("daemon_identifier"),
		"frontend_stats_auth_credentials" : None,
		"frontend_stats_admin_acl" : None,
		"frontend_stats_version" : True,
		"frontend_stats_refresh" : 6,
		
		"frontend_accept_proxy_enabled" : False,
		"frontend_capture_length" : 1024,
		
		"frontend_http_keep_alive_mode" : "keep-alive",
		"frontend_http_keep_alive_reuse" : "safe",
		"frontend_http_keep_alive_timeout" : None,
		
		"frontend_http_stick_source" : "source",
		"frontend_http_stick_track" : True,
		
		
		
		
		"backend_enabled" : True,
		"backend_check_enabled" : True,
		
		"backend_http_host" : None,
		
		"backend_http_check_enabled" : parameters_get ("backend_check_enabled"),
		"backend_http_check_request_method" : "GET",
		"backend_http_check_request_uri" : parameters_get ("heartbeat_server_path"),
		"backend_http_check_request_version" : "HTTP/1.1",
		"backend_http_check_request_host" : parameters_get ("backend_http_host"),
		"backend_http_check_request_extra" : parameters_join (
				"\r\n",
				(
						parameters_get ("backend_http_check_request_version"),
						parameters_choose_if_non_null (parameters_get ("backend_http_check_request_host"), parameters_format ("Host: %s", parameters_get ("backend_http_check_request_host"))),
						"Connection: close",
				)
			),
		"backend_http_check_expect_matcher" : "status",
		"backend_http_check_expect_pattern" : "200",
		
		"backend_server_max_connections_active_count" : None,
		"backend_server_max_connections_queue_count" : parameters_math ("*", parameters_get ("backend_server_max_connections_active_count"), 4, True),
		"backend_server_check_interval_normal" : None,
		"backend_server_check_interval_rising" : None,
		"backend_server_check_interval_failed" : None,
		
		# FIXME:  Apply formulas as in case of defaults!
		"backend_server_timeout_activity" : None,
		"backend_server_timeout_activity_server" : None,
		"backend_server_timeout_activity_client" : None,
		"backend_server_timeout_activity_tunnel" : None,
		"backend_server_timeout_connect" : None,
		"backend_server_timeout_fin" : None,
		"backend_server_timeout_queue" : None,
		"backend_server_timeout_check" : None,
		"backend_server_timeout_tarpit" : None,
		"backend_server_timeout_request" : None,
		"backend_server_timeout_keep_alive" : None,
		
		"backend_http_keep_alive_mode" : "server-close",
		"backend_http_keep_alive_reuse" : "safe",
		"backend_http_keep_alive_timeout" : None,
		
		"backend_balance" : None,
		
		
		
		
		"server_enabled" : True,
		
		"server_max_connections_active_count" : None, # parameters_get ("defaults_server_max_connections_active_count"),
		"server_max_connections_queue_count" : None, # parameters_get ("defaults_server_max_connections_queue_count"),
		"server_check_enabled" : parameters_get ("backend_check_enabled"),
		"server_send_proxy_enabled" : False,
		"server_send_proxy_version" : "v1",
		
		"server_tcp_max_connections_active_count" : parameters_get ("server_max_connections_active_count"),
		"server_tcp_max_connections_queue_count" : parameters_get ("server_max_connections_queue_count"),
		"server_tcp_check_enabled" : parameters_get ("server_check_enabled"),
		"server_tcp_send_proxy_enabled" : parameters_get ("server_send_proxy_enabled"),
		"server_tcp_send_proxy_version" : parameters_get ("server_send_proxy_version"),
		"server_tcp_options" : (
				parameters_choose_if (
						parameters_get ("server_tcp_check_enabled"),
						"check"),
				parameters_choose_if (
						parameters_get ("server_tcp_check_enabled"),
						("observe", "layer4")),
				parameters_choose_if_non_null (
						parameters_get ("server_tcp_max_connections_active_count"),
						("maxconn", parameters_get ("server_tcp_max_connections_active_count"))),
				parameters_choose_if_non_null (
						parameters_get ("server_tcp_max_connections_queue_count"),
						("maxqueue", parameters_get ("server_tcp_max_connections_queue_count"))),
				parameters_choose_if (
						parameters_get ("server_tcp_send_proxy_enabled"),
						(
							parameters_choose_match (
								parameters_get ("server_tcp_send_proxy_version"),
								(True, "send-proxy"),
								("v1", "send-proxy"),
								("v2", "send-proxy-v2"),
								("v2-ssl", "send-proxy-v2-ssl"),
								("v2-ssl-cn", "send-proxy-v2-ssl-cn"),
							),
							parameters_choose_if (parameters_get ("server_tcp_check_enabled"), "check-send-proxy"))),
			),
		
		"server_http_max_connections_active_count" : parameters_get ("server_max_connections_active_count"),
		"server_http_max_connections_queue_count" : parameters_get ("server_max_connections_queue_count"),
		"server_http_check_enabled" : parameters_get ("server_check_enabled"),
		"server_http_send_proxy_enabled" : parameters_get ("server_send_proxy_enabled"),
		"server_http_send_proxy_version" : parameters_get ("server_send_proxy_version"),
		"server_http_options" : (
				parameters_choose_if (
						parameters_get ("server_http_check_enabled"),
						"check"),
				parameters_choose_if (
						parameters_get ("server_http_check_enabled"),
						("observe", "layer7")),
				parameters_choose_if_non_null (
						parameters_get ("server_http_max_connections_active_count"),
						("maxconn", parameters_get ("server_http_max_connections_active_count"))),
				parameters_choose_if_non_null (
						parameters_get ("server_http_max_connections_queue_count"),
						("maxqueue", parameters_get ("server_http_max_connections_queue_count"))),
				parameters_choose_if (
						parameters_get ("server_http_send_proxy_enabled"),
						(
							parameters_choose_match (
								parameters_get ("server_http_send_proxy_version"),
								(True, "send-proxy"),
								("v1", "send-proxy"),
								("v2", "send-proxy-v2"),
								("v2-ssl", "send-proxy-v2-ssl"),
								("v2-ssl-cn", "send-proxy-v2-ssl-cn"),
							),
							parameters_choose_if (parameters_get ("server_http_check_enabled"), "check-send-proxy"))),
			),
		
		"server_tls_enabled" : False,
		"server_tls_options" :
				parameters_choose_if (
						parameters_get ("server_tls_enabled"),
						(
								"ssl",
								# FIXME:  Make the following options configurable!
								("verify", "none"),
								parameters_choose_if (
										parameters_get ("server_check_enabled"),
										"check-ssl"),
						)
				),
		
		"server_check_interval_normal" : None,
		"server_check_interval_rising" : None,
		"server_check_interval_failed" : None,
		
		"server_resolvers" : parameters_get ("defaults_server_resolvers"),
		
		"server_options" : (
				parameters_choose_match (
						parameters_get ("backend_mode"),
						("tcp", parameters_get ("server_tcp_options")),
						("http", parameters_get ("server_http_options"))),
				parameters_get ("server_tls_options"),
				parameters_choose_if_non_null (parameters_get ("server_check_interval_normal"), ("inter", parameters_get ("server_check_interval_normal"))),
				parameters_choose_if_non_null (parameters_get ("server_check_interval_rising"), ("fastinter", parameters_get ("server_check_interval_rising"))),
				parameters_choose_if_non_null (parameters_get ("server_check_interval_failed"), ("downinter", parameters_get ("server_check_interval_failed"))),
				parameters_choose_if_non_null (parameters_get ("server_resolvers"), ("resolvers", parameters_get ("server_resolvers"))),
			),
		
		
		
		
		"defaults_frontend_http_bind_endpoint" : "ipv4@0.0.0.0:80",
		"defaults_frontend_http_bind_endpoint_tls" : "ipv4@0.0.0.0:443",
		
		"defaults_frontend_max_connections_active_count" : parameters_math ("//", parameters_get ("global_max_connections_count"), 2),
		"defaults_frontend_max_connections_backlog_count" : parameters_math ("//", parameters_get ("defaults_frontend_max_connections_active_count"), 4),
		"defaults_frontend_max_sessions_rate" : parameters_math ("*", parameters_get ("defaults_frontend_max_connections_active_count"), 4),
		
		"defaults_server_max_connections_active_count" : 32,
		"defaults_server_max_connections_queue_count" : parameters_math ("*", parameters_get ("defaults_server_max_connections_active_count"), 4),
		
		"defaults_server_check_interval_normal" : 60,
		"defaults_server_check_interval_rising" : parameters_math ("//", parameters_get ("defaults_server_check_interval_normal"), 30),
		"defaults_server_check_interval_failed" : parameters_math ("//", parameters_get ("defaults_server_check_interval_normal"), 3),
		"defaults_server_check_count_rising" : 8,
		"defaults_server_check_count_failed" : 4,
		"defaults_server_check_count_errors" : parameters_get ("defaults_server_check_count_failed"),
		
		"defaults_server_resolvers" : None,
		
		"defaults_timeout_activity" : 30,
		"defaults_timeout_activity_server" : parameters_math ("*", parameters_get ("defaults_timeout_activity"), 2),
		"defaults_timeout_activity_client" : parameters_get ("defaults_timeout_activity"),
		"defaults_timeout_activity_tunnel" : parameters_math ("*", parameters_get ("defaults_timeout_activity"), 6),
		"defaults_timeout_connect" : 6,
		"defaults_timeout_fin" : 6,
		"defaults_timeout_queue" : 30,
		"defaults_timeout_check" : 6,
		"defaults_timeout_tarpit" : parameters_get ("defaults_timeout_queue"),
		"defaults_timeout_request" : 30,
		"defaults_timeout_keep_alive" : 60,
		
		"defaults_compression_content_types" : compression_content_types,
		
		
		
		
		"global_max_connections_count" : 1024 * 8,
		"global_max_connections_rate" : parameters_math ("//", parameters_get ("global_max_connections_count"), 16),
		"global_max_sessions_rate" : parameters_math ("*", parameters_get ("global_max_connections_rate"), 4),
		"global_max_tls_connections_count" : parameters_math ("//", parameters_get ("global_max_connections_count"), 2),
		"global_max_tls_connections_rate" : parameters_math ("//", parameters_get ("global_max_tls_connections_count"), 16),
		"global_max_pipes" : parameters_math ("//", parameters_get ("global_max_connections_count"), 2),
		
		
		
		"tls_enabled" : True,
		"tls_ca_base" : parameters_choose_if (parameters_get ("tls_enabled"), parameters_choose_if (False, parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_tls"), "/ca"))),
		"tls_crt_base" : parameters_choose_if (parameters_get ("tls_enabled"), parameters_choose_if (False, parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_tls"), "/certificates"))),
		"tls_dh_params" : parameters_choose_if (parameters_get ("tls_enabled"), parameters_choose_if (True, parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_tls"), "/dh-params.pem"))),
		
		"tls_mode" : tls_mode,
		"tls_ciphers" : parameters_choose_match (
				parameters_get ("tls_mode"),
				("normal", parameters_get ("tls_ciphers_normal")),
				("paranoid", parameters_get ("tls_ciphers_paranoid")),
				("backdoor", parameters_get ("tls_ciphers_backdoor")),
			),
		"tls_ciphers_descriptor" : parameters_join (":", parameters_get ("tls_ciphers")),
		"tls_ciphers_normal" : tls_ciphers_normal,
		"tls_ciphers_paranoid" : tls_ciphers_paranoid,
		"tls_ciphers_backdoor" : tls_ciphers_backdoor,
		"tls_options" : parameters_choose_match (
				parameters_get ("tls_mode"),
				("normal", (
						parameters_get ("tls_options_normal"),
						parameters_get ("tls_alpn_descriptor"),
						parameters_get ("tls_npn_descriptor"))),
				("paranoid", (
						parameters_get ("tls_options_paranoid"),
						parameters_get ("tls_alpn_descriptor"),
						parameters_get ("tls_npn_descriptor"))),
				("backdoor", (
						parameters_get ("tls_options_backdoor"),
						parameters_get ("tls_alpn_descriptor"),
						parameters_get ("tls_npn_descriptor"))),
			),
		"tls_options_normal" : tls_options_normal,
		"tls_options_paranoid" : tls_options_paranoid,
		"tls_options_backdoor" : tls_options_backdoor,
		"tls_alpn_enabled" : False,
		"tls_alpn_descriptor" : parameters_choose_if (parameters_get ("tls_alpn_enabled"), ("alpn", parameters_join (",", parameters_get ("tls_alpn_protocols")))),
		"tls_alpn_protocols" : ("h2,http/1.1", "http/1.0"),
		"tls_npn_enabled" : False,
		"tls_npn_descriptor" : parameters_choose_if (parameters_get ("tls_npn_enabled"), ("npn", parameters_join (",", parameters_get ("tls_npn_protocols")))),
		"tls_npn_protocols" : ("h2,http/1.1", "http/1.0"),
		
		
		
		
		"geoip_enabled" : False,
		"geoip_map" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_maps"), "/geoip.map"),
		
		"bots_acl" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations_maps"), "/bots.acl"),
		
		
		
		
		"daemon_node" : "localhost",
		"daemon_name" : "haproxy",
		"daemon_identifier" : parameters_format ("%s@%s", parameters_get ("daemon_name"), parameters_get ("daemon_node")),
		"daemon_description" : "[]",
		
		"daemon_user" : "haproxy",
		"daemon_group" : parameters_get ("daemon_user"),
		"daemon_pid" : parameters_format ("%s%s", parameters_get ("daemon_paths_runtime"), "/haproxy.pid"),
		"daemon_chroot" : parameters_format ("%s%s", parameters_get ("daemon_paths_runtime"), "/haproxy.chroot"),
		"daemon_chroot_enabled" : False,
		"daemon_ulimit" : 65536,
		"daemon_processes_count" : 1,
		# "daemon_processes_affinity" : ("all", 1),
		"daemon_processes_affinity" : None,
		"daemon_threads_count" : 1,
		"daemon_socket" : parameters_choose_if (True, parameters_format ("%s%s", parameters_get ("daemon_paths_runtime"), "/haproxy.sock")),
		
		"daemon_paths_configurations" : "/etc/haproxy",
		"daemon_paths_configurations_tls" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations"), "/tls"),
		"daemon_paths_configurations_maps" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations"), "/maps"),
		"daemon_paths_runtime" : "/var/run",
		
		"daemon_paths_states_prefix" : parameters_format ("%s%s", parameters_get ("daemon_paths_runtime"), "/haproxy-state--"),
		"daemon_paths_state_global" : parameters_format ("%s%s", parameters_get ("daemon_paths_runtime"), "/haproxy.state"),
		
		
		
		
		"syslog_1_enabled" : True,
		"syslog_1_endpoint" : "/dev/log",
		"syslog_1_protocol" : parameters_get ("syslog_protocol"),
		
		"syslog_2_enabled" : False,
		"syslog_2_endpoint" : "127.0.0.1:514",
		"syslog_2_protocol" : parameters_get ("syslog_protocol"),
		
		"syslog_p_enabled" : False,
		"syslog_p_endpoint" : "127.0.0.1:514",
		"syslog_p_protocol" : parameters_get ("syslog_protocol"),
		
		# NOTE:  Preferred protocol should be `rfc5424`!
		#        If there are issues, use `rfc3164` and set `syslog_source_node` to `None`.
		"syslog_protocol" : "rfc5424",
		"syslog_source_node" : parameters_get ("daemon_node"),
		"syslog_source_tag" : "haproxy",
		
		
		
		
		"logging_type" : logging_type,
		"logging_tcp_type" : parameters_get ("logging_type"),
		"logging_tcp_format_text" : logging_tcp_format_text,
		"logging_tcp_format_json" : logging_tcp_format_json,
		"logging_tcp_format" : parameters_choose_match (
				parameters_get ("logging_tcp_type"),
				("text", parameters_get ("logging_tcp_format_text")),
				("json", parameters_get ("logging_tcp_format_json"))
		),
		"logging_http_type" : parameters_get ("logging_type"),
		"logging_http_format_text" : logging_http_format_text,
		"logging_http_format_json" : logging_http_format_json,
		"logging_http_format_subschema" : "default",
		"logging_http_format" : parameters_choose_match (
				parameters_get ("logging_http_type"),
				("text", parameters_get ("logging_http_format_text")),
				("json", parameters_get ("logging_http_format_json"))
		),
		"logging_http_variable_method" : "txn.logging_http_method",
		"logging_http_variable_host" : "txn.logging_http_host",
		"logging_http_variable_forwarded_host" : "txn.logging_http_forwarded_host",
		"logging_http_variable_forwarded_for" : "txn.logging_http_forwarded_for",
		"logging_http_variable_forwarded_proto" : "txn.logging_http_forwarded_proto",
		"logging_http_variable_agent" : "txn.logging_http_agent",
		"logging_http_variable_referrer" : "txn.logging_http_referrer",
		"logging_http_variable_location" : "txn.logging_http_location",
		"logging_http_variable_content_type" : "txn.logging_http_content_type",
		"logging_http_variable_content_encoding" : "txn.logging_http_content_encoding",
		"logging_http_variable_content_length" : "txn.logging_http_content_length",
		"logging_http_variable_cache_control" : "txn.logging_http_cache_control",
		"logging_http_variable_cache_etag" : "txn.logging_http_cache_etag",
		"logging_http_variable_session" : "txn.logging_http_session",
		"logging_http_variable_action" : "txn.logging_http_action",
		"logging_http_header_forwarded_host" : "X-Forwarded-Host",
		"logging_http_header_forwarded_for" : "X-Forwarded-For",
		"logging_http_header_forwarded_proto" : "X-Forwarded-Proto",
		"logging_http_header_forwarded_port" : "X-Forwarded-Port",
		"logging_http_header_forwarded_server_ip" : "X-Forwarded-Server-Ip",
		"logging_http_header_forwarded_server_port" : "X-Forwarded-Server-Port",
		"logging_http_header_session" : parameters_get ("http_tracking_session_header"),
		"logging_http_header_action" : "X-HA-HTTP-Action",
		"logging_geoip_country_variable" : "txn.logging_geoip_country",
		
		
		
		
		"error_pages_enabled" : True,
		"error_pages_codes" : (400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504,),
		"error_pages_store" : parameters_format ("%s%s", parameters_get ("daemon_paths_configurations"), "/errors/http"),
		
		
		
		
		"internals_path_prefix" : "/__/",
		"internals_rules_order_allow" : -9920,
		"internals_rules_order_deny" : -9910,
		"internals_netfilter_mark_allowed" : None,
		"internals_netfilter_mark_denied" : None,
		
		"haproxy_internals_path_prefix" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "haproxy/"),
		"heartbeat_server_path" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "heartbeat"),
		"heartbeat_proxy_path" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "heartbeat-proxy"),
		"heartbeat_self_path" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "heartbeat-haproxy"),
		"authenticate_path" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "authenticate"),
		"error_pages_path_prefix" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "errors/"),
		
		"whitelist_path" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "whitelist"),
		"whitelist_netfilter_mark_allowed" : None,
		"whitelist_netfilter_mark_denied" : None,
		
		
		
		
		"http_tracking_session_cookie" : "X-HA-Session-Id",
		"http_tracking_session_cookie_max_age" : 2419200,
		"http_tracking_session_header" : "X-HA-Session-Id",
		"http_tracking_session_variable" : "txn.http_tracking_session",
		"http_tracking_request_header" : "X-HA-Request-Id",
		"http_tracking_request_variable" : "txn.http_tracking_request",
		"http_tracking_enabled_variable" : "txn.http_tracking_enabled",
		
		"http_authenticated_header" : "X-HA-Authenticated",
		"http_authenticated_cookie" : "X-HA-Authenticated",
		"http_authenticated_cookie_max_age" : 3600,
		"http_authenticated_path" : parameters_get ("authenticate_path"),
		"http_authenticated_query" : "__authenticate",
		"http_authenticated_variable" : "txn.http_authenticated",
		"http_authenticated_netfilter_mark" : None,
		
		"http_debug_timestamp_header" : "X-HA-Timestamp",
		"http_debug_frontend_header" : "X-HA-Frontend",
		"http_debug_backend_header" : "X-HA-Backend",
		
		"http_errors_marker" : "X-Ha-Error-Proxy",
		"http_errors_method" : "X-HA-Error-Method",
		"http_errors_status" : "X-HA-Error-Status",
		
		
		
		
		"http_harden_level" : "standard",
		
		"http_harden_allowed_methods_strict" : ('get'),
		"http_harden_allowed_methods_standard" : ('head', 'get', 'options'),
		"http_harden_allowed_methods" : parameters_choose_match (
				parameters_get ("http_harden_level"),
				("strict", parameters_get ("http_harden_allowed_methods_strict")),
				("standard", parameters_get ("http_harden_allowed_methods_standard")),
		),
		
		"http_harden_allowed_status_codes_strict" : http_status_codes["harden_allowed_strict"],
		"http_harden_allowed_status_codes_standard" : http_status_codes["harden_allowed_standard"],
		"http_harden_allowed_status_codes" : parameters_choose_match (
				parameters_get ("http_harden_level"),
				("strict", parameters_get ("http_harden_allowed_status_codes_strict")),
				("standard", parameters_get ("http_harden_allowed_status_codes_standard")),
		),
		
		"http_harden_allowed_get_status_codes_strict" : http_status_codes["harden_allowed_get_strict"],
		"http_harden_allowed_get_status_codes_standard" : http_status_codes["harden_allowed_get_standard"],
		"http_harden_allowed_get_status_codes" : parameters_choose_match (
				parameters_get ("http_harden_level"),
				("strict", parameters_get ("http_harden_allowed_get_status_codes_strict")),
				("standard", parameters_get ("http_harden_allowed_get_status_codes_standard")),
		),
		
		"http_harden_allowed_post_status_codes_strict" : http_status_codes["harden_allowed_post_strict"],
		"http_harden_allowed_post_status_codes_standard" : http_status_codes["harden_allowed_post_standard"],
		"http_harden_allowed_post_status_codes" : parameters_choose_match (
				parameters_get ("http_harden_level"),
				("strict", parameters_get ("http_harden_allowed_post_status_codes_strict")),
				("standard", parameters_get ("http_harden_allowed_post_status_codes_standard")),
		),
		
		"http_harden_hsts_enabled" : True,
		"http_harden_hsts_interval" : parameters_choose_match (
				parameters_get ("http_harden_level"),
				("strict", 4 * 365 * 24 * 3600),
				("standard", 28 * 24 * 3600),
		),
		"http_harden_hsts_descriptor" : parameters_format ("max-age=%d", parameters_get ("http_harden_hsts_interval")),
		"http_harden_csp_descriptor" : "upgrade-insecure-requests",
		"http_harden_referrer_descriptor" : "strict-origin-when-cross-origin",
		"http_harden_frames_descriptor" : "sameorigin",
		"http_harden_cto_descriptor" : "nosniff",
		"http_harden_xss_descriptor" : "1; mode=block",
		"http_harden_netfilter_mark_allowed" : None,
		"http_harden_netfilter_mark_denied" : None,
		"http_harden_enabled_variable" : "txn.http_harden_enabled",
		"http_hardened_header" : "X-HA-Hardened",
		
		# FIXME:  Implement:  "http_drop_caching_forced" : False,
		"http_drop_caching_enabled_variable" : "txn.http_drop_caching_enabled",
		"http_force_caching_enabled_variable" : "txn.http_force_caching_enabled",
		
		# FIXME:  Implement: "http_drop_cookies_forced" : False,
		"http_drop_cookies_enabled_variable" : "txn.http_drop_cookies_enabled",
		
		"http_ranges_allowed_variable" : "txn.http_ranges_allowed",
		
		
		
		
		"letsencrypt_backend_identifier" : "letsencrypt",
		"letsencrypt_server_ip" : "127.0.0.1",
		"letsencrypt_server_port" : 445,
		"letsencrypt_server_endpoint" : parameters_format ("ipv4@%s:%d", parameters_get ("letsencrypt_server_ip"), parameters_get ("letsencrypt_server_port")),
		"letsencrypt_frontend_rules_order" : -9100,
		"letsencrypt_frontend_routes_order" : -9100,
		"letsencrypt_path" : "/.well-known/acme-challenge",
		
		
		
		
		"varnish_backend_identifier" : "varnish",
		"varnish_downstream_ip" : "127.0.0.1",
		"varnish_downstream_port" : 6083,
		"varnish_downstream_endpoint" : parameters_format ("ipv4@%s:%d", parameters_get ("varnish_downstream_ip"), parameters_get ("varnish_downstream_port")),
		"varnish_downstream_send_proxy_enabled" : parameters_get ("varnish_send_proxy_enabled"),
		"varnish_upstream_ip" : "127.0.0.1",
		"varnish_upstream_port" : 6081,
		"varnish_upstream_endpoint" : parameters_format ("ipv4@%s:%d", parameters_get ("varnish_upstream_ip"), parameters_get ("varnish_upstream_port")),
		"varnish_upstream_send_proxy_enabled" : parameters_get ("varnish_send_proxy_enabled"),
		"varnish_management_ip" : "127.0.0.1",
		"varnish_management_port" : 6082,
		"varnish_management_endpoint" : parameters_format ("ipv4@%s:%d", parameters_get ("varnish_management_ip"), parameters_get ("varnish_management_port")),
		"varnish_frontend_rules_order" : -5100,
		"varnish_frontend_routes_order" : -5100,
		"varnish_drop_caching_enabled" : False,
		"varnish_drop_cookies_enabled" : False,
		"varnish_internals_path_prefix" : parameters_format ("%s%s", parameters_get ("internals_path_prefix"), "varnish/"),
		"varnish_internals_rules_order_allow" : parameters_get ("internals_rules_order_allow"),
		"varnish_internals_rules_order_deny" : parameters_get ("internals_rules_order_deny"),
		"varnish_heartbeat_enabled" : True,
		"varnish_heartbeat_path" : parameters_format ("%s%s", parameters_get ("varnish_internals_path_prefix"), "heartbeat"),
		"varnish_heartbeat_interval" : 1,
		"varnish_max_connections_active_count" : parameters_math ("//", parameters_get ("frontend_max_connections_active_count"), 4, True),
		"varnish_max_connections_queue_count" : parameters_math ("*", parameters_get ("varnish_max_connections_active_count"), 4, True),
		"varnish_send_proxy_enabled" : False,
		
		
		
		
		"samples_via_tls_method" : "ssl_fc",
		
	}




