

import ha


_ha_parameters = ha.parameters (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
		daemon_user = "haproxy",
		daemon_group = "haproxy",
	)


_ha = ha.haproxy (_ha_parameters)

_fe = _ha.http_frontend_create ("http")
_fe_requests = _fe.http_request_rule_builder ()
_fe_routes = _fe.http_route_builder ()

_fe.declare_bind ()
_fe.declare_bind_tls ()

_fe_requests.redirect_domain_with_www ("with-www.example.com")
_fe_requests.redirect_domain_without_www ("without-www.example.com")

_fe_routes.route_host ("fallback-http", "example.com")

_be_http = _ha.http_backend_create ("fallback-http")
_be_http.declare_server ("default", "ipv4@127.255.255.254:8080")


_ha.output_stdout ()


