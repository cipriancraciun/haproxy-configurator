

from configurator import *


_ha_parameters = parameters (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
		daemon_user = "haproxy",
		daemon_group = "haproxy",
	)


_ha = haproxy (_ha_parameters)

_fe = _ha.http_frontend_create ("http")
_fe_acl = _fe.acl_builder ()
_fe_http_requests = _fe.http_request_rule_builder ()

_fe.declare_bind ("ipv4@0.0.0.0:80")
# _fe.declare_bind_tls ("ipv4@0.0.0.0:443", statement_quote ("\'", "/etc/haproxy/tls/server.pem"))

_fe_http_requests.redirect_domain_with_www ("with-www.example.com")
_fe_http_requests.redirect_domain_without_www ("without-www.example.com")

#_fe.declare_route_if ("fallback-http", _fe_acl.host ("example.com"))
#_fe.declare_http_request_rule_if ("tarpit", _fe_acl.host ("invalid.com"))


_be_http = _ha.http_backend_create ("fallback-http")
_be_http.declare_server ("default", "ipv4@127.255.255.254:8080")

_be_tcp = _ha.tcp_backend_create ("fallback-tcp")
_be_tcp.declare_server ("default", "ipv4@127.255.255.254:8080")


_ha.output_stdout ()


