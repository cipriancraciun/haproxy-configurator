

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
	)


_fe = _ha.http_frontend_create ("http")

_fe.declare_bind ()
_fe.declare_bind_tls ()

_fe.requests.redirect_domain_with_www ("site-with-www.example.com")
_fe.requests.redirect_domain_without_www ("site-without-www.example.com")


_be_http_fallback = _ha.http_backends.fallback_deny ()
_fe.routes.route_host (_be_http_fallback, "example.com")


_ha.output_stdout ()

