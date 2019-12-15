

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
		only_frontends_and_backends = True,
	)


_fe = _ha.http_frontends.basic ()

_fe.requests.redirect_domain_with_www ("site-with-www.example.com")
_fe.requests.redirect_domain_without_www ("site-without-www.example.com")


_be = _ha.http_backends.basic (frontend = _fe)


_ha.output_stdout ()

