

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()

_fe.requests.redirect_domain_with_www ("site-with-www.example.com")
_fe.requests.redirect_domain_without_www ("site-without-www.example.com")


_be = _ha.http_backends.basic (frontend = _fe)


_ha.output_stdout ()

