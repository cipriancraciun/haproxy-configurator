

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (frontend = _fe)


_fe.requests.drop_cookies_enable ()

_fe.requests.drop_cookies ()
_fe.responses.drop_cookies ()


_ha.output_stdout ()

