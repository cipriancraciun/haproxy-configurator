

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (frontend = _fe)


_fe.requests.drop_caching_enable ()

_fe.requests.drop_caching ()
_fe.responses.drop_caching ()


_ha.output_stdout ()

