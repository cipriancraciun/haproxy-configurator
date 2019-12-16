

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (frontend = _fe)


_fe.requests.set_debug_headers ()
_fe.responses.set_debug_headers ()


_ha.output_stdout ()

