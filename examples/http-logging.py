

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		frontend_logging_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (frontend = _fe)


_fe.requests.capture_logging ()
_fe.responses.capture_logging ()


_ha.output_stdout ()

