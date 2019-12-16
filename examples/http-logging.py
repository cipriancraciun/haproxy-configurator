

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		frontend_logging_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)


_fe.requests.variables_defaults ()
_fe.responses.variables_defaults ()


_ha.output_stdout ()

