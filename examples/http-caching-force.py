

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)


_fe.requests.force_caching_enable ()

_fe.responses.force_caching ()


_ha.output_stdout ()

