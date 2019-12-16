

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		geoip_enabled = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (frontend = _fe)


_fe.requests.track_enable ()

_fe.requests.track ()
_fe.responses.track ()


_ha.output_stdout ()

