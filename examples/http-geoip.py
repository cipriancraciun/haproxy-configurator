

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		geoip_enabled = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)


_fe.requests.set_geoip_headers ()

_fe.requests.variables_geoip ()
_fe.requests.capture_geoip ()


_ha.output_stdout ()

