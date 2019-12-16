

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		http_harden_level = "standard",
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (frontend = _fe)


_fe.requests.harden_enable ()

_fe.requests.harden_all ()
_fe.responses.harden_all ()


_ha.output_stdout ()

