

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		frontend_bind_tls_minimal = False,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)




_trusted = (
		"10.0.0.0/8",
		"192.168.0.0/16",
	)




_fe.requests.deny (
		_code = 403,
		_acl = _fe.acls.client_ip (_trusted) .negate (),
	)




_ha.output_stdout ()

