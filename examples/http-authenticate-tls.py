

import ha


_ha = ha.haproxy (
		minimal_configure = True,
		frontend_bind_tls_minimal = False,
	)


_fe = _ha.http_frontends.basic (
		_tls = True,
		tls_ca_file_enabled = True,
		tls_verify_client = "optional",
	)

_be = _ha.http_backends.basic (frontend = _fe)




_operators = (
		"874a47fdf56abfb59402779564976f48",
		"bc98855760c47e3643053790edd856cd",
	)




_fe.requests.deny (
		_code = 403,
		_acl = _fe.acls.tls_client_certificate (_operators) .negate (),
	)




_ha.output_stdout ()

