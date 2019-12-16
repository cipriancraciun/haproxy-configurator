

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)


_operators = _ha.credentials_create ("operators", "example.com")
_operators.declare_user ("operator", "zeregigojacuyixu")




_fe.requests.authenticate (
		_operators,
		_acl = _fe.acls.host ("private.example.com"),
	)




_ha.output_stdout ()

