

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()


_be_variant_a = _ha.http_backends.basic (
		identifier = "variant-a",
		endpoint = "ipv4@127.0.0.1:9090",
	)

_be_variant_b = _ha.http_backends.basic (
		identifier = "variant-b",
		endpoint = "ipv4@127.0.0.1:9091",
	)




_fe.routes.route (_be_variant_b, (
		_fe.acls.backend_active (_be_variant_b),
		_fe.acls.ab_in_bucket (0, 4),
	))

_fe.routes.route (_be_variant_a)




_ha.output_stdout ()

