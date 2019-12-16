

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()


_be_flask = _ha.http_backends.basic (
		_identifier = "http-flask",
		_endpoint = "ipv4@127.0.0.1:9090",
	)

_be_static = _ha.http_backends.basic (
		_identifier = "http-static",
		_endpoint = "ipv4@127.0.0.1:9091",
	)

_be_media = _ha.http_backends.basic (
		_identifier = "http-media",
		_endpoint = "ipv4@127.0.0.1:9092",
	)




_fe.routes.route_path_prefix (_be_static, ("/assets/", "/public/"))
_fe.routes.route_path_prefix (_be_media, "/media/")
_fe.routes.route (_be_flask)




_ha.output_stdout ()

