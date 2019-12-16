

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()


_be_www = _ha.http_backends.basic (
		_identifier = "http-flask",
		_endpoint = "ipv4@127.0.0.1:9090",
	)

_be_blog = _ha.http_backends.basic (
		_identifier = "http-static",
		_endpoint = "ipv4@127.0.0.1:9091",
	)

_be_app = _ha.http_backends.basic (
		_identifier = "http-media",
		_endpoint = "ipv4@127.0.0.1:9092",
	)

_be_deny = _ha.http_backends.fallback_deny ()




_fe.requests.redirect_domain_with_www ("example.com")

_fe.routes.route_host (_be_www, "www.example.com")
_fe.routes.route_host (_be_blog, "blog.example.com")
_fe.routes.route_host (_be_app, "app.example.com")

_fe.routes.route (_be_deny)




_ha.output_stdout ()

