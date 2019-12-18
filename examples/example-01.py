

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy.example.com",
	)


_fe = _ha.http_frontends.basic ()


_be_web = _ha.http_backends.basic (
		_identifier = "http-www",
		_endpoint = "ipv4@127.0.0.1:9090",
		http_harden_level = "standard",
	)

_be_admin = _ha.http_backends.basic (
		_identifier = "http-admin",
		_endpoint = "ipv4@127.0.0.1:9091",
		http_harden_level = "strict",
	)

_be_static = _ha.http_backends.basic (
		_identifier = "http-static",
		_endpoint = "ipv4@127.0.0.1:9092",
		http_harden_level = "paranoid",
	)

_be_media = _ha.http_backends.basic (
		_identifier = "http-media",
		_endpoint = "ipv4@127.0.0.1:9093",
		http_harden_level = "paranoid",
	)

_be_fallback = _ha.http_backends.fallback_deny ()


_operators = _ha.credentials_create ("operators", "example.com")
_operators.declare_user ("operator", "zeregigojacuyixu")




_fe.requests.set_forwarded_headers ()

_fe.requests.variables_defaults ()
_fe.responses.variables_defaults ()

_fe.requests.capture_defaults ()
_fe.responses.capture_defaults ()

_fe.requests.set_debug_headers ()
_fe.responses.set_debug_headers ()




_fe.requests.redirect_via_tls ()

_fe.requests.redirect_domain_with_www ("example.com", _force_tls = True)

_fe.requests.redirect_prefix ("https://www.example.com/blog",
		_acl = (
			_fe.acls.host ("blog.example.com"),
		))

_fe.requests.redirect_prefix ("https://admin.example.com",
		_acl = (
			_fe.acls.host ("www.example.com"),
			_fe.acls.path_prefix ("/admin/"),
		))




_be_admin.requests.authenticate (_operators)

for _be_current in [_be_web, _be_admin, _be_static, _be_media] :
	
	_be_current.requests.harden_enable ()
	_be_current.requests.harden_all ()
	_be_current.responses.harden_all ()


for _be_current in [_be_web, _be_static, _be_media] :
	
	_be_web.requests.drop_cookies_enable ()
	_be_web.requests.drop_cookies ()
	_be_web.responses.drop_cookies ()
	
	_be_web.requests.force_caching_enable ()
	_be_web.responses.force_caching ()




_fe.routes.route (_be_web,
		_acl = (
				_fe.acls.host ("www.example.com"),
		))

_fe.routes.route (_be_admin,
		_acl = (
				_fe.acls.host ("admin.example.com"),
		))

_fe.routes.route (_be_static,
		_acl = (
				_fe.acls.host (("www.example.com", "admin.example.com")),
				("/assets/", "/public/"),
		))

_fe.routes.route (_be_media,
		_acl = (
				_fe.acls.host ("media.example.com"),
		))


_fe.routes.route (_be_fallback)




_ha.output_stdout ()

