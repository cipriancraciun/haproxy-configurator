



from errors import *
from tools import *

from builders_core import *




class HaHttpBackendBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
	
	
	def basic (self, _identifier = None, _endpoint = None, _frontend = None, _acl = None, _route_order = None, **_parameters) :
		
		_identifier = _identifier if _identifier is not None else "http-backend"
		_endpoint = _endpoint if _endpoint is not None else "ipv4@127.0.0.1:8080"
		
		_backend = self._context.http_backend_create (_identifier, **_parameters)
		if _endpoint is not None :
			_backend.declare_server ("default", _endpoint)
		
		def _frontend_configure (_routes, _requests, _responses) :
			_routes.route (_backend, _acl, order = _route_order)
		self._for_each_frontend_http_builders (_frontend, _frontend_configure)
		
		return _backend
	
	
	def for_domain (self, _domain, _endpoint = None, _identifier = None, _frontend = None, _acl = None, **_parameters) :
		
		_endpoint = _endpoint if _endpoint is not None else "ipv4@127.0.0.1:8080"
		_backend_identifier = parameters_coalesce (_identifier, _domain)
		
		_parameters = parameters_defaults (_parameters, backend_http_check_request_host = _domain)
		
		_backend = self._context.http_backend_create (_backend_identifier, **_parameters)
		_backend.declare_server ("default", _endpoint)
		
		def _frontend_configure (_routes, _requests, _responses) :
			_routes.route_host (_backend, _host, _acl)
		self._for_each_frontend_http_builders (_frontend, _frontend_configure)
		
		return _backend
	
	def for_domains (self, _map, _frontend = None, _acl = None, **_parameters) :
		_backends = list ()
		for _domain, _endpoint in _map.iteritems () :
			_backend = self.for_domain (_domain, _endpoint, _frontend = _frontend, _identifier = _domain, _acl = _acl, **_parameters)
			_backends.append (_backend)
		return _backends
	
	
	def letsencrypt (self, _identifier = None, _endpoint = None, _frontend = None, _acl = None, **_parameters) :
		
		_server_endpoint = statement_coalesce (_endpoint, "$letsencrypt_server_endpoint")
		_backend_identifier = parameters_coalesce (_identifier, parameters_get ("letsencrypt_backend_identifier"))
		
		_parameters = parameters_overrides (_parameters, backend_check_enabled = False)
		
		_backend = self._context.http_backend_create (_backend_identifier, **_parameters)
		_backend.declare_server ("default", _server_endpoint)
		
		def _frontend_configure (_routes, _requests, _responses) :
			# FIXME:  These parameters should be taken from overrides, then from frontend parameters, and then from self parameters!
			_path = self._parameters_get_and_expand ("letsencrypt_path", overrides = _parameters)
			_frontend_rules_order = self._parameters_get_and_expand ("letsencrypt_frontend_rules_order", overrides = _parameters)
			_frontend_routes_order = self._parameters_get_and_expand ("letsencrypt_frontend_routes_order", overrides = _parameters)
			_routes.route_subpath (_backend, _path, _acl, order = _frontend_routes_order)
			_requests.allow_subpath (_path, _acl, order = _frontend_rules_order)
		
		self._for_each_frontend_http_builders (_frontend, _frontend_configure)
		
		return _backend
	
	
	def varnish (self, _identifier = None, _endpoint = None, _frontend = None, _domain = None, _acl = None, **_parameters) :
		
		_server_endpoint = statement_coalesce (_endpoint, "$varnish_upstream_endpoint")
		_backend_identifier = parameters_coalesce (_identifier, parameters_get ("varnish_backend_identifier"))
		
		_parameters = parameters_overrides (
				_parameters,
				backend_http_check_enabled = parameters_get ("varnish_heartbeat_enabled"),
				backend_http_check_request_uri = parameters_get ("varnish_heartbeat_path"),
				backend_server_min_connections_active_count = parameters_get ("varnish_min_connections_active_count"),
				backend_server_max_connections_active_count = parameters_get ("varnish_max_connections_active_count"),
				backend_server_max_connections_queue_count = parameters_get ("varnish_max_connections_queue_count"),
				backend_server_max_connections_full_count = parameters_get ("varnish_max_connections_full_count"),
				backend_server_check_interval_normal = parameters_get ("varnish_heartbeat_interval"),
				backend_server_check_interval_rising = parameters_get ("varnish_heartbeat_interval"),
				backend_server_check_interval_failed = parameters_get ("varnish_heartbeat_interval"),
				backend_http_keep_alive_reuse = parameters_get ("varnish_keep_alive_reuse"),
				backend_http_keep_alive_mode = parameters_get ("varnish_keep_alive_mode"),
				backend_http_keep_alive_timeout = parameters_get ("varnish_keep_alive_timeout"),
				server_http_send_proxy_enabled = parameters_get ("varnish_downstream_send_proxy_enabled"),
			)
		
		_backend = self._context.http_backend_create (_backend_identifier, **_parameters)
		_backend.declare_server ("default", _server_endpoint)
		
		if self._parameters_get_and_expand ("varnish_drop_caching_enabled") :
			_backend.http_request_rule_builder () .drop_caching ()
		if self._parameters_get_and_expand ("varnish_drop_cookies_enabled") :
			_backend.http_request_rule_builder () .drop_cookies ()
		
		def _frontend_configure (_routes, _requests, _responses) :
			# FIXME:  These parameters should be taken from overrides, then from frontend parameters, and then from self parameters!
			_frontend_rules_order = self._parameters_get_and_expand ("varnish_frontend_rules_order", parameters = _frontend._parameters, overrides = _parameters)
			_frontend_routes_order = self._parameters_get_and_expand ("varnish_frontend_routes_order", parameters = _frontend._parameters, overrides = _parameters)
			_internals_path_prefix = self._parameters_get_and_expand ("varnish_internals_path_prefix", parameters = _frontend._parameters, overrides = _parameters)
			_internals_order_allow = self._parameters._get_and_expand ("varnish_internals_rules_order_allow", parameters = _frontend._parameters, overrides = _parameters)
			_routes.route_host (_backend, _domain, _acl, order = _frontend_routes_order)
			_requests.allow_prefix (_internals_path_prefix, _acl, order = _internals_order_allow)
		
		self._for_each_frontend_http_builders (_frontend, _frontend_configure)
		
		return _backend
	
	
	def _for_each_frontend (self, _frontend, _callable) :
		if _frontend is None :
			return
		if not isinstance (_frontend, tuple) and not isinstance (_frontend, list) :
			_frontend = (_frontend,)
		for _frontend in _frontend :
			_callable (_frontend)
	
	def _for_each_frontend_http_builders (self, _frontend, _callable) :
		if _frontend is None :
			return
		if not isinstance (_frontend, tuple) and not isinstance (_frontend, list) :
			_frontend = (_frontend,)
		for _frontend in _frontend :
			_frontend_routes = _frontend.routes
			_frontend_http_requests = _frontend.http_request_rule_builder ()
			_frontend_http_responses = _frontend.http_response_rule_builder ()
			_callable (_frontend_routes, _frontend_http_requests, _frontend_http_responses)
	
	
	def fallback (self, _identifier = "http-fallback") :
		_backend = self._context.http_backend_create (
				_identifier,
				backend_check_enabled = True,
				backend_http_keep_alive_reuse = "never",
				backend_http_keep_alive_mode = "close",
			)
		_backend.declare_server ("default", "ipv4@127.255.255.254:8080")
		return _backend
	
	def fallback_deny (self, _identifier = "http-fallback", _code = 403, _mark = None) :
		_backend = self._context.http_backend_create (
				_identifier,
				backend_check_enabled = False,
				backend_http_keep_alive_reuse = "never",
				backend_http_keep_alive_mode = "close",
			)
		_backend.requests.deny (_code, None, _mark)
		return _backend




