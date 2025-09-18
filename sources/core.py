



from parameters import Parameters
from parameters import undefined as parameters_undefined
from scroll import Scroll

import defaults
import declares
import builders

from errors import *
from tools import *




def haproxy (_parameters = None, **_overrides) :
	_parameters = Parameters (_parameters, _overrides, defaults.parameters)
	return HaProxy (_parameters)

def parameters (_parameters = None, **_overrides) :
	return Parameters (_parameters, _overrides, defaults.parameters)

parameters.undefined = parameters_undefined

def overrides (**_overrides) :
	return _overrides




class HaBase (object) :
	
	def _expand_token (self, _token, _join = None, _quote = None) :
		return expand_token (_token, self._parameters, _join, _quote)
	
	def _resolve_token (self, _token) :
		return resolve_token (_token, self._parameters)
	
	def _enforce_token (self, _token, _schema) :
		return enforce_token (_token, _schema)
	
	def _expand_and_enforce_token (self, _token, _schema) :
		_token = self._expand_token (_token)
		_token = self._enforce_token (_token, _schema)
		return _token




class HaProxy (HaBase) :
	
	def __init__ (self, _parameters) :
		
		HaBase.__init__ (self)
		
		_identifier = enforce_identifier (_parameters, parameters_get ("proxy_identifier"))
		
		self.identifier = _identifier
		self._parameters = _parameters
		
		if self._expand_token ("$?global_configure") :
			self.globals = HaGlobals (self._parameters._fork ())
		else :
			self.globals = None
		
		if self._expand_token ("$?defaults_configure") :
			self.defaults = HaDefaults (self._parameters._fork ())
		else :
			self.defaults = None
		
		self._frontends = dict ()
		self._frontends_ordered = list ()
		
		self._backends = dict ()
		self._backends_ordered = list ()
		
		self._resolvers = dict ()
		self._resolvers_ordered = list ()
		
		self._credentials = dict ()
		self._credentials_ordered = list ()
		
		self.http_frontends = self.http_frontend_builder ()
		self.http_backends = self.http_backend_builder ()
	
	
	def frontends (self) :
		return self._frontends_ordered
	
	def backends (self) :
		return self._backends_ordered
	
	
	def frontend (self, _identifier) :
		_identifier = enforce_identifier (self._parameters, _identifier)
		return self._frontends[_identifier]
	
	def backend (self, _identifier) :
		_identifier = enforce_identifier (self._parameters, _identifier)
		return self._backends[_identifier]
	
	def resolvers (self, _identifier) :
		_identifier = enforce_identifier (self._parameters, _identifier)
		return self._resolvers[_identifier]
	
	def credentials (self, _identifier) :
		_identifier = enforce_identifier (self._parameters, _identifier)
		return self._credentials[_identifier]
	
	
	def frontend_create (self, _identifier, _type = None, **_overrides) :
		
		_parameters = self._parameters._fork (**_overrides)
		_identifier = enforce_identifier (_parameters, _identifier)
		_parameters._set (frontend_identifier = _identifier)
		
		if _identifier in self._frontends :
			raise_error ("eb0997d4", _identifier)
		if _type is None :
			_type = HaFrontend
		
		_frontend = _type (_identifier, _parameters)
		self._frontends[_identifier] = _frontend
		self._frontends_ordered.append (_frontend)
		self._frontends_ordered.sort (key = lambda _section : _section._order)
		
		return _frontend
	
	def backend_create (self, _identifier, _type = None, **_overrides) :
		
		_parameters = self._parameters._fork (**_overrides)
		_identifier = enforce_identifier (_parameters, _identifier)
		_parameters._set (backend_identifier = _identifier)
		
		if _identifier in self._backends :
			raise_error ("ad2910cf", _identifier)
		if _type is None :
			_type = HaBackend
		
		_backend = _type (_identifier, _parameters)
		self._backends[_identifier] = _backend
		self._backends_ordered.append (_backend)
		self._backends_ordered.sort (key = lambda _section : _section._order)
		
		return _backend
	
	
	def resolvers_create (self, _identifier, **_overrides) :
		
		_parameters = self._parameters._fork (**_overrides)
		_identifier = enforce_identifier (_parameters, _identifier)
		_parameters._set (resolvers_identifier = _identifier)
		
		if _identifier in self._resolvers :
			raise_error ("07b20b3f", _identifier)
		
		_resolvers = HaResolvers (_identifier, _parameters)
		self._resolvers[_identifier] = _resolvers
		self._resolvers_ordered.append (_resolvers)
		self._resolvers_ordered.sort (key = lambda _section : _section._order)
		
		return _resolvers
	
	
	def credentials_create (self, _identifier, _realm = None, **_overrides) :
		
		_parameters = self._parameters._fork (**_overrides)
		_identifier = enforce_identifier (_parameters, _identifier)
		_parameters._set (credentials_identifier = _identifier)
		
		if _identifier in self._credentials :
			raise_error ("0e49fc8e", _identifier)
		
		_credentials = HaCredentials (_identifier, _realm, _parameters)
		self._credentials[_identifier] = _credentials
		self._credentials_ordered.append (_credentials)
		self._credentials_ordered.sort (key = lambda _section : _section._order)
		
		return _credentials
	
	
	def tcp_frontend_create (self, _identifier, **_overrides) :
		return self.frontend_create (_identifier, _type = HaTcpFrontend, frontend_mode = "tcp", **_overrides)
	
	def tcp_backend_create (self, _identifier, **_overrides) :
		return self.backend_create (_identifier, _type = HaTcpBackend, backend_mode = "tcp", **_overrides)
	
	
	def http_frontend_create (self, _identifier, **_overrides) :
		return self.frontend_create (_identifier, _type = HaHttpFrontend, frontend_mode = "http", **_overrides)
	
	def http_backend_create (self, _identifier, **_overrides) :
		return self.backend_create (_identifier, _type = HaHttpBackend, backend_mode = "http", **_overrides)
	
	
	def http_frontend_builder (self) :
		return builders.HaHttpFrontendBuilder (self, self._parameters)
	
	def http_backend_builder (self) :
		return builders.HaHttpBackendBuilder (self, self._parameters)
	
	
	def output_stdout (self) :
		_scroll = self.generate ()
		_scroll.output_stdout ()
	
	
	def generate (self) :
		
		self._declare_implicit_auto ()
		
		_empty_lines = 8 if self._expand_token ("$?sections_extra_separation") else 2
		
		_scroll = Scroll ()
		_scroll.include_empty_line (99, 0, _empty_lines)
		
		if self.globals is not None :
			_scroll.include_normal_line (100, 0, self.globals.generate ())
			_scroll.include_empty_line (100, 0, _empty_lines)
		
		if self.defaults is not None :
			_scroll.include_normal_line (200, 0, self.defaults.generate ())
			_scroll.include_empty_line (200, 0, _empty_lines)
		
		_scroll.include_normal_line (300, 0, [_frontend.generate () for _frontend in self._frontends_ordered])
		_scroll.include_empty_line (300, 0, _empty_lines)
		
		_scroll.include_normal_line (400, 0, [_backend.generate () for _backend in self._backends_ordered])
		_scroll.include_empty_line (400, 0, _empty_lines)
		
		_scroll.include_normal_line (500, 0, [_resolvers.generate () for _resolvers in self._resolvers_ordered])
		_scroll.include_empty_line (500, 0, _empty_lines)
		
		_scroll.include_normal_line (600, 0, [_credentials.generate () for _credentials in self._credentials_ordered])
		_scroll.include_empty_line (600, 0, _empty_lines)
		
		return _scroll
	
	
	def _declare_implicit_auto (self) :
		
		if self.globals is not None :
			self.globals._declare_implicit_auto ()
		if self.defaults is not None :
			self.defaults._declare_implicit_auto ()
		
		for _frontend in self._frontends_ordered :
			_frontend._declare_implicit_auto ()
		
		for _backend in self._backends_ordered :
			_backend._declare_implicit_auto ()




class HaSection (HaBase) :
	
	def __init__ (self, _parameters, declare_implicit_if = True) :
		HaBase.__init__ (self)
		self._parameters = _parameters
		self._statements = HaStatementGroup (self._parameters, None, order = 4000)
		self._custom_statements = HaStatementGroup (self._parameters, "Custom", order = 6000)
		self._declare_implicit_if = declare_implicit_if
		self._declare_implicit_done = False
		self._order = self._parameters._get ("order", 999999)
	
	
	def declare (self, *_tokens, **_options) :
		return self._statements.declare (_tokens, **_options)
	
	def declare_group (self, _heading, *_statements, **_options) :
		return self._statements.declare_group (_heading, *_statements, **_options)
	
	
	def declare_custom (self, *_tokens, **_options) :
		return self._custom_statements.declare (_tokens, **_options)
	
	def declare_custom_group (self, _heading, *_statements, **_options) :
		return self._custom_statements.declare_group (_heading, *_statements, **_options)
	
	
	def declare_implicit (self, **_options) :
		if self._declare_implicit_done :
			raise_error ("215d179b")
		self._declare_implicit_done = True
		self._declare_implicit (**_options)
	
	def _declare_implicit (self) :
		pass
	
	def _declare_implicit_auto (self) :
		if not self._declare_implicit_done :
			_declare_implicit_if = self._resolve_token (self._declare_implicit_if)
			if _declare_implicit_if is True :
				self.declare_implicit ()
			elif _declare_implicit_if is False :
				pass
			else :
				raise_error ("c9d16b7a", _declare_implicit_if)
	
	
	def generate (self) :
		self._declare_implicit_auto ()
		_scroll = Scroll ()
		_empty_lines = 4 if self._expand_token ("$?sections_extra_separation") else 2
		_scroll.include_empty_line (99, 0, _empty_lines)
		_scroll.include_normal_line (100, 0, self._generate_header ())
		_scroll.include_empty_line (199, 0, 1)
		_scroll.include_normal_line (200, 0, self._generate_statements ())
		_scroll.include_empty_line (299, 0, 1)
		_scroll.include_normal_line (300, 0, self._generate_trailer ())
		_scroll.include_empty_line (399, 0, _empty_lines)
		return _scroll
	
	def _generate_header (self) :
		raise_error ("1adb835c")
	
	def _generate_trailer (self) :
		return Scroll ()
	
	def _generate_statements (self) :
		_scroll = Scroll (1)
		self._statements.generate (_scroll, _merge = True)
		self._generate_statements_extra (_scroll)
		self._custom_statements.generate (_scroll, _merge = True)
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		pass




class HaGlobals (HaSection) :
	
	def __init__ (self, _parameters) :
		HaSection.__init__ (self, _parameters)
	
	def _declare_implicit (self) :
		declares.declare_globals (self)
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, "global")
		return _scroll




class HaDefaults (HaSection) :
	
	def __init__ (self, _parameters) :
		HaSection.__init__ (self, _parameters)
	
	def _declare_implicit (self) :
		declares.declare_defaults (self)
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, "defaults")
		return _scroll




class HaResolvers (HaSection) :
	
	def __init__ (self, _identifier, _parameters) :
		HaSection.__init__ (self, _parameters)
		self.identifier = enforce_identifier (self._parameters, _identifier)
		self._nameserver_statements = HaStatementGroup (self._parameters, "Nameservers", order = 5000 + 100)
		
		self._parameter_statements = HaStatementGroup (self._parameters, "Parameters", order = 5000 + 200)
		self._parameter_statements.declare (("hold", "valid", statement_seconds (60)))
		self._parameter_statements.declare (("hold", "obsolete", statement_seconds (3600)))
		self._parameter_statements.declare (("hold", "nx", statement_seconds (6)))
		self._parameter_statements.declare (("hold", "refused", statement_seconds (6)))
		self._parameter_statements.declare (("hold", "timeout", statement_seconds (6)))
		self._parameter_statements.declare (("hold", "other", statement_seconds (6)))
		self._parameter_statements.declare (("timeout", "resolve", statement_seconds (1)))
		self._parameter_statements.declare (("timeout", "retry", statement_seconds (1)))
		self._parameter_statements.declare (("resolve_retries", 4))
		self._parameter_statements.declare (("accepted_payload_size", 8192))
	
	
	def declare_nameserver (self, _nameserver, _ip, _port) :
		self._nameserver_statements.declare (
				("nameserver",
						statement_quote ("\'", _nameserver),
						statement_quote ("\'",
								statement_format ("%s:%d",
										statement_enforce_string (_ip),
										statement_enforce_int (_port)))
				))
	
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, self._expand_token (("resolvers", "$\'resolvers_identifier")))
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		self._nameserver_statements.generate (_scroll)
		self._parameter_statements.generate (_scroll)
	
	def _self_expand_token (self) :
		return self.identifier
	
	def _self_resolve_token (self) :
		return self.identifier




class HaCredentials (HaSection) :
	
	def __init__ (self, _identifier, _realm, _parameters) :
		HaSection.__init__ (self, _parameters)
		self.identifier = enforce_identifier (self._parameters, _identifier)
		self.realm = enforce_identifier (self._parameters, _realm) if _realm is not None else None
		self._group_statements = HaStatementGroup (self._parameters, "Groups", order = 5000 + 100)
		self._user_statements = HaStatementGroup (self._parameters, "Users", order = 5000 + 200)
	
	
	def declare_group (self, _group, _users = None) :
		self._group_statements.declare (
				("group",
						statement_quote ("\'", _group),
						statement_choose_if_non_null (
								_users,
								("users", statement_quote ("\'", statement_join (",", _users))))
				))
	
	
	def declare_user (self, _user, _password, _password_secure = False, _groups = None) :
		self._user_statements.declare (
				("user",
						statement_quote ("\'", _user),
						statement_choose_if (
								_password_secure,
								("password", statement_quote ("\'", _password)),
								("insecure-password", statement_quote ("\'", _password))),
						statement_choose_if_non_null (
								_groups,
								("groups", statement_quote ("\'", statement_join (",", _groups))))
				))
	
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, self._expand_token (("userlist", "$\'credentials_identifier")))
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		self._group_statements.generate (_scroll)
		self._user_statements.generate (_scroll)
	
	def _self_expand_token (self) :
		return self.identifier
	
	def _self_resolve_token (self) :
		return self.identifier




class HaWorker (HaSection) :
	
	def __init__ (self, _identifier, _parameters) :
		HaSection.__init__ (self, _parameters)
		self.identifier = enforce_identifier (self._parameters, _identifier)
		self._acl = list ()
		self._samples = list ()
		self._tcp_request_rule_statements = HaStatementGroup (self._parameters, "TCP Request Rules", order = 5000 + 300 - 1)
		self._tcp_response_rule_statements = HaStatementGroup (self._parameters, "TCP Response Rules", order = 5000 + 400 - 1)
		self._http_request_rule_statements = HaStatementGroup (self._parameters, "HTTP Request Rules", order = 5000 + 300)
		self._http_response_rule_statements = HaStatementGroup (self._parameters, "HTTP Response Rules", order = 5000 + 400)
	
	
	def acl_1 (self, _criteria, _matcher, _patterns) :
		return self.acl_0 (None, _criteria, _matcher, None, None, _patterns)
	
	def acl_0 (self, _identifier, _criteria, _matcher, _flags, _operator, _patterns) :
		_acl = HaAcl (self._parameters, _identifier, _criteria, _matcher, _flags, _operator, _patterns)
		self._acl.append (_acl)
		return _acl
	
	def http_acl_builder (self) :
		return builders.HaHttpAclBuilder (self, self._parameters)
	
	def _condition_if (self, _acl) :
		if _acl is True : return None
		if _acl is False : return ("if", "FALSE")
		return self._condition_0 ("if", _acl) if _acl is not None else None
	
	def _condition_unless (self, _acl) :
		if _acl is False : return None
		if _acl is True : return ("unless", "TRUE")
		return self._condition_0 ("unless", _acl) if _acl is not None else None
	
	def _condition_0 (self, _method, _acl) :
		def _condition (_expand) :
			_method_expanded = _expand (_method)
			_acl_expanded = _expand (_acl)
			if _acl_expanded is not None :
				return (_method_expanded, _acl_expanded)
			else :
				return None
		return _condition
	
	
	def sample_1 (self, _method, _arguments) :
		return self.sample_0 (_method, _arguments, None)
	
	def sample_0 (self, _method, _arguments, transforms) :
		_sample = HaSample (self._parameters, _method, _arguments, transforms)
		self._samples.append (_sample)
		return _sample
	
	def http_sample_builder (self) :
		return builders.HaHttpSampleBuilder (self, self._parameters)
	
	
	def declare_http_request_rule (self, _action, **_overrides) :
		self.declare_http_request_rule_0 ((_action, None), **_overrides)
	
	def declare_http_request_rule_if (self, _action, _acl, **_overrides) :
		_condition = self._condition_if (_acl)
		self.declare_http_request_rule_0 ((_action, _condition), **_overrides)
	
	def declare_http_request_rule_unless (self, _action, _acl, **_overrides) :
		_condition = self._condition_unless (_acl)
		self.declare_http_request_rule_0 ((_action, _condition), **_overrides)
	
	def declare_http_request_rule_0 (self, _rule, **_overrides) :
		self._http_request_rule_statements.declare (("http-request", _rule), **_overrides)
	
	def http_request_rule_builder (self) :
		return builders.HaHttpRequestRuleBuilder (self, self._parameters)
	
	
	def declare_http_response_rule_if (self, _action, **_overrides) :
		self.declare_http_response_rule_0 ((_action, None), **_overrides)
	
	def declare_http_response_rule_if (self, _action, _acl, **_overrides) :
		_condition = self._condition_if (_acl)
		self.declare_http_response_rule_0 ((_action, _condition), **_overrides)
	
	def declare_http_response_rule_unless (self, _action, _acl, **_overrides) :
		_condition = self._condition_unless (_acl)
		self.declare_http_response_rule_0 ((_action, _condition), **_overrides)
	
	def declare_http_response_rule_0 (self, _rule, **_overrides) :
		self._http_response_rule_statements.declare (("http-response", _rule), **_overrides)
	
	def http_response_rule_builder (self) :
		return builders.HaHttpResponseRuleBuilder (self, self._parameters)
	
	
	def declare_tcp_request_rule (self, _action, **_overrides) :
		self.declare_tcp_request_rule_0 ((_action, None), **_overrides)
	
	def declare_tcp_request_rule_if (self, _action, _acl, **_overrides) :
		_condition = self._condition_if (_acl)
		self.declare_tcp_request_rule_0 ((_action, _condition), **_overrides)
	
	def declare_tcp_request_rule_unless (self, _action, _acl, **_overrides) :
		_condition = self._condition_unless (_acl)
		self.declare_tcp_request_rule_0 ((_action, _condition), **_overrides)
	
	def declare_tcp_request_rule_0 (self, _rule, **_overrides) :
		self._tcp_request_rule_statements.declare (("tcp-request", _rule), **_overrides)
	
	
	def declare_tcp_response_rule (self, _action,  **_overrides) :
		self.declare_tcp_response_rule_0 ((_action, None), **_overrides)
	
	def declare_tcp_response_rule_if (self, _action, _acl, **_overrides) :
		_condition = self._condition_if (_acl)
		self.declare_tcp_response_rule_0 ((_action, _condition), **_overrides)
	
	def declare_tcp_response_rule_unless (self, _action, _acl, **_overrides) :
		_condition = self._condition_unless (_acl)
		self.declare_tcp_response_rule_0 ((_action, _condition), **_overrides)
	
	def declare_tcp_response_rule_0 (self, _rule, **_overrides) :
		self._tcp_response_rule_statements.declare (("tcp-response", _rule), **_overrides)
	
	
	def _generate_statements_for_acl (self, _scroll) :
		if len (self._acl) > 0 :
			_acl_uniques = set ()
			_acl_statements = list ()
			_acl_expanded = set ()
			for _acl in self._acl :
				if _acl._expanded :
					_acl_tokens = _acl.generate ()
					_acl_identifier = _acl._generated_identifier
					_acl_expanded.add (_acl_identifier)
			for _acl in self._acl :
				_acl_tokens = _acl.generate ()
				_acl_identifier = _acl._generated_identifier
				if _acl_identifier not in _acl_expanded :
					continue
				if (_acl_identifier, _acl._generated_fingerprint) in _acl_uniques :
					continue
				else :
					_acl_uniques.add ((_acl_identifier, _acl._generated_fingerprint))
				if isinstance (_acl_tokens, list) :
					for _acl_tokens in _acl_tokens :
						_acl_statements.append ((_acl_identifier, _acl_tokens))
				else :
					_acl_statements.append ((_acl_identifier, _acl_tokens))
			_acl_statements.sort (key = lambda _acl_statement : (_acl_statement[1][2:], _acl_statement[0]))
			_statements = HaStatementGroup (self._parameters, "ACL", order = 5000 + 200)
			for _acl_statement in _acl_statements :
				_statements.declare (_acl_statement[1])
			_statements.generate (_scroll)
	
	def _generate_statements_for_http_rules (self, _scroll) :
		self._tcp_request_rule_statements.generate (_scroll)
		self._tcp_response_rule_statements.generate (_scroll)
		self._http_request_rule_statements.generate (_scroll)
		self._http_response_rule_statements.generate (_scroll)
	
	
	def _self_expand_token (self) :
		return self.identifier
	
	def _self_resolve_token (self) :
		return self.identifier




class HaFrontend (HaWorker) :
	
	def __init__ (self, _identifier, _parameters) :
		HaWorker.__init__ (self, _identifier, _parameters)
		self._bind_statements = HaStatementGroup (self._parameters, "Bind", order = 5000 + 120)
		self._route_statements = HaStatementGroup (self._parameters, "Routes", order = 5000 + 500)
		self._request_capture_statements = HaStatementGroup (self._parameters, "Captures for requests", order = 8000 + 830)
		self._request_captures_count = 0
		self._response_capture_statements = HaStatementGroup (self._parameters, "Captures for responses", order = 8000 + 840)
		self._response_captures_count = 0
	
	
	def declare_bind (self, _endpoint = "$frontend_bind_endpoint", _name = None, _options = "$frontend_bind_options", order = None, overrides = None) :
		_name = statement_choose_if (_name, ("name", statement_quote ("\'", _name)))
		self._bind_statements.declare (("bind", statement_quote ("\'", _endpoint), _name, _options), order = order, overrides = overrides)
	
	def declare_bind_tls (self, _endpoint = "$frontend_bind_tls_endpoint", _name = None, _certificate = "$\'frontend_bind_tls_certificate", _certificate_rules = "$\'frontend_bind_tls_certificate_rules", _options = "$frontend_bind_tls_options", order = None, overrides = None) :
		_tls_options = ["ssl"]
		if _certificate is not None :
			_tls_options.append (statement_choose_if_non_null (_certificate, ("crt", _certificate)))
		if _certificate_rules is not None :
			_tls_options.append (statement_choose_if_non_null (_certificate_rules, ("crt-list", _certificate_rules)))
		_tls_options = tuple (_tls_options)
		_name = statement_choose_if (_name, ("name", statement_quote ("\'", _name)))
		self._bind_statements.declare (("bind", statement_quote ("\'", _endpoint), _name, _tls_options, _options), order = order, overrides = overrides)
	
	
	def declare_route (self, _backend, **_overrides) :
		self.declare_route_if_0 (_backend, None, **_overrides)
	
	def declare_route_if_0 (self, _backend, _acl, **_overrides) :
		_condition = self._condition_if (_acl)
		if isinstance (_backend, int) :
			self._route_statements.declare (("http-request", "return", "status", _backend, "file", statement_path_join (("$error_pages_store_html", "%d.html" % _backend), quote = True), "content-type", statement_quote ("\'", "text/html"), _condition), **_overrides)
		else :
			self._route_statements.declare (("use_backend", _backend, _condition), **_overrides)
	
	def declare_route_unless_0 (self, _backend, _acl, **_overrides) :
		_condition = self._condition_unless (_acl)
		if isinstance (_backend, int) :
			self._route_statements.declare (("http-request", "return", "status", _backend, "file", statement_path_join (("$error_pages_store_html", "%d.html" % _backend), quote = True), "content-type", statement_quote ("\'", "text/html"), _condition), **_overrides)
		else :
			self._route_statements.declare (("use_backend", _backend, _condition), **_overrides)
	
	def http_route_builder (self, **_overrides) :
		return builders.HaHttpRouteBuilder (self, self._parameters, **_overrides)
	
	
	def _declare_request_capture (self, _length = "$+frontend_capture_length", **_overrides) :
		_index = self._request_captures_count
		self._request_captures_count += 1
		self._request_capture_statements.declare (("declare", "capture", "request", "len", statement_enforce_int (_length)), **_overrides)
		return _index
	
	def _declare_response_capture (self, _length = "$+frontend_capture_length", **_overrides) :
		_index = self._response_captures_count
		self._response_captures_count += 1
		self._response_capture_statements.declare (("declare", "capture", "response", "len", statement_enforce_int (_length)), **_overrides)
		return _index
	
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, self._expand_token (("frontend", "$\'frontend_identifier")))
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		
		self._generate_statements_for_binds (_scroll)
		self._generate_statements_for_captures (_scroll)
		
		_after_acl_scroll = Scroll ()
		self._generate_statements_for_http_rules (_after_acl_scroll)
		self._generate_statements_for_routes (_after_acl_scroll)
		
		_acl_scroll = Scroll ()
		self._generate_statements_for_acl (_acl_scroll)
		
		_scroll.include_scroll_lines (None, 0, _acl_scroll, False)
		_scroll.include_scroll_lines (None, 0, _after_acl_scroll, False)
	
	def _generate_statements_for_binds (self, _scroll) :
		self._bind_statements.generate (_scroll)
	
	def _generate_statements_for_captures (self, _scroll) :
		self._request_capture_statements.generate (_scroll)
		self._response_capture_statements.generate (_scroll)
	
	def _generate_statements_for_routes (self, _scroll) :
		self._route_statements.generate (_scroll)




class HaBackend (HaWorker) :
	
	def __init__ (self, _identifier, _parameters) :
		HaWorker.__init__ (self, _identifier, _parameters)
		self._server_statements = HaStatementGroup (self._parameters, "Servers", order = 5000 + 800)
	
	
	def declare_server (self, _identifier, _endpoint, _options = "$server_options", _acl = None, _persist = True, _options_overrides = {}, **_overrides) :
		_identifier = enforce_identifier (self._parameters, _identifier)
		_options = statement_overrides (_options, **_options_overrides)
		_condition = self._condition_if (_acl)
		if _condition is not None :
			if _persist :
				self._server_statements.declare (("force-persist", _condition), **_overrides)
			self._server_statements.declare (("use-server", statement_quote ("\'", _identifier), _condition), **_overrides)
		self._server_statements.declare (("server", statement_quote ("\'", _identifier), statement_quote ("\'", _endpoint), _options), **_overrides)
	
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, self._expand_token (("backend", "$\'backend_identifier")))
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		
		_after_acl_scroll = Scroll ()
		self._generate_statements_for_http_rules (_after_acl_scroll)
		self._generate_statements_for_servers (_after_acl_scroll)
		
		_acl_scroll = Scroll ()
		self._generate_statements_for_acl (_acl_scroll)
		
		_scroll.include_scroll_lines (None, 0, _acl_scroll, False)
		_scroll.include_scroll_lines (None, 0, _after_acl_scroll, False)
	
	def _generate_statements_for_servers (self, _scroll) :
		self._server_statements.generate (_scroll)




class HaTcpFrontend (HaFrontend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaFrontend.__init__ (self, _identifier, _parameters, **_options)
	
	def _declare_implicit (self, **_options) :
		declares.declare_tcp_frontend (self, **_options)


class HaTcpBackend (HaBackend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaBackend.__init__ (self, _identifier, _parameters, **_options)
	
	def _declare_implicit (self, **_options) :
		declares.declare_tcp_backend (self, **_options)




class HaHttpFrontend (HaFrontend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		_parameters = _parameters._fork (
				frontend_bind_endpoint = "$frontend_http_bind_endpoint",
				frontend_bind_tls_endpoint = "$frontend_http_bind_endpoint_tls",
			)
		HaFrontend.__init__ (self, _identifier, _parameters, **_options)
		self.acls = self.http_acl_builder ()
		self.samples = self.http_sample_builder ()
		self.requests = self.http_request_rule_builder ()
		self.responses = self.http_response_rule_builder ()
		self.routes = self.http_route_builder ()
	
	def _declare_implicit (self, **_options) :
		self.declare_http_request_rule_if (
				("deny", "deny_status", "200"),
				self.acls.path ("$heartbeat_self_path"),
				enabled_if = statement_and ("$?frontend_monitor_enabled", "$?frontend_monitor_configure"),
				order = 0)
		declares.declare_http_frontend (self, **_options)


class HaHttpBackend (HaBackend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaBackend.__init__ (self, _identifier, _parameters, **_options)
		self.acls = self.http_acl_builder ()
		self.samples = self.http_sample_builder ()
		self.requests = self.http_request_rule_builder ()
		self.responses = self.http_response_rule_builder ()
	
	def _declare_implicit (self, **_options) :
		declares.declare_http_backend (self, **_options)




class HaAcl (HaBase) :
	
	
	def __init__ (self, _parameters, _identifier, _criteria, _matcher, _flags, _operator, _patterns) :
		HaBase.__init__ (self)
		_identifier = enforce_identifier (_parameters, _identifier, True)
		self._parameters = _parameters
		self._identifier = _identifier
		self._criteria = _criteria
		self._matcher = _matcher
		self._flags = _flags
		self._operator = _operator
		self._patterns = _patterns
		self._generated = None
		self._expanded = False
	
	
	def identifier (self) :
		self.generate ()
		return self._generated_identifier
	
	def force_include (self) :
		self.generate ()
		self._expanded = True
	
	
	def negate (self) :
		return HaAclNegation (self)
	
	
	def generate (self) :
		
		if self._generated is not None :
			return self._generated
		
		_identifier, _criteria, _matcher, _flags, _operator, _patterns, _fingerprint = self._expand ()
		
		_tokens = list ()
		
		_tokens.append ("acl")
		
		if _identifier is None :
			_identifier = "acl-" + _fingerprint
		_tokens.append (_identifier)
		
		_tokens.append (_criteria)
		
		_tokens.append ("-m")
		_tokens.append (_matcher)
		
		_patterns_in_files = False
		if _flags is not None :
			for _flag in _flags :
				if _flag == "-f" :
					_patterns_in_files = True
					continue
				_tokens.append (_flag)
		
		if _operator is not None :
			_tokens.append (_operator)
		
		if _patterns is not None :
			
			if not _patterns_in_files :
				_tokens.append ("--")
			
			_patterns_batch = 1
			if _patterns_in_files :
				_patterns_batch = 1
			
			if len (_patterns) <= _patterns_batch :
				for _pattern in _patterns :
					if _patterns_in_files :
						_tokens.append ("-f")
					_tokens.append (_pattern)
				_tokens = tuple (_tokens)
				
			else :
				_tokens_original = _tokens
				_tokens = []
				for _pattern_offset in xrange (0, len (_patterns), _patterns_batch) :
					_tokens_0 = list (_tokens_original) + list (_patterns[_pattern_offset : _pattern_offset + _patterns_batch])
					_tokens_0 = tuple (_tokens_0)
					_tokens.append (_tokens_0)
			
		else :
			_tokens = tuple (_tokens)
		
		self._generated_identifier = _identifier
		self._generated_fingerprint = _fingerprint
		self._generated = _tokens
		
		return self._generated
	
	
	def _expand (self) :
		
		_identifier = self._expand_and_enforce_token (
				self._identifier,
				{"type" : "or", "schemas" : (
						basestring,
						None,
				)})
		
		_criteria = self._enforce_token (
				self._criteria,
				HaSample)
		_criteria = _criteria.generate ()
		
		_matcher = self._expand_and_enforce_token (
				self._matcher,
				{"type" : "and", "schemas" : (
						basestring,
						(lambda _token : _token in HaAcl.matchers),
				)})
		
		_flags = self._expand_and_enforce_token (
				self._flags,
				{"type" : "or", "schemas" : (
						None,
						{"type" : tuple, "schema" : basestring},
						# FIXME:  Also check if the flag is allowed!
				)})
		if _flags is not None :
			_flags = tuple (sorted (set (_flags)))
		
		_operator = self._expand_and_enforce_token (
				self._operator,
				{"type" : "or", "schemas" : (
						None,
						basestring,
						# FIXME:  Also check if the operator is allowed!
				)})
		
		_patterns = self._expand_token (self._patterns, tuple, "\'?")
		_patterns = self._enforce_token (
				_patterns,
				{"type" : "or", "schemas" : (
						None,
						basestring,
						{"type" : tuple, "schema" : {"type" : "or", "schemas" : (basestring, int)}},
				)})
		if _patterns is not None :
			if isinstance (_patterns, tuple) :
				_patterns = tuple (sorted (set (_patterns)))
			else :
				_patterns = (_patterns,)
		
		_fingerprint = hash_token ((_criteria, "-m", _matcher, _flags, _operator, "--", _patterns))
		
		return _identifier, _criteria, _matcher, _flags, _operator, _patterns, _fingerprint
	
	
	def _self_expand_token (self) :
		self._expanded = True
		return self.identifier ()
	
	def _self_resolve_token (self) :
		self._expanded = True
		return self.identifier ()
	
	
	matchers = {
			"found" : (None, (0, 0), None, ("-u",)),
			"bool" : (("boolean", "integer"), (0, 0), None, ("-u",)),
			"int" : (("integer", "boolean"), (1, None), ("eq", "ge", "gt", "le", "lt"), ("-u",)),
			"ip" : (("ip", "string", "binary"), (1, None), None, ("-u", "-n")),
			"bin" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"len" : (("string", "binary"), (1, None), None, ("-u",)),
			"str" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"sub" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"reg" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"beg" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"end" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"dir" : (("string", "binary"), (1, None), None, ("-u", "-i")),
			"dom" : (("string", "binary"), (1, None), None, ("-u", "-i")),
	}


class HaAclNegation (object) :
	
	def __init__ (self, _acl) :
		self._acl = _acl
	
	def identifier (self) :
		_identifier = self._acl.identifier ()
		return "!%s" % (_identifier,)
	
	def negate (self) :
		return self._acl
	
	def _self_expand_token (self) :
		self._acl._expanded = True
		return self.identifier ()
	
	def _self_resolve_token (self) :
		self._acl._expanded = True
		return self.identifier ()




class HaSample (HaBase) :
	
	
	def __init__ (self, _parameters, _method, _arguments, _transforms) :
		HaBase.__init__ (self)
		self._parameters = _parameters
		self._method = _method
		self._arguments = _arguments
		self._transforms = _transforms
		self._generated = None
	
	
	def statement_format (self) :
		return statement_format ("%%[%s]", self)
	
	def parameter_get (self) :
		return lambda _parameters : self.generate ()
	
	
	def generate (self) :
		
		if self._generated is not None :
			return self._generated
		
		_method, _arguments, _transforms = self._expand ()
		
		_tokens = list ()
		
		_tokens.append (_method)
		
		if _arguments is not None and len (_arguments) > 0 :
			_tokens.append ("(")
			_tokens.append (str (quote_token ("\'?", _arguments[0])))
			for _argument in _arguments[1:] :
				_argument = str (quote_token ("\'?", _argument))
				_tokens.append (",")
				_tokens.append (_argument)
			_tokens.append (")")
		
		if _transforms is not None and len (_transforms) > 0 :
			for _transform in _transforms :
				_tokens.append (",")
				_tokens.append (_transform[0])
				if len (_transform) > 1 :
					_tokens.append ("(")
					_tokens.append (str (quote_token ("\'?", _transform[1])))
					for _transform_argument in _transform[2:] :
						_transform_argument = str (quote_token ("\'?", _transform_argument))
						_tokens.append (",")
						_tokens.append (_transform_argument)
					_tokens.append (")")
		
		_tokens = "".join (_tokens)
		
		self._generated = _tokens
		
		return self._generated
	
	
	def _expand (self) :
		
		_method = self._expand_and_enforce_token (
				self._method,
				basestring)
		
		_arguments = self._expand_and_enforce_token (
				self._arguments,
				{"type" : "or", "schemas" : (
						{"type" : tuple, "schema" : {"type" : "or", "schemas" : (basestring, int)}},
						basestring,
						int,
						None,
				)})
		if isinstance (_arguments, basestring) :
			_arguments = (_arguments,)
		
		_transforms = self._expand_and_enforce_token (
				self._transforms,
				{"type" : "or", "schemas" : (
						{"type" : tuple, "schema" :
								{"type" : "or", "schemas" : (
										{"type" : tuple, "schema" : {"type" : "or", "schemas" : (basestring, int)}},
										basestring,
										int,
								)}
						},
						basestring,
						None,
				)})
		if isinstance (_transforms, basestring) :
			_transforms = (_transforms,)
		if _transforms is not None :
			_transforms = [_transform if isinstance (_transform, tuple) else (_transform,) for _transform in _transforms]
			_transforms = tuple (_transforms)
		
		return _method, _arguments, _transforms
	
	
	def _self_expand_token (self) :
		return self.generate ()
	
	def _self_resolve_token (self) :
		return self.generate ()



class HaStatement (HaBase) :
	
	def __init__ (self, _parameters, enabled_if = True, order = None, overrides = None) :
		HaBase.__init__ (self)
		self._parameters = _parameters
		self._enabled_if = enabled_if
		self._order = order
		self._overrides = overrides
		if self._overrides is not None :
			self._parameters = self._parameters._fork (**self._overrides)
	
	def generate (self, _scroll, **_options) :
		_enabled = self._resolve_token (self._enabled_if)
		if _enabled is True :
			self._generate (_scroll, **_options)
		elif _enabled is False :
			pass
		else :
			raise_error ("b7e176f4", _enabled)
	
	def _generate (self, _scroll) :
		raise_error ("1ff66257")




class HaGenericStatement (HaStatement) :
	
	def __init__ (self, _parameters, _tokens, _comment, **_options) :
		HaStatement.__init__ (self, _parameters, **_options)
		self._tokens = _tokens
		self._comment = _comment
	
	def _generate (self, _scroll) :
		_contents = self._expand_token (self._tokens)
		if _contents is not None :
			if self._comment is not None :
				_scroll.include_normal_line_with_comment (self._order, 0, _contents, self._comment)
			else :
				_scroll.include_normal_line (self._order, 0, _contents)
		#if isinstance (self._tokens, list) :
		#	_contents = self._tokens
		#else :
		#	_contents = [self._tokens]
		#_contents = [self._expand_token (_tokens) for _tokens in _contents]
		#_contents = [_contents for _contents in _contents if _contents is not None]
		#for _contents in _contents :
		#	_scroll.include_normal_line (self._order, 0, _contents)




class HaStatementGroup (HaStatement) :
	
	def __init__ (self, _parameters, _heading, **_options) :
		HaStatement.__init__ (self, _parameters, **_options)
		if _heading is None :
			self._heading = None
		elif isinstance (_heading, basestring) :
			self._heading = (_heading,)
		elif isinstance (_heading, tuple) :
			self._heading = _heading
		else :
			raise_error ("7f294bbf", _heading)
		self._statements = list ()
	
	def declare (self, *_tokens, **_options) :
		while isinstance (_tokens, tuple) and len (_tokens) == 1 and isinstance (_tokens[0], tuple) :
			_tokens = _tokens[0]
		_comment = _options.get ("comment", None)
		_statement_comment = None
		if _comment is not None :
			_options = dict (_options)
			del _options["comment"]
		_statement = HaGenericStatement (self._parameters, _tokens, _comment, **_options)
		self._statements.append (_statement)
		return _statement
	
	def declare_group (self, _heading, *_statements, **_options) :
		_group = HaStatementGroup (self._parameters, _heading, **_options)
		_group._declare_recurse (list (_statements))
		self._statements.append (_group)
		return _group
	
	def _declare_recurse (self, _statement) :
		if isinstance (_statement, list) :
			for _statement in _statement :
				self._declare_recurse (_statement)
		elif isinstance (_statement, tuple) :
			self.declare (*_statement)
		elif isinstance (_statement, basestring) :
			self.declare (_statement)
		elif isinstance (_statement, int) :
			self.declare (_statement)
		elif callable (_statement) :
			self.declare (_statement)
		else :
			raise_error ("a67b1ba7", _statement)
	
	def _generate (self, _scroll, _merge = False) :
		_statements_scroll = Scroll ()
		for _statement in self._statements :
			_statement.generate (_statements_scroll)
		if not _statements_scroll.is_empty () :
			if _merge :
				_scroll.include_scroll_lines (self._order, 0, _statements_scroll, False)
			else :
				_self_scroll = Scroll ()
				_self_scroll.include_empty_line (0, 0, 1)
				if self._heading is not None :
					_heading = " -- ".join (self._heading)
					_self_scroll.include_comment_line (0, 0, HaStatementGroup.heading_prefix + _heading)
				_self_scroll.include_normal_line (0, 0, _statements_scroll)
				_self_scroll.include_empty_line (0, 0, 1)
				_scroll.include_normal_line (self._order, 0, _self_scroll)
	
	heading_prefix = "#---- "




