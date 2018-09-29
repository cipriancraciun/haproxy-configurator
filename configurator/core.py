



from parameters import Parameters
from scroll import Scroll

import default_parameters
import default_declares
import default_builders

from errors import *
from tools import *




def haproxy (_parameters = None, **_overrides) :
	_parameters = Parameters (_parameters, _overrides, default_parameters.parameters)
	return HaProxy (_parameters)

def parameters (_parameters = None, **_overrides) :
	return Parameters (_parameters, _overrides, default_parameters.parameters)

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
		
		self.globals = HaGlobals (self._parameters._fork ())
		self.defaults = HaDefaults (self._parameters._fork ())
		
		self._frontends = dict ()
		self._frontends_ordered = list ()
		
		self._backends = dict ()
		self._backends_ordered = list ()
		
		self._resolvers = dict ()
		self._resolvers_ordered = list ()
		
		self._credentials = dict ()
		self._credentials_ordered = list ()
	
	
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
		
		return _resolvers
	
	
	def credentials_create (self, _identifier, **_overrides) :
		
		_parameters = self._parameters._fork (**_overrides)
		_identifier = enforce_identifier (_parameters, _identifier)
		_parameters._set (credentials_identifier = _identifier)
		
		if _identifier in self._credentials :
			raise_error ("0e49fc8e", _identifier)
		
		_credentials = HaCredentials (_identifier, _parameters)
		self._credentials[_identifier] = _credentials
		self._credentials_ordered.append (_credentials)
		
		return _credentials
	
	
	def tcp_frontend_create (self, _identifier, **_overrides) :
		return self.frontend_create (_identifier, _type = HaTcpFrontend, frontend_mode = "tcp", **_overrides)
	
	def tcp_backend_create (self, _identifier, **_overrides) :
		return self.backend_create (_identifier, _type = HaTcpBackend, backend_mode = "tcp", **_overrides)
	
	
	def http_frontend_create (self, _identifier, **_overrides) :
		return self.frontend_create (_identifier, _type = HaHttpFrontend, frontend_mode = "http", **_overrides)
	
	def http_backend_create (self, _identifier, **_overrides) :
		return self.backend_create (_identifier, _type = HaHttpBackend, backend_mode = "http", **_overrides)
	
	
	def backend_builder (self) :
		return default_builders.HaBackendBuilder (self, self._parameters)
	
	
	def output_stdout (self) :
		_scroll = self.generate ()
		_scroll.output_stdout ()
	
	
	def generate (self) :
		
		self._declare_implicit_auto ()
		
		_scroll = Scroll ()
		_scroll.include_empty_line (99, 0, 8)
		
		_scroll.include_normal_line (100, 0, self.globals.generate ())
		_scroll.include_empty_line (100, 0, 8)
		
		_scroll.include_normal_line (200, 0, self.defaults.generate ())
		_scroll.include_empty_line (200, 0, 8)
		
		_scroll.include_normal_line (300, 0, [_frontend.generate () for _frontend in self._frontends_ordered])
		_scroll.include_empty_line (300, 0, 8)
		
		_scroll.include_normal_line (400, 0, [_backend.generate () for _backend in self._backends_ordered])
		_scroll.include_empty_line (400, 0, 8)
		
		_scroll.include_normal_line (500, 0, [_resolvers.generate () for _resolvers in self._resolvers_ordered])
		_scroll.include_empty_line (500, 0, 8)
		
		_scroll.include_normal_line (600, 0, [_credentials.generate () for _credentials in self._credentials_ordered])
		_scroll.include_empty_line (600, 0, 8)
		
		return _scroll
	
	
	def _declare_implicit_auto (self) :
		
		self.globals._declare_implicit_auto ()
		self.defaults._declare_implicit_auto ()
		
		for _frontend in self._frontends_ordered :
			_frontend._declare_implicit_auto ()
		
		for _backend in self._backends_ordered :
			_backend._declare_implicit_auto ()




class HaSection (HaBase) :
	
	def __init__ (self, _parameters, declare_implicit_if = True) :
		HaBase.__init__ (self)
		self._parameters = _parameters
		self._statements = HaStatementGroup (self._parameters, None)
		self._custom_statements = HaStatementGroup (self._parameters, "Custom")
		self._declare_implicit_if = declare_implicit_if
		self._declare_implicit_done = False
	
	
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
		_scroll.include_empty_line (99, 0, 4)
		_scroll.include_normal_line (100, 0, self._generate_header ())
		_scroll.include_empty_line (100, 0, 1)
		_scroll.include_normal_line (200, 0, self._generate_statements ())
		_scroll.include_empty_line (200, 0, 1)
		_scroll.include_normal_line (300, 0, self._generate_trailer ())
		_scroll.include_empty_line (300, 0, 4)
		return _scroll
	
	def _generate_header (self) :
		raise_error ("1adb835c")
	
	def _generate_trailer (self) :
		return Scroll ()
	
	def _generate_statements (self) :
		_scroll = Scroll (1)
		self._statements.generate (_scroll)
		self._generate_statements_extra (_scroll)
		self._custom_statements.generate (_scroll)
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		pass




class HaGlobals (HaSection) :
	
	def __init__ (self, _parameters) :
		HaSection.__init__ (self, _parameters)
	
	def _declare_implicit (self) :
		default_declares.declare_globals (self)
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, "global")
		return _scroll




class HaDefaults (HaSection) :
	
	def __init__ (self, _parameters) :
		HaSection.__init__ (self, _parameters)
	
	def _declare_implicit (self) :
		default_declares.declare_defaults (self)
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, "defaults")
		return _scroll




class HaResolvers (HaSection) :
	
	def __init__ (self, _identifier, _parameters) :
		HaSection.__init__ (self, _parameters)
		self.identifier = enforce_identifier (self._parameters, _identifier)
		self._nameserver_statements = HaStatementGroup (self._parameters, "Nameservers")
		
		self._parameter_statements = HaStatementGroup (self._parameters, "Parameters")
		self._parameter_statements.declare (("hold", "valid", statement_seconds (360)))
		self._parameter_statements.declare (("hold", "nx", statement_seconds (60)))
		self._parameter_statements.declare (("hold", "refused", statement_seconds (60)))
		self._parameter_statements.declare (("hold", "timeout", statement_seconds (60)))
		self._parameter_statements.declare (("hold", "other", statement_seconds (60)))
		self._parameter_statements.declare (("timeout", "retry", statement_seconds (1)))
		self._parameter_statements.declare (("resolve_retries", 4))
	
	
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
	
	def __init__ (self, _identifier, _parameters) :
		HaSection.__init__ (self, _parameters)
		self.identifier = enforce_identifier (self._parameters, _identifier)
		self._group_statements = HaStatementGroup (self._parameters, "Groups")
		self._user_statements = HaStatementGroup (self._parameters, "Users")
	
	
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
		self._http_request_rule_statements = HaStatementGroup (self._parameters, "HTTP Request Rules")
		self._http_response_rule_statements = HaStatementGroup (self._parameters, "HTTP Response Rules")
	
	
	def acl_1 (self, _criteria, _matcher, _patterns) :
		return self.acl_0 (None, _criteria, _matcher, None, None, _patterns)
	
	def acl_0 (self, _identifier, _criteria, _matcher, _flags, _operator, _patterns) :
		_acl = HaAcl (self._parameters, _identifier, _criteria, _matcher, _flags, _operator, _patterns)
		self._acl.append (_acl)
		return _acl
	
	def acl_builder (self) :
		return default_builders.HaAclBuilder (self, self._parameters)
	
	
	def sample_1 (self, _method, _arguments) :
		return self.sample_0 (_method, _arguments, None)
	
	def sample_0 (self, _method, _arguments, transforms) :
		_sample = HaSample (self._parameters, _method, _arguments, transforms)
		self._samples.append (_sample)
		return _sample
	
	def sample_builder (self) :
		return default_builders.HaSampleBuilder (self, self._parameters)
	
	
	def declare_http_request_rule_if (self, _action, _acl, order = None) :
		_condition = ("if", _acl, "TRUE")
		self.declare_http_request_rule_0 ((_action, _condition), order = order)
	
	def declare_http_request_rule_unless (self, _action, _acl, order = None) :
		_condition = ("unless", _acl, "TRUE")
		self.declare_http_request_rule_0 ((_action, _condition), order = order)
	
	def declare_http_request_rule_0 (self, _rule, order = None) :
		self._http_request_rule_statements.declare (("http-request", _rule), order = order)
	
	def http_request_rule_builder (self) :
		return default_builders.HaHttpRequestRuleBuilder (self, self._parameters)
	
	
	def declare_http_response_rule_if (self, _action, _acl, order = None) :
		_condition = ("if", _acl, "TRUE")
		self.declare_http_response_rule_0 ((_action, _condition), order = order)
	
	def declare_http_response_rule_unless (self, _action, _acl, order = None) :
		_condition = ("unless", _acl, "TRUE")
		self.declare_http_response_rule_0 ((_action, _condition), order = order)
	
	def declare_http_response_rule_0 (self, _rule, order = None) :
		self._http_response_rule_statements.declare (("http-response", _rule), order = order)
	
	def http_response_rule_builder (self) :
		return default_builders.HaHttpResponseRuleBuilder (self, self._parameters)
	
	
	def _generate_statements_for_acl (self, _scroll) :
		if len (self._acl) > 0 :
			_acl_uniques = set ()
			_acl_statements = list ()
			for _acl in self._acl :
				_acl_tokens = _acl.generate ()
				_acl_identifier = _acl._generated_identifier
				if (_acl_identifier, _acl._generated_fingerprint) in _acl_uniques :
					continue
				else :
					_acl_uniques.add ((_acl_identifier, _acl._generated_fingerprint))
				# print _acl_tokens
				if isinstance (_acl_tokens, list) :
					for _acl_tokens in _acl_tokens :
						_acl_statements.append ((_acl_identifier, _acl_tokens))
				else :
					_acl_statements.append ((_acl_identifier, _acl_tokens))
			_acl_statements.sort (key = lambda _acl_statement : _acl_statement[1][2:])
			_statements = HaStatementGroup (self._parameters, "ACL")
			for _acl_statement in _acl_statements :
				_statements.declare (_acl_statement[1])
			_statements.generate (_scroll)
	
	def _generate_statements_for_http_rules (self, _scroll) :
		self._http_request_rule_statements.generate (_scroll)
		self._http_response_rule_statements.generate (_scroll)
	
	
	def _self_expand_token (self) :
		return self.identifier
	
	def _self_resolve_token (self) :
		return self.identifier




class HaFrontend (HaWorker) :
	
	def __init__ (self, _identifier, _parameters) :
		HaWorker.__init__ (self, _identifier, _parameters)
		self._bind_statements = HaStatementGroup (self._parameters, "Sockets")
		self._route_statements = HaStatementGroup (self._parameters, "Routes")
		self._request_capture_statements = HaStatementGroup (self._parameters, "Captures for requests")
		self._request_captures_count = 0
		self._response_capture_statements = HaStatementGroup (self._parameters, "Captures for responses")
		self._response_captures_count = 0
	
	
	def declare_bind (self, _endpoint, _name = None, _options = "$frontend_bind_options", order = None) :
		_name = statement_choose_if (_name, ("name", statement_quote ("\'", _name)))
		self._bind_statements.declare (("bind", statement_quote ("\'", _endpoint), _name, _options), order = order)
	
	def declare_bind_tls (self, _endpoint, _name = None, _certificate = "$\'frontend_bind_tls_certificate", _certificate_rules = "$\'frontend_bind_tls_certificate_rules", _options = "$frontend_bind_tls_options", order = None, overrides = None) :
		_tls_options = ["ssl"]
		if _certificate is not None :
			_tls_options.append (("crt", _certificate))
		if _certificate_rules is not None :
			_tls_options.append (("crt-list", _certificate_rules))
		_tls_options = tuple (_tls_options)
		_name = statement_choose_if (_name, ("name", statement_quote ("\'", _name)))
		self._bind_statements.declare (("bind", statement_quote ("\'", _endpoint), _name, _tls_options, _options), order = order, overrides = overrides)
	
	
	def declare_route_if_0 (self, _backend, _acl, order = None) :
		_condition = ("if", _acl, "TRUE")
		self._route_statements.declare (("use_backend", _backend, _condition), order = order)
	
	def declare_route_unless_0 (self, _backend, _acl, order = None) :
		_condition = ("unless", _acl, "TRUE")
		self._route_statements.declare (("use_backend", _backend, _condition), order = order)
	
	def route_builder (self, **_overrides) :
		return default_builders.HaRouteBuilder (self, self._parameters, **_overrides)
	
	
	def _declare_request_capture (self, _length = "$+frontend_capture_length") :
		_index = self._request_captures_count
		self._request_captures_count += 1
		self._request_capture_statements.declare (("declare", "capture", "request", "len", statement_enforce_int (_length)))
		return _index
	
	def _declare_response_capture (self, _length = "$+frontend_capture_length") :
		_index = self._response_captures_count
		self._response_captures_count += 1
		self._response_capture_statements.declare (("declare", "capture", "response", "len", statement_enforce_int (_length)))
		return _index
	
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, self._expand_token (("frontend", "$\'frontend_identifier")))
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		self._generate_statements_for_binds (_scroll)
		self._generate_statements_for_captures (_scroll)
		self._generate_statements_for_acl (_scroll)
		self._generate_statements_for_http_rules (_scroll)
		self._generate_statements_for_routes (_scroll)
	
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
		self._server_statements = HaStatementGroup (self._parameters, "Servers")
	
	
	def declare_server (self, _identifier, _endpoint, _options = "$server_options", _acl = None, order = None, **_overrides) :
		_identifier = enforce_identifier (self._parameters, _identifier)
		_options = statement_overrides (_options, **_overrides)
		if _acl is not None :
			self._server_statements.declare (("use-server", statement_quote ("\'", _identifier), "if", _acl), order = order)
		self._server_statements.declare (("server", statement_quote ("\'", _identifier), statement_quote ("\'", _endpoint), _options), order = order)
	
	
	def _generate_header (self) :
		_scroll = Scroll ()
		_scroll.include_normal_line (0, 0, self._expand_token (("backend", "$\'backend_identifier")))
		return _scroll
	
	def _generate_statements_extra (self, _scroll) :
		self._generate_statements_for_acl (_scroll)
		self._generate_statements_for_http_rules (_scroll)
		self._generate_statements_for_servers (_scroll)
	
	def _generate_statements_for_servers (self, _scroll) :
		self._server_statements.generate (_scroll)




class HaTcpFrontend (HaFrontend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaFrontend.__init__ (self, _identifier, _parameters, **_options)
	
	def _declare_implicit (self, **_options) :
		default_declares.declare_tcp_frontend (self, **_options)


class HaTcpBackend (HaBackend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaBackend.__init__ (self, _identifier, _parameters, **_options)
	
	def _declare_implicit (self, **_options) :
		default_declares.declare_tcp_backend (self, **_options)




class HaHttpFrontend (HaFrontend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaFrontend.__init__ (self, _identifier, _parameters, **_options)
	
	def _declare_implicit (self, **_options) :
		default_declares.declare_http_frontend (self, **_options)


class HaHttpBackend (HaBackend) :
	
	def __init__ (self, _identifier, _parameters, **_options) :
		HaBackend.__init__ (self, _identifier, _parameters, **_options)
	
	def _declare_implicit (self, **_options) :
		default_declares.declare_http_backend (self, **_options)




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
	
	
	def identifier (self) :
		self.generate ()
		return self._generated_identifier
	
	
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
		
		if _flags is not None :
			for _flag in _flags :
				_tokens.append (_flag)
		
		if _operator is not None :
			_tokens.append (_operator)
		
		if _patterns is not None :
			
			_tokens.append ("--")
			
			_patterns_batch = 1
			if len (_patterns) <= _patterns_batch :
				for _pattern in _patterns :
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
		return self.identifier ()
	
	def _self_resolve_token (self) :
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
		return self.identifier ()
	
	def _self_resolve_token (self) :
		return self.identifier ()




class HaSample (HaBase) :
	
	
	def __init__ (self, _parameters, _method, _arguments, _transforms) :
		HaBase.__init__ (self)
		self._parameters = _parameters
		self._method = _method
		self._arguments = _arguments
		self._transforms = _transforms
		self._generated = None
	
	
	def generate (self) :
		
		if self._generated is not None :
			return self._generated
		
		_method, _arguments, _transforms = self._expand ()
		
		_tokens = list ()
		
		_tokens.append (_method)
		
		_tokens.append ("(")
		if _arguments is not None and len (_arguments) > 0 :
			_tokens.append (_arguments[0])
			for _argument in _arguments[1:] :
				_argument = str (_argument)
				_tokens.append (",")
				_tokens.append (_argument)
		_tokens.append (")")
		
		if _transforms is not None and len (_transforms) > 0 :
			for _transform in _transforms :
				_tokens.append (",")
				_tokens.append (_transform[0])
				if len (_transform) > 1 :
					_tokens.append ("(")
					_tokens.append (_transform[1])
					for _transform_argument in _transforms[2:] :
						_transform_argument = str (_transform_argument)
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
	
	def generate (self, _scroll) :
		_enabled = self._resolve_token (self._enabled_if)
		if _enabled is True :
			self._generate (_scroll)
		elif _enabled is False :
			pass
		else :
			raise_error ("b7e176f4", _enabled)
	
	def _generate (self, _scroll) :
		raise_error ("1ff66257")




class HaGenericStatement (HaStatement) :
	
	def __init__ (self, _parameters, _tokens, **_options) :
		HaStatement.__init__ (self, _parameters, **_options)
		self._tokens = _tokens
	
	def _generate (self, _scroll) :
		_contents = self._expand_token (self._tokens)
		if _contents is not None :
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
		self._heading = _heading
		self._statements = list ()
	
	def declare (self, *_tokens, **_options) :
		while isinstance (_tokens, tuple) and len (_tokens) == 1 and isinstance (_tokens[0], tuple) :
			_tokens = _tokens[0]
		_statement = HaGenericStatement (self._parameters, _tokens, **_options)
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
	
	def _generate (self, _scroll) :
		_statements_scroll = Scroll ()
		for _statement in self._statements :
			_statement.generate (_statements_scroll)
		if not _statements_scroll.is_empty () :
			_self_scroll = Scroll ()
			_self_scroll.include_empty_line (0, 0, 1)
			if self._heading is not None :
				_self_scroll.include_comment_line (0, 0, HaStatementGroup.heading_prefix + self._heading)
			_self_scroll.include_normal_line (0, 0, _statements_scroll)
			_self_scroll.include_empty_line (0, 0, 1)
			_scroll.include_normal_line (self._order, 0, _self_scroll)
	
	heading_prefix = "#---- "




