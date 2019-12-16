



from tools import *
from tools import __default__




class HaBuilder (object) :
	
	def __init__ (self, _context, _parameters) :
		self._context = _context
		self._parameters = _parameters
	
	def _value_or_parameters_get_and_expand (self, _value, _parameter, _default = __default__, parameters = None, overrides = None) :
		if _value is not None :
			return _value
		else :
			return self._parameters_get_and_expand (_parameter, _default, parameters, overrides)
	
	def _parameters_get_and_expand (self, _parameter, _default = __default__, parameters = None, overrides = None) :
		_parameters, _overrides = self._resolve_parameters_overrides (parameters, overrides)
		if _overrides is not None and _parameter in _overrides :
			return _overrides[_parameter]
		_default = _default if _default is not __default__ else self._parameters._get_fallback_enabled
		return _parameters._get_and_expand (_parameter, _default)
	
	def _parameters_get (self, _parameter, _default = __default__, parameters = None, overrides = None) :
		_parameters, _overrides = self._resolve_parameters_overrides (parameters, overrides)
		if _overrides is not None and _parameter in _overrides :
			return _overrides[_parameter]
		_default = _default if _default is not __default__ else self._parameters._get_fallback_enabled
		return self._parameters._get (_parameter, _default)
	
	def _parameters_expand (self, _parameter, overrides = None) :
		_parameters, _overrides = self._resolve_parameters_overrides (parameters, overrides)
		if _overrides is not None and _parameter in _overrides :
			return _overrides[_parameter]
		return self._parameters._expand (_parameter)
	
	def _resolve_parameters_overrides (self, _parameters, _overrides) :
		if _parameters is not None :
			_parameters = parameters
		else :
			_parameters = self._parameters
		return _parameters, _overrides
	
	def _one_or_many (self, _value) :
		if isinstance (_value, tuple) or isinstance (_value, list) :
			return _value
		else :
			return (_value,)




class HaHttpAclBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
		self._samples = HaHttpSampleBuilder (_context, _parameters)
	
	
	def client_ip (self, _ip, _method = None, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.client_ip (_method), "ip", None, None, _ip)
	
	def frontend_port (self, _port, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.frontend_port (), "int", None, "eq", (_port,))
	
	
	def forwarded_host (self, _host, _from_logging = False, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.forwarded_host (None, _from_logging), "str", ("-i",), "eq", _host)
	
	def forwarded_for (self, _ip, _from_logging = False, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.forwarded_for (None, _from_logging), "ip", None, None, (_ip,))
	
	def forwarded_proto (self, _proto, _from_logging = False, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.forwarded_proto (None, _from_logging), "str", ("-i"), "eq", (_proto,))
	
	def forwarded_port (self, _port, _from_logging = False, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.forwarded_for (None, _from_logging), "int", None, "eq", (_port,))
	
	
	def host (self, _host, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.host (), "str", ("-i",), "eq", _host)
	
	def host_prefix (self, _host, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.host (), "beg", ("-i",), None, _host)
	
	def host_suffix (self, _host, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.host (), "end", ("-i",), None, _host)
	
	
	def path (self, _path, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.path (), "str", None, "eq", _path)
	
	def path_prefix (self, _path, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.path (), "beg", None, None, _path)
	
	def path_suffix (self, _path, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.path (), "end", None, None, _path)
	
	def path_substring (self, _path, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.path (), "sub", None, None, _path)
	
	def subpath (self, _path, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.path (), "dir", None, None, _path)
	
	def path_regex (self, _path_regex, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.path (), "reg", None, None, _path_regex)
	
	
	def query (self, _query, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.query (), "str", None, "eq", _query)
	
	def query_empty (self, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.query (), "len", None, None, (0,))
	
	def query_prefix (self, _query, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.query (), "beg", None, None, _query)
	
	def query_exists (self, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.query (), "found", None, None, None)
	
	
	def query_parameter (self, _parameter, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.query_parameter (_parameter), "str", None, "eq", _value)
	
	def query_parameter_exists (self, _parameter, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.query_parameter (_parameter), "found", None, None, None)
	
	
	def request_method (self, _method, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_method (), "str", ("-i",), "eq", (_method,))
	
	def response_status (self, _code, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_status (), "int", None, "eq", (_code,))
	
	
	def request_header (self, _name, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_name), "str", None, "eq", (_value,))
	
	def request_header_exists (self, _header, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header_exists (_header, _expected), "bool", None, None, None)
	
	def response_header (self, _name, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_name), "str", None, "eq", (_value,))
	
	def response_header_exists (self, _header, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header_exists (_header, _expected), "bool", None, None, None)
	
	
	def request_cookie_exists (self, _cookie, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_cookie_exists (_cookie, _expected), "bool", None, None, None)
	
	def response_cookie_exists (self, _cookie, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_cookie_exists (_header, _expected), "bool", None, None, None)
	
	
	def variable_bool (self, _variable, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable_bool (_variable, _expected), "bool", None, None, None)
	
	def variable_exists (self, _variable, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "found", None, None, None)
	
	def variable_equals (self, _variable, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "str", None, "eq", _value)
	
	def variable_prefix (self, _variable, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "beg", None, None, _value)
	
	
	def via_tls (self, _expected = True, _method = None, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.via_tls (_expected, _method), "bool", None, None, None)
	
	def tls_client_certificate (self, _fingerprint, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_client_certificate (), "str", ("-i",), "eq", (_fingerprint,))
	
	
	def authenticated (self, _credentials, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.authenticated (_credentials, _expected), "bool", None, None, None)
	
	
	def backend_active (self, _backend, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.backend_active (_backend, _expected), "bool", None, None, None)
	
	
	def geoip_country_extracted (self, _country, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.geoip_country_extracted (), "str", None, "eq", _country)
	
	def geoip_country_captured (self, _country, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.geoip_country_captured (), "str", None, "eq", _country)
	
	
	def bot (self, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header ("User-Agent", ("lower",)), "str", ("-i", "-f"), "sub", "$'bots_acl")
	
	
	def ab_in_bucket (self, _expected, _count, _criteria = None, _identifier = None) :
		if _criteria == "session" :
			_sample = self._samples.variable ("$http_tracking_session_variable", (("wt6", 1), ("mod", _count)))
		elif _criteria == "request" :
			_sample = self._samples.variable ("$http_tracking_request_variable", (("wt6", 1), ("mod", _count)))
		elif _criteria == "agent" :
			_sample = self._samples.variable ("$logging_http_variable_agent", (("wt6", 1), ("mod", _count)))
		elif _criteria == "ip" :
			_sample = self._samples.variable ("$logging_http_variable_forwarded_for", (("wt6", 1), ("mod", _count)))
		elif _criteria == "path" :
			_sample = self._samples.variable ("$logging_http_variable_path", (("wt6", 1), ("mod", _count)))
		elif _criteria == "action" :
			_sample = self._samples.variable ("$logging_http_variable_action", (("wt6", 1), ("mod", _count)))
		else :
			raise_error ("34cca11c", _criteria)
		return self._context.acl_0 (_identifier, _sample, "int", None, "eq", (_expected,))




class HaHttpSampleBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
	
	
	def client_ip (self, _method = None, _transforms = None) :
		if _method is None :
			_method = self._parameters._get_and_expand ("samples_client_ip_method")
		if _method == "src" :
			return self._context.sample_0 ("src", None, _transforms)
		elif _method == "X-Forwarded-For" :
			return self._context.sample_0 ("req.hdr", ("$logging_http_header_forwarded_for", 1), _transforms)
		else :
			raise_error ("fd58dd1e", _method)
	
	def frontend_port (self, _transforms = None) :
		return self._context.sample_0 ("dst_port", None, _transforms)
	
	
	def forwarded_host (self, _transforms = None, _from_logging = False) :
		if _from_logging :
			return self._context.sample_0 ("var", ("$logging_http_variable_forwarded_host",), _transforms)
		else :
			return self._context.sample_0 ("req.hdr", ("$logging_http_header_forwarded_host", 1), _transforms)
	
	def forwarded_for (self, _transforms = None, _from_logging = False) :
		if _from_logging :
			return self._context.sample_0 ("var", ("$logging_http_variable_forwarded_for",), _transforms)
		else :
			return self._context.sample_0 ("req.hdr", ("$logging_http_header_forwarded_for", 1), _transforms)
	
	def forwarded_proto (self, _transforms = None, _from_logging = False) :
		if _from_logging :
			return self._context.sample_0 ("var", ("$logging_http_variable_forwarded_proto",), _transforms)
		else :
			return self._context.sample_0 ("req.hdr", ("$logging_http_header_forwarded_proto", 1), _transforms)
	
	def forwarded_port (self, _transforms = None, _from_logging = False) :
		if _from_logging :
			return self._context.sample_0 ("var", ("$logging_http_variable_forwarded_port",), _transforms)
		else :
			return self._context.sample_0 ("req.hdr", ("$logging_http_header_forwarded_port", 1), _transforms)
	
	
	def host (self, _transforms = None) :
		if _transforms is None :
			_transforms = ("lower",)
		return self._context.sample_0 ("req.fhdr", ("Host", -1), _transforms)
	
	def path (self, _transforms = None) :
		return self._context.sample_0 ("path", None, _transforms)
	
	def query (self, _transforms = None) :
		return self._context.sample_0 ("query", None, _transforms)
	
	def query_parameter (self, _parameter, _transforms = None) :
		return self._context.sample_0 ("url_param", (_parameter,), _transforms)
	
	
	def request_method (self, _transforms = None) :
		if _transforms is None :
			_transforms = ("upper",)
		return self._context.sample_0 ("method", None, _transforms)
	
	def response_status (self, _transforms = None) :
		return self._context.sample_0 ("status", None, _transforms)
	
	
	def request_header (self, _header, _transforms = None, _index = None) :
		if _index is None :
			_index = -1
		return self._context.sample_0 ("req.fhdr", (_header, _index), _transforms)
	
	def response_header (self, _header, _transforms = None, _index = None) :
		if _index is None :
			_index = -1
		return self._context.sample_0 ("res.fhdr", (_header, _index), _transforms)
	
	
	def request_cookie (self, _cookie, _transforms = None) :
		return self._context.sample_0 ("req.cook", (_cookie,), _transforms)
	
	def response_cookie (self, _cookie, _transforms = None) :
		return self._context.sample_0 ("res.cook", (_cookie,), _transforms)
	
	
	def request_header_exists (self, _header, _expected = True) :
		return self._context.sample_0 ("req.fhdr_cnt", (_header,), ("bool" if _expected else ("bool", "not")))
	
	def response_header_exists (self, _header, _expected = True) :
		return self._context.sample_0 ("res.fhdr_cnt", (_header,), ("bool" if _expected else ("bool", "not")))
	
	
	def request_cookie_exists (self, _cookie, _expected = True) :
		return self._context.sample_0 ("req.cook_cnt", (_cookie,), ("bool" if _expected else ("bool", "not")))
	
	def response_cookie_exists (self, _cookie, _expected = True) :
		return self._context.sample_0 ("res.cook_cnt", (_cookie,), ("bool" if _expected else ("bool", "not")))
	
	
	def variable (self, _variable, _transforms = None) :
		return self._context.sample_0 ("var", (_variable,), _transforms)
	
	def variable_bool (self, _variable, _expected = True) :
		return self._context.sample_0 ("var", (_variable,), ("bool" if _expected else ("bool", "not")))
	
	
	def via_tls (self, _expected = True, _method = None) :
		if _method is None :
			_method = self._parameters._get_and_expand ("samples_via_tls_method")
		if _method == "ssl_fc" :
			return self._context.sample_0 ("ssl_fc", None, (None if _expected else "not"))
		elif _method == "dst_port_443" :
			return self._context.sample_0 ("dst_port", None, (("xor", 443), "bool", ("not" if _expected else None)))
		elif _method == "X-Forwarded-Port-443" :
			return self._context.sample_0 ("req.hdr", ("$logging_http_header_forwarded_port", 1), (("xor", 443), "bool", ("not" if _expected else None)))
		else :
			raise_error ("fd58dd1e", self)
	
	def tls_client_certificate (self) :
		return self._context.sample_0 ("ssl_c_sha1", None, "hex")
	
	
	def authenticated (self, _credentials, _expected = True) :
		return self._context.sample_0 ("http_auth", (_credentials,), ("bool" if _expected else ("bool", "not")))
	
	def authenticated_group (self, _credentials, _transforms = None) :
		return self._context.sample_0 ("http_auth_group", (_credentials,), _transforms)
	
	
	def backend_active (self, _backend, _expected = True) :
		return self._context.sample_0 ("nbsrv", (_backend,), ("bool" if _expected else ("bool", "not")))
	
	
	def geoip_country_extracted (self, _method = None) :
		return self.client_ip (_method, (("map_ip", "$geoip_map"),))
	
	def geoip_country_captured (self) :
		return self.variable ("$logging_geoip_country_variable")




class HaHttpRuleBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
		self._acl = HaHttpAclBuilder (_context, _parameters)
		self._samples = HaHttpSampleBuilder (_context, _parameters)
	
	def _declare_http_rule_0 (self, _rule, _condition, **_overrides) :
		if isinstance (self, HaHttpRequestRuleBuilder) :
			self._context.declare_http_request_rule_0 ((_rule, _condition), **_overrides)
		elif isinstance (self, HaHttpResponseRuleBuilder) :
			self._context.declare_http_response_rule_0 ((_rule, _condition), **_overrides)
		else :
			raise_error ("508829d5", self)
	
	
	def allow (self, _acl, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("allow",)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def allow_path (self, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path (_path)
		self.allow ((_acl, _acl_path), **_overrides)
	
	def allow_path_prefix (self, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path_prefix (_path)
		self.allow ((_acl, _acl_path), **_overrides)
	
	def allow_path_suffix (self, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path_suffix (_path)
		self.allow ((_acl, _acl_path), **_overrides)
	
	def allow_path_substring (self, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path_substring (_path)
		self.allow ((_acl, _acl_path), **_overrides)
	
	def allow_subpath (self, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.subpath (_path)
		self.allow ((_acl, _acl_path), **_overrides)
	
	
	def deny (self, _code, _acl = None, _mark = None, **_overrides) :
		# FIXME:  Make this configurable and deferable!
		if _mark is not None and _mark != 0 :
			self.set_mark (_mark, _acl, **_overrides)
		_rule_condition = self._context._condition_if (_acl)
		_deny_rule = ("deny", statement_choose_if_non_null (_code, ("deny_status", statement_enforce_int (_code))))
		self._declare_http_rule_0 (_deny_rule, _rule_condition, **_overrides)
	
	def deny_host (self, _host, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_host = self._acl.host (_host)
		self.deny (_code, (_acl, _acl_host), _mark, **_overrides)
	
	def deny_path (self, _path, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_path = self._acl.path (_path)
		self.deny (_code, (_acl, _acl_path), _mark, **_overrides)
	
	def deny_path_prefix (self, _path, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_path = self._acl.path_prefix (_path)
		self.deny (_code, (_acl, _acl_path), _mark, **_overrides)
	
	def deny_path_suffix (self, _path, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_path = self._acl.path_suffix (_path)
		self.deny (_code, (_acl, _acl_path), _mark, **_overrides)
	
	def deny_path_substring (self, _path, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_path = self._acl.path_substring (_path)
		self.deny (_code, (_acl, _acl_path), _mark, **_overrides)
	
	def deny_subpath (self, _path, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_path = self._acl.subpath (_path)
		self.deny (_code, (_acl, _acl_path), _mark, **_overrides)
	
	def deny_geoip_country (self, _country, _negated = False, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_country = self._acl.geoip_country_captured (_country)
		if _negated :
			_acl_country = _acl_country.negate ()
		self.deny (_code, (_acl, _acl_country), _mark, **_overrides)
	
	def deny_bot (self, _acl = None, _code = None, _mark = None, **_overrides) :
		_acl_bot = self._acl.bot ()
		self.deny (_code, (_acl, _acl_bot), _mark, **_overrides)
	
	
	def set_header (self, _header, _value, _ignore_if_exists = False, _acl = None, **_overrides) :
		_acl_exists = self._header_acl_exists (_header) if _ignore_if_exists else None
		_rule_condition = self._context._condition_if ((_acl, _acl_exists))
		_rule = ("set-header", statement_quote ("\"", _header), statement_quote ("\"", _value))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def delete_header (self, _header, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("del-header", statement_quote ("\"", _header))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def append_header (self, _header, _value, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("add-header", statement_quote ("\"", _header), statement_quote ("\"", _value))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def _header_acl_exists (self, _header) :
		if isinstance (self, HaHttpRequestRuleBuilder) :
			return self._acl.request_header_exists (_header, False)
		elif isinstance (self, HaHttpResponseRuleBuilder) :
			return self._acl.response_header_exists (_header, False)
		else :
			raise_error ("b0203fc6", self)
	
	
	def set_cookie (self, _name, _value, _path, _max_age, _same_site, _secure, _http_only, _acl = None, **_overrides) :
		# FIXME:  Make `Path` and `Max-Age` configurable!
		_path = statement_choose_if (_path, statement_format ("Path=%s", statement_enforce_string (_path)))
		_max_age = statement_choose_if (_max_age, statement_format ("Max-Age=%d", statement_enforce_int (_max_age)))
		_cookie = statement_format ("%s=%s", statement_enforce_string (_name), statement_enforce_string (_value))
		_cookie = [_cookie, _path, _max_age]
		if _same_site is not None :
			if _same_site is True :
				_same_site = "Strict"
			elif _same_site is False :
				_same_site = "None"
			_cookie.append (statement_format ("SameSite=%s", statement_enforce_string (_same_site)))
		_cookie.append (statement_choose_if (_secure, "Secure"))
		_cookie.append (statement_choose_if (_http_only, "HttpOnly"))
		_cookie = statement_join ("; ", tuple (_cookie))
		self.append_header ("Set-Cookie", _cookie, _acl, **_overrides)
	
	
	def set_variable (self, _variable, _value, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		if isinstance (_value, basestring) :
			_value = "str(%s)" % quote_token ("\'", _value)
		_rule = (statement_format ("set-var(%s)", _variable), _value)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def set_enabled (self, _variable, _acl = None, **_overrides) :
		self.set_variable (_variable, ("bool(true)",), _acl, **_overrides)
	
	def set_disabled (self, _variable, _acl = None, **_overrides) :
		self.set_variable (_variable, ("bool(false)",), _acl, **_overrides)
	
	
	def track_enable (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_tracking_enabled_variable", _acl, **_overrides)
	
	def track_exclude (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_tracking_excluded_variable", _acl, **_overrides)
	
	
	def harden_enable (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_harden_enabled_variable", _acl, **_overrides)
	
	def harden_exclude (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_harden_excluded_variable", _acl, **_overrides)
	
	
	def drop_caching_enable (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_drop_caching_enabled_variable", _acl, **_overrides)
	
	def drop_caching_exclude (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_drop_caching_excluded_variable", _acl, **_overrides)
	
	
	def force_caching_enable (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_force_caching_enabled_variable", _acl, **_overrides)
	
	def force_caching_exclude (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_force_caching_excluded_variable", _acl, **_overrides)
	
	
	def drop_cookies_enable (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_drop_cookies_enabled_variable", _acl, **_overrides)
	
	def drop_cookies_exclude (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_drop_cookies_excluded_variable", _acl, **_overrides)
	
	
	def force_cors_enable (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_force_cors_enabled_variable", _acl, **_overrides)
	
	def force_cors_exclude (self, _acl = None, **_overrides) :
		self.set_enabled ("$http_force_cors_excluded_variable", _acl, **_overrides)
	
	
	def set_mark (self, _mark, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_mark_rule = ("set-mark", statement_format ("0x%08x", statement_enforce_int (_mark)))
		self._declare_http_rule_0 (_mark_rule, _rule_condition, **_overrides)
	
	
	def redirect (self, _target, _code = 307, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("redirect", "location", statement_quote ("\"", _target), "code", _code)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def redirect_with_path (self, _path, _code = 307, _acl = None, _include_scheme = True, _include_host = True, **_overrides) :
		if _include_scheme and _include_host :
			_target = statement_format ("%%[%s]://%%[%s]%s", self._samples.forwarded_proto (), self._samples.forwarded_host (), _path)
		elif _include_host :
			_target = statement_format ("//%%[%s]%s", self._samples.forwarded_host (), _path)
		else :
			_target = _path
		self.redirect (_target, _code = _code, _acl = _acl, **_overrides)
	
	def redirect_with_path_prefix (self, _path_prefix, _code = 307, _acl = None, _include_scheme = True, _include_host = True, **_overrides) :
		_path = statement_format ("%s%%[%s]", _path_prefix, self._samples.path ())
		self.redirect_with_path (_path, _code = _code, _acl = _acl, _include_scheme = _include_scheme, _include_host = _include_host, **_overrides)
	
	def redirect_with_path_suffix (self, _path_suffix, _code = 307, _acl = None, _include_scheme = True, _include_host = True, **_overrides) :
		_path = statement_format ("%%[%s]%s", self._samples.path (), _path_suffix)
		self.redirect_with_path (_path, _code = _code, _acl = _acl, _include_scheme = _include_scheme, _include_host = _include_host, **_overrides)
	
	def redirect_prefix (self, _target, _code = 307, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("redirect", "prefix", statement_quote ("\"", _target), "code", _code)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def redirect_via_tls (self, _code = 307, _acl = None, **_overrides) :
		_acl_non_tls = self._acl.via_tls (False)
		_rule_condition = self._context._condition_if ((_acl, _acl_non_tls))
		_rule = ("redirect", "scheme", "https", "code", _code)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	
	def track_stick (self, _source = None, _acl = None, **_overrides) :
		if _source is None :
			_source = "$frontend_http_stick_source"
		_source = statement_choose_match (_source,
					("src", "src"),
					("X-Forwarded-For", statement_format ("req.hdr(%s,1)", "$logging_http_header_forwarded_for")),
			)
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("track-sc0", _source)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)




class HaHttpRequestRuleBuilder (HaHttpRuleBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaHttpRuleBuilder.__init__ (self, _context, _parameters)
	
	
	def set_method (self, _method, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-method", statement_quote ("\'", _method))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def set_path (self, _path, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-path", statement_quote ("\"", _path))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def set_path_prefix (self, _path_prefix, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-path", statement_quote ("\"", statement_format ("%s%%[%s]", _path_prefix, self._samples.path ())))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def set_path_suffix (self, _path_suffix, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-path", statement_quote ("\"", statement_format ("%%[%s]%s", self._samples.path (), _path_suffix)))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def set_query (self, _query, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-query", statement_quote ("\"", _query))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def set_uri (self, _uri, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-uri", statement_quote ("\"", _uri))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	
	def set_enabled_for_domain (self, _variable, _domain, _acl = None, **_overrides) :
		_acl_host = self._acl.host (_domain)
		self.set_enabled (_variable, (_acl, _acl_host), **_overrides)
	
	
	def redirect_domain_via_tls (self, _domain, _only_root = False, _code = 307, _acl = None, **_overrides) :
		for _domain in sorted (self._one_or_many (_domain)) :
			_acl_host = self._acl.host (_domain)
			_acl_non_tls = self._acl.via_tls (False)
			_acl_path = self._acl.path ("/") if _only_root else None
			_rule_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_non_tls))
			_rule = ("redirect", "scheme", "https", "code", _code)
			self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def redirect_domain_with_www (self, _domain, _only_root = False, _force_tls = False, _code = 307, _acl = None, **_overrides) :
		for _domain in sorted (self._one_or_many (_domain)) :
			if _domain.startswith ("www.") :
				_domain = _domain[4:]
			_redirect_tls = statement_quote ("\"", statement_format ("https://www.%s", _domain))
			_redirect_non_tls = statement_quote ("\"", statement_format ("http://www.%s", _domain)) if not _force_tls else _redirect_tls
			_acl_host = self._acl.host (statement_format ("%s", _domain))
			_acl_path = self._acl.path ("/") if _only_root else None
			_acl_non_tls = self._acl.via_tls (False)
			_acl_tls = self._acl.via_tls (True)
			_rule_non_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_non_tls))
			_rule_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_tls))
			_rule_non_tls = ("redirect", "prefix", _redirect_non_tls, "code", _code)
			_rule_tls = ("redirect", "prefix", _redirect_tls, "code", _code)
			self._declare_http_rule_0 (_rule_non_tls, _rule_non_tls_condition, **_overrides)
			self._declare_http_rule_0 (_rule_tls, _rule_tls_condition, **_overrides)
	
	def redirect_domain_without_www (self, _domain, _only_root = False, _force_tls = False, _code = 307, _acl = None, **_overrides) :
		for _domain in sorted (self._one_or_many (_domain)) :
			if _domain.startswith ("www.") :
				_domain = _domain[4:]
			_redirect_tls = statement_quote ("\"", statement_format ("https://%s", _domain))
			_redirect_non_tls = statement_quote ("\"", statement_format ("http://%s", _domain)) if not _force_tls else _redirect_tls
			_acl_host = self._acl.host (statement_format ("www.%s", _domain))
			_acl_path = self._acl.path ("/") if _only_root else None
			_acl_non_tls = self._acl.via_tls (False)
			_acl_tls = self._acl.via_tls (True)
			_rule_non_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_non_tls))
			_rule_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_tls))
			_rule_non_tls = ("redirect", "prefix", _redirect_non_tls, "code", _code)
			_rule_tls = ("redirect", "prefix", _redirect_tls, "code", _code)
			self._declare_http_rule_0 (_rule_non_tls, _rule_non_tls_condition, **_overrides)
			self._declare_http_rule_0 (_rule_tls, _rule_tls_condition, **_overrides)
	
	def redirect_domain (self, _source, _target, _force_tls = False, _redirect_code = 307, _acl = None, **_overrides) :
		_redirect_tls = statement_quote ("\"", statement_format ("https://%s", _target))
		_redirect_non_tls = statement_quote ("\"", statement_format ("http://%s", _target)) if not _force_tls else _redirect_tls
		_acl_host = self._acl.host (_source)
		_acl_non_tls = self._acl.via_tls (False)
		_acl_tls = self._acl.via_tls (True)
		_rule_non_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_non_tls))
		_rule_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_tls))
		_rule_non_tls = ("redirect", "prefix", _redirect_non_tls, "code", _redirect_code)
		_rule_tls = ("redirect", "prefix", _redirect_tls, "code", _redirect_code)
		self._declare_http_rule_0 (_rule_non_tls, _rule_non_tls_condition, **_overrides)
		self._declare_http_rule_0 (_rule_tls, _rule_tls_condition, **_overrides)
	
	def redirect_domain_and_path (self, _source, _target, _force_tls = False, _redirect_code = 307, _acl = None, **_overrides) :
		_source_domain, _source_path, _source_path_exact, _negate = _source
		_target_domain, _target_path, _target_path_exact = _target
		if _target_path is None :
			_target_path = ""
			_redirect_method = "prefix"
			if _target_path_exact is not None :
				raise_error ("c951cde1", _source, _target)
		else :
			if _target_path_exact is True :
				_redirect_method = "location"
			elif _target_path_exact is False :
				_redirect_method = "prefix"
			else :
				raise_error ("925d9f3b", _source, _target)
		if _target_domain is not None :
			_redirect_tls = statement_quote ("\"", statement_format ("https://%s%s", _target_domain, _target_path))
			_redirect_non_tls = statement_quote ("\"", statement_format ("http://%s%s", _target_domain, _target_path)) if not _force_tls else _redirect_tls
		else :
			if _force_tls :
				raise_error ("923c4768", _source, _target)
			_redirect_non_tls = statement_quote ("\"", _target_path)
			_redirect_tls = None
		if _source_domain is not None :
			_acl_host = self._acl.host (_source_domain)
		else :
			_acl_host = None
		if _source_path is not None :
			if _source_path_exact is True :
				_acl_path = self._acl.path (_source_path)
			elif _source_path_exact is False :
				# NOTE:  This is a hack!
				_acl_path = (self._acl.subpath (_source_path), self._acl.path_prefix (_source_path))
			elif _source_path_exact == "prefix" :
				_acl_path = self._acl.path_prefix (_source_path)
			else :
				raise Exception ("6149bbc7", _source_path_exact)
			_acl_path = _acl_path.negate () if _negate else _acl_path
		else :
			_acl_path = None
		_acl_non_tls = self._acl.via_tls (False)
		_rule_non_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_non_tls))
		_rule_non_tls = ("redirect", _redirect_method, _redirect_non_tls, "code", _redirect_code)
		self._declare_http_rule_0 (_rule_non_tls, _rule_non_tls_condition, **_overrides)
		if _redirect_tls is not None :
			_acl_tls = self._acl.via_tls (True)
			_rule_tls_condition = self._context._condition_if ((_acl, _acl_host, _acl_path, _acl_tls))
			_rule_tls = ("redirect", _redirect_method, _redirect_tls, "code", _redirect_code)
			self._declare_http_rule_0 (_rule_tls, _rule_tls_condition, **_overrides)
	
	def redirect_domains (self, _map, _force_tls = False, _acl = None, **_overrides) :
		for _source, _target in sorted (_map.iteritems ()) :
			self.redirect_domain (_source, _target, _force_tls, _acl, **_overrides)
	
	def redirect_domains_and_paths (self, _map, _force_tls = False, _acl = None, **_overrides) :
		for _source, _target in sorted (_map.iteritems ()) :
			self.redirect_domain_and_path (_source, _target, _force_tls, _acl, **_overrides)
	
	
	def redirect_favicon (self, _redirect = "$favicon_redirect_url", _internal = True, _code = 307, _acl = None, **_overrides) :
		_acl_path = self._acl.path ("/favicon.ico")
		if _internal :
			self.set_path (_redirect, (_acl, _acl_path), **_overrides)
		else :
			self.redirect (_redirect, _code, (_acl, _acl_path), **_overrides)
	
	
	def expose_internals_0 (self, _acl_internals, _credentials = None, _acl = None, _mark_allowed = None, **_overrides) :
		_mark_allowed = self._value_or_parameters_get_and_expand (_mark_allowed, "internals_netfilter_mark_allowed")
		_order_allow = self._parameters._get_and_expand ("internals_rules_order_allow")
		_acl_authenticated = self._acl.authenticated (_credentials) if _credentials is not None else None
		# FIXME:  Make this deferable!
		if _mark_allowed is not None and _mark_allowed != 0 :
			self.set_mark (_mark_allowed, (_acl, _acl_authenticated, _acl_internals), **parameters_overrides (_overrides, order = _order_allow))
		self.allow ((_acl, _acl_authenticated, _acl_internals), **parameters_overrides (_overrides, order = _order_allow))
	
	def expose_internals_path (self, _path, _credentials = None, _acl = None, _mark_allowed = None, **_overrides) :
		_acl_path = self._acl.path (_path)
		self.expose_internals_0 (_acl_path, _credentials, _acl, _mark_allowed, **_overrides)
	
	def expose_internals_path_prefix (self, _path, _credentials = None, _acl = None, _mark_allowed = None, **_overrides) :
		_acl_path = self._acl.path_prefix (_path)
		self.expose_internals_0 (_acl_path, _credentials, _acl, _mark_allowed, **_overrides)
	
	def protect_internals_path_prefix (self, _path, _credentials = None, _acl = None, _mark_denied = None, **_overrides) :
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "internals_netfilter_mark_denied")
		_order_deny = self._parameters._get_and_expand ("internals_rules_order_deny")
		_acl_path = self._acl.path_prefix (_path)
		if _credentials is not None :
			self.authenticate (_credentials, None, (_acl, _acl_path), order = _order_deny, **_overrides)
		self.deny (None, (_acl, _acl_path), _mark_denied, order = _order_deny, **_overrides)
	
	def expose_internals (self, _credentials = None, _acl = None, _mark_allowed = None, _mark_denied = None, **_overrides) :
		self.expose_internals_path_prefix ("$haproxy_internals_path_prefix", _credentials, _acl, _mark_allowed, **_overrides)
		self.expose_internals_path_prefix ("$heartbeat_self_path", _credentials, _acl, _mark_allowed, **_overrides)
		self.expose_internals_path_prefix ("$heartbeat_proxy_path", _credentials, _acl, _mark_allowed, **_overrides)
		self.expose_internals_path_prefix ("$heartbeat_server_path", _credentials, _acl, _mark_allowed, **_overrides)
		self.protect_internals_path_prefix ("$internals_path_prefix", _credentials, _acl, _mark_denied, **_overrides)
	
	def expose_error_pages (self, _credentials = None, _codes = "$error_pages_codes", _acl = None, _mark_allowed = None, _mark_denied = None, **_overrides) :
		# FIXME:  Make this deferable!
		_codes = [200] + list (self._context._resolve_token (_codes))
		_order_allow = self._parameters._get_and_expand ("internals_rules_order_allow")
		_order_deny = self._parameters._get_and_expand ("internals_rules_order_deny")
		_acl_authenticated = self._acl.authenticated (_credentials) if _credentials is not None else None
		for _code in _codes :
			_acl_path = self._acl.path (statement_format ("%s%d", "$error_pages_path_prefix", _code))
			self.deny (statement_enforce_int (_code), (_acl, _acl_authenticated, _acl_path), _mark_allowed, **parameters_overrides (_overrides, order = _order_allow))
		self.deny (None, (_acl, self._acl.path_prefix ("$error_pages_path_prefix")), _mark_denied, order = _order_deny)
	
	def expose_whitelist (self, _credentials = None, _acl = None, _mark_allowed = None, _mark_denied = None, **_overrides) :
		_mark_allowed = self._value_or_parameters_get_and_expand (_mark_allowed, "whitelist_netfilter_mark_allowed")
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "whitelist_netfilter_mark_denied")
		_order_allow = self._parameters._get_and_expand ("internals_rules_order_allow")
		_order_deny = self._parameters._get_and_expand ("internals_rules_order_deny")
		_acl_authenticated = self._acl.authenticated (_credentials) if _credentials is not None else None
		_acl_path = self._acl.path ("$whitelist_path")
		self.deny (200, (_acl, _acl_authenticated, _acl_path), _mark_allowed, **parameters_overrides (_overrides, order = _order_allow))
		self.deny (None, (_acl, _acl_path), _mark_denied, **parameters_overrides (_overrides, order = _order_deny))
	
	
	def set_forwarded_headers (self, _ignore_if_exists = False, _acl = None, **_overrides) :
		_via_tls_method = self._parameters._get_and_expand ("logging_http_header_forwarded_proto_method")
		_acl_with_tls = self._acl.via_tls (True, _method = _via_tls_method)
		_acl_without_tls = self._acl.via_tls (False, _method = _via_tls_method)
		self.set_header ("$logging_http_header_forwarded_host", statement_format ("%%[%s]", self._samples.host ()), _ignore_if_exists, _acl, **_overrides)
		self.set_header ("$logging_http_header_forwarded_for", "%ci", _ignore_if_exists, _acl, **_overrides)
		self.set_header ("$logging_http_header_forwarded_proto", "http", _ignore_if_exists, (_acl_without_tls, _acl), **_overrides)
		self.set_header ("$logging_http_header_forwarded_proto", "https", _ignore_if_exists, (_acl_with_tls, _acl), **_overrides)
		self.set_header ("$logging_http_header_forwarded_port", 80, _ignore_if_exists, (_acl_without_tls, _acl), **_overrides)
		self.set_header ("$logging_http_header_forwarded_port", 443, _ignore_if_exists, (_acl_with_tls, _acl), **_overrides)
		self.set_header ("$logging_http_header_forwarded_server_ip", "%fi", _ignore_if_exists, _acl, **_overrides)
		self.set_header ("$logging_http_header_forwarded_server_port", "%fp", _ignore_if_exists, _acl, **_overrides)
		self.set_geoip_headers (_ignore_if_exists, _acl, **_overrides)
	
	def drop_forwarded_headers (self, _acl = None, **_overrides) :
		self.delete_header ("$logging_http_header_forwarded_host", _acl, **_overrides)
		self.delete_header ("$logging_http_header_forwarded_for", _acl, **_overrides)
		self.delete_header ("$logging_http_header_forwarded_proto", _acl, **_overrides)
		self.delete_header ("$logging_http_header_forwarded_port", _acl, **_overrides)
		self.delete_header ("$logging_http_header_forwarded_server_ip", _acl, **_overrides)
		self.delete_header ("$logging_http_header_forwarded_server_port", _acl, **_overrides)
		self.delete_header ("$logging_http_header_action", _acl, **_overrides)
	
	
	def set_geoip_headers (self, _ignore_if_exists = False, _acl = None, **_overrides) :
		_geoip_enabled = self._parameters._get_and_expand ("geoip_enabled")
		if _geoip_enabled :
			self.set_header ("X-Country", statement_format ("%%[%s]", self._samples.geoip_country_extracted ()), _ignore_if_exists, _acl, **_overrides)
	
	
	def track (self, _acl = None, _force = False, _generate = True, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_tracking_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_tracking_excluded_variable", True) .negate () if not _force else None
		_acl_request_explicit = self._acl.request_header_exists ("$http_tracking_request_header")
		_acl_tracked_via_header = self._acl.request_header_exists ("$http_tracking_session_header")
		_acl_tracked_via_cookie = self._acl.request_cookie_exists ("$http_tracking_session_cookie")
		_acl_untracked = (_acl_tracked_via_header.negate (), _acl_tracked_via_cookie.negate ())
		if _generate :
			# FIXME:  Find a better way!
			self.set_header ("$http_tracking_request_header", "%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]", False, (_acl, _acl_request_explicit.negate (), _acl_enabled, _acl_included), **_overrides)
		self.set_variable ("$http_tracking_request_variable", self._samples.request_header ("$http_tracking_request_header"), (_acl, _acl_enabled, _acl_included), **_overrides)
		if _generate :
			# FIXME:  Find a better way!
			self.set_header ("$http_tracking_session_header", "%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]", False, (_acl, _acl_untracked, _acl_enabled, _acl_included), **_overrides)
		self.set_header ("$http_tracking_session_header", statement_format ("%%[%s]", self._samples.request_cookie ("$http_tracking_session_cookie")), False, (_acl, _acl_tracked_via_header.negate (), _acl_tracked_via_cookie, _acl_enabled, _acl_included), **_overrides)
		self.set_variable ("$http_tracking_session_variable", self._samples.request_header ("$http_tracking_session_header"), (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def track_enable_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_tracking_enabled_variable", _domain, _acl, **_overrides)
	
	def track_exclude_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_tracking_excluded_variable", _domain, _acl, **_overrides)
	
	
	def harden_http (self, _acl = None, _force = False, _mark_denied = None, **_overrides) :
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "http_harden_netfilter_mark_denied")
		_acl_methods = self._acl.request_method ("$http_harden_allowed_methods")
		_acl_methods = _acl_methods.negate ()
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.deny (None, (_acl, _acl_methods, _acl_enabled, _acl_included), _mark_denied, **_overrides)
	
	def harden_authorization (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Authorization", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def harden_browsing (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("User-Agent", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Referer", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Accept-Encoding", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Accept-Language", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Accept-Charset", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def harden_ranges (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		_acl_forbidden = self._acl.variable_bool ("$http_ranges_allowed_variable", True) .negate () if not _force else None
		self.delete_header ("Range", (_acl, _acl_enabled, _acl_included, _acl_forbidden), **_overrides)
		self.delete_header ("If-Range", (_acl, _acl_enabled, _acl_included, _acl_forbidden), **_overrides)
	
	def harden_all (self, _acl = None, _force = False, **_overrides) :
		self.harden_http (_acl, _force, **_overrides)
		self.harden_browsing (_acl, _force, **_overrides)
		self.harden_authorization (_acl, _force, **_overrides)
		self.harden_ranges (_acl, _force, **_overrides)
	
	def harden_enable_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_harden_enabled_variable", _domain, _acl, **_overrides)
	
	def harden_exclude_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_harden_excluded_variable", _domain, _acl, **_overrides)
	
	
	def drop_caching (self, _acl = None, _force = False, _keep_etag_acl = None, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_drop_caching_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_drop_caching_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Cache-Control", (_acl, _acl_enabled, _acl_included), **_overrides)
		if _keep_etag_acl is None or _keep_etag_acl is not True :
			self.delete_header ("If-None-Match", (_acl, _acl_enabled, _acl_included), **_overrides)
			self.delete_header ("If-Match", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("If-Modified-Since", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("If-Unmodified-Since", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Pragma", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def drop_caching_enable_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_drop_caching_enabled_variable", _domain, _acl, **_overrides)
	
	def drop_caching_exclude_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_drop_caching_excluded_variable", _domain, _acl, **_overrides)
	
	
	def force_caching_enable_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_force_caching_enabled_variable", _domain, _acl, **_overrides)
	
	def force_caching_exclude_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_force_caching_excluded_variable", _domain, _acl, **_overrides)
	
	
	def drop_cookies (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_drop_cookies_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_drop_cookies_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Cookie", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def drop_cookies_enable_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_drop_cookies_enabled_variable", _domain, _acl)
	
	def drop_cookies_exclude_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_drop_cookies_excluded_variable", _domain, _acl)
	
	
	def force_cors (self, _acl = None, _force = False, **_overrides) :
		self.force_cors_prepare ()
		self.force_cors_unset ()
	
	def force_cors_prepare (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		_acl_origin_present = self._acl.request_header_exists ("Origin")
		_acl_options_present = self._acl.request_method ("OPTIONS")
		self.set_enabled ("$http_force_cors_origin_present_variable", (_acl, _acl_enabled, _acl_included, _acl_origin_present), **_overrides)
		self.set_enabled ("$http_force_cors_options_present_variable", (_acl, _acl_enabled, _acl_included, _acl_options_present), **_overrides)
		self.set_variable ("$http_force_cors_origin_variable", self._samples.request_header ("Origin"), (_acl, _acl_enabled, _acl_included, _acl_origin_present), **_overrides)
	
	def force_cors_unset (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Origin", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Request-Method", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Request-Headers", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def force_cors_allow (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		_acl_origin = self._acl.variable_bool ("$http_force_cors_origin_present_variable", True) if not _force else None
		self.set_enabled ("$http_force_cors_allowed_variable", (_acl, _acl_enabled, _acl_included, _acl_origin), **_overrides)
	
	def force_cors_allow_origin (self, _origin, _acl = None, _force = False, **_overrides) :
		_acl_origin = self._acl.variable_equals ("$http_force_cors_origin_variable", _origin)
		self.force_cors_allow ((_acl, _acl_origin), _force, **_overrides)
	
	def force_cors_retarget_options (self, _method, _path, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		_acl_allowed = self._acl.variable_bool ("$http_force_cors_allowed_variable", True) if not _force else None
		_acl_origin = self._acl.variable_bool ("$http_force_cors_origin_present_variable", True) if not _force else None
		_acl_options = self._acl.variable_bool ("$http_force_cors_options_present_variable", True) if not _force else None
		self.set_method (_method, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed, _acl_options), **_overrides)
		self.set_path (_path, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed, _acl_options), **_overrides)
		self.deny (403, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed.negate (), _acl_options), **_overrides)
	
	def force_cors_enable_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_force_cors_enabled_variable", _domain, _acl)
	
	def force_cors_exclude_for_domain (self, _domain, _acl = None, **_overrides) :
		self.set_enabled_for_domain ("$http_force_cors_excluded_variable", _domain, _acl)
	
	
	def capture (self, _sample, _acl = None, **_overrides) :
		_index = self._context._declare_request_capture (**_overrides)
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("capture", _sample, "id", _index)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
		return _index
	
	def capture_header (self, _header, _transforms = None, _acl = None, _index = None, **_overrides) :
		_sample = self._samples.request_header (_header, _transforms, _index)
		return self.capture (_sample, _acl, **_overrides)
	
	
	def capture_defaults (self, _acl = None, **_overrides) :
		self.capture_protocol (_acl, **_overrides)
		self.capture_forwarded (_acl, **_overrides)
		self.capture_tracking (_acl, **_overrides)
		self.capture_browsing (_acl, **_overrides)
		self.capture_caching (_acl, **_overrides)
		self.capture_cookies (_acl, **_overrides)
		self.capture_geoip (_acl, **_overrides)
	
	def capture_protocol (self, _acl = None, **_overrides) :
		self.capture_header ("Host", "base64", _acl, **_overrides)
	
	def capture_forwarded (self, _acl = None, **_overrides) :
		self.capture_header ("$logging_http_header_forwarded_host", "base64", _acl, **_overrides)
		self.capture_header ("$logging_http_header_forwarded_for", "base64", _acl, **_overrides)
		self.capture_header ("$logging_http_header_forwarded_proto", "base64", _acl, **_overrides)
		self.capture_header ("$logging_http_header_forwarded_port", "base64", _acl, **_overrides)
	
	def capture_tracking (self, _acl = None, **_overrides) :
		self.capture_header ("$http_tracking_request_header", "base64", _acl, **_overrides)
		self.capture_header ("$http_tracking_session_header", "base64", _acl, **_overrides)
	
	def capture_browsing (self, _acl = None, **_overrides) :
		self.capture_header ("User-Agent", "base64", _acl, **_overrides)
		self.capture_header ("Referer", "base64", _acl, **_overrides)
		self.capture_header ("Accept-Encoding", "base64", _acl, **_overrides)
		self.capture_header ("Accept-Language", "base64", _acl, **_overrides)
		self.capture_header ("Accept-Charset", "base64", _acl, **_overrides)
	
	def capture_caching (self, _acl = None, **_overrides) :
		self.capture_header ("Cache-Control", "base64", _acl, **_overrides)
		self.capture_header ("If-None-Match", "base64", _acl, **_overrides)
		self.capture_header ("If-Match", "base64", _acl, **_overrides)
		self.capture_header ("If-Modified-Since", "base64", _acl, **_overrides)
		self.capture_header ("If-Unmodified-Since", "base64", _acl, **_overrides)
		self.capture_header ("Pragma", "base64", _acl, **_overrides)
	
	def capture_cookies (self, _acl = None, **_overrides) :
		self.capture_header ("Cookie", "base64", _acl, 1, **_overrides)
		self.capture_header ("Cookie", "base64", _acl, 2, **_overrides)
		self.capture_header ("Cookie", "base64", _acl, 3, **_overrides)
		self.capture_header ("Cookie", "base64", _acl, 4, **_overrides)
	
	def capture_geoip (self, _acl = None, **_overrides) :
		_geoip_enabled = self._parameters._get_and_expand ("geoip_enabled")
		if _geoip_enabled :
			self.capture_header ("X-Country", "base64", _acl, **_overrides)
	
	
	def variables_defaults (self, _acl = None, **_overrides) :
		self.variables_protocol (_acl, **_overrides)
		self.variables_forwarded (_acl, **_overrides)
		self.variables_tracking (_acl, **_overrides)
		self.variables_browsing (_acl, **_overrides)
		self.variables_geoip (_acl, **_overrides)
	
	def variables_protocol (self, _acl = None, **_overrides) :
		self.set_header ("$logging_http_header_action", statement_format ("%%[%s]://%%[%s]%%[%s]", self._samples.request_method (), self._samples.host (), self._samples.path ()), False, (_acl, self._acl.query_exists () .negate ()), **_overrides)
		self.set_header ("$logging_http_header_action", statement_format ("%%[%s]://%%[%s]%%[%s]?%%[%s]", self._samples.request_method (), self._samples.host (), self._samples.path (), self._samples.query ()), False, (_acl, self._acl.query_exists ()), **_overrides)
		self.set_variable ("$logging_http_variable_action", self._samples.request_header ("$logging_http_header_action"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_method", self._samples.request_method (), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_host", self._samples.host (), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_path", self._samples.path (), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_query", self._samples.query (), _acl, **_overrides)
	
	def variables_forwarded (self, _acl = None, **_overrides) :
		self.set_variable ("$logging_http_variable_forwarded_host", self._samples.forwarded_host (), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_forwarded_for", self._samples.forwarded_for (), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_forwarded_proto", self._samples.forwarded_proto (), _acl, **_overrides)
	
	def variables_tracking (self, _acl = None, **_overrides) :
		self.set_variable ("$logging_http_variable_request", self._samples.request_header ("$logging_http_header_request"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_session", self._samples.request_header ("$logging_http_header_session"), _acl, **_overrides)
	
	def variables_browsing (self, _acl = None, **_overrides) :
		self.set_variable ("$logging_http_variable_agent", self._samples.request_header ("User-Agent"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_referrer", self._samples.request_header ("Referer"), _acl, **_overrides)
	
	def variables_geoip (self, _acl = None, **_overrides) :
		_geoip_enabled = self._parameters._get_and_expand ("geoip_enabled")
		if _geoip_enabled :
			self.set_variable ("$logging_geoip_country_variable", self._samples.request_header ("X-Country"), _acl, **_overrides)
	
	
	def authenticate (self, _credentials, _realm = None, _acl = None, **_overrides) :
		_acl_authenticated = self._acl.authenticated (_credentials)
		_rule_condition = self._context._condition_if ((_acl, _acl_authenticated.negate ()))
		_rule = ("auth", "realm", statement_quote ("\'", statement_coalesce (_realm, "$daemon_identifier")))
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	def authenticate_for_path_and_query (self, _path, _query, _credentials, _realm = None, _acl = None, **_overrides) :
		_acl_authenticated = self._acl.authenticated (_credentials)
		_acl_path = self._acl.path (_path)
		_acl_query = self._acl.query (_query)
		self.authenticate (_credentials, _realm, (_acl, _acl_path, _acl_query), **_overrides)
		self.deny (200, (_acl, _acl_path, _acl_query, _acl_authenticated), **_overrides)
	
	def authenticate_trigger (self, _credentials, _realm = None, _acl = None, **_overrides) :
		_acl_authenticated = self._acl.authenticated (_credentials)
		_acl_path = self._acl.path ("$http_authenticated_path")
		_acl_query = self._acl.query ("$http_authenticated_query")
		_acl_cookie = self._acl.request_cookie_exists ("$http_authenticated_cookie")
		self.authenticate (_credentials, _realm, (_acl, _acl_path), **_overrides)
		self.authenticate (_credentials, _realm, (_acl, _acl_query), **_overrides)
		self.authenticate (_credentials, _realm, (_acl, _acl_cookie), **_overrides)
		# FIXME:  Find a better way!
		self.delete_header ("$http_authenticated_header", _acl, **_overrides)
		self.set_header ("$http_authenticated_header", statement_format ("%%[%s]", self._samples.authenticated_group (_credentials)), False, (_acl, _acl_authenticated), **_overrides)
		self.set_variable ("$http_authenticated_variable", self._samples.request_header ("$http_authenticated_header"), (_acl, _acl_authenticated), **_overrides)
		self.deny (200, (_acl, _acl_authenticated, _acl_path), **_overrides)
		self.deny (200, (_acl, _acl_authenticated, _acl_query), **_overrides)
	
	def authenticated (self, _credentials, _variable = None, _cleanup = True, _acl = None, **_overrides) :
		_variable = _variable if _variable is not None else "txn.authenticated_%s" % (_credentials.identifier,)
		_acl_authenticated = self._acl.authenticated (_credentials)
		_acl_variable = self._acl.variable_bool (_variable)
		self.set_enabled (_variable, (_acl, _acl_authenticated), **_overrides)
		if _cleanup :
			self.delete_header ("Authorized", (_acl, _acl_authenticated, _acl_variable), **_overrides)
		return _acl_variable
	
	
	def set_debug_headers (self, _acl = None, **_overrides) :
		self.set_header ("$logging_http_header_action", statement_format ("%%[%s]", self._samples.variable ("$logging_http_variable_action")), False, _acl, **_overrides)
		self.set_header ("$http_debug_timestamp_header", "%[date(),http_date()]", False, _acl, **_overrides)
		self.append_header ("$http_debug_frontend_header", "%f", _acl, **_overrides)
		self.append_header ("$http_debug_backend_header", "%b", _acl, **_overrides)




class HaHttpResponseRuleBuilder (HaHttpRuleBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaHttpRuleBuilder.__init__ (self, _context, _parameters)
	
	
	def set_status (self, _code, _acl = None, **_overrides) :
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("set-status", _code)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
	
	
	def deny_status (self, _code, _acl = None, _mark = None, **_overrides) :
		_acl_status = self._acl.response_status (_code)
		self.deny (None, (_acl, _acl_status), _mark, **_overrides)
	
	
	def expose_internals_0 (self, _acl_internals, _acl = None, _mark_allowed = None, **_overrides) :
		_mark_allowed = self._value_or_parameters_get_and_expand (_mark_allowed, "internals_netfilter_mark_allowed")
		_order_allow = self._parameters._get_and_expand ("internals_rules_order_allow")
		# FIXME:  Make this deferable!
		if _mark_allowed is not None and _mark_allowed != 0 :
			self.set_mark (_mark_allowed, (_acl, _acl_internals), **parameters_overrides (_overrides, order = _order_allow))
		self.allow ((_acl, _acl_internals), **parameters_overrides (_overrides, order = _order_allow))
	
	def expose_internals_path (self, _path, _acl = None, _mark_allowed = None, **_overrides) :
		_acl_path = self._acl.path (_path)
		self.expose_internals_0 (_acl_path, _acl, _mark_allowed, **_overrides)
	
	def expose_internals_path_prefix (self, _path, _acl = None, _mark_allowed = None, **_overrides) :
		_acl_path = self._acl.path_prefix (_path)
		self.expose_internals_0 (_acl_path, _acl, _mark_allowed, **_overrides)
	
	def protect_internals_path_prefix (self, _path, _acl = None, _mark_denied = None, **_overrides) :
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "internals_netfilter_mark_denied")
		_order_deny = self._parameters._get_and_expand ("internals_rules_order_deny")
		_acl_path = self._acl.path_prefix (_path)
		self.deny (None, (_acl, _acl_path), _mark_denied, order = _order_deny, **_overrides)
	
	def expose_internals (self, _acl = None, _mark_allowed = None, _mark_denied = None, **_overrides) :
		self.expose_internals_path_prefix ("$haproxy_internals_path_prefix", _acl, _mark_allowed, **_overrides)
		self.expose_internals_path_prefix ("$heartbeat_self_path", _acl, _mark_allowed, **_overrides)
		self.expose_internals_path_prefix ("$heartbeat_proxy_path", _acl, _mark_allowed, **_overrides)
		self.expose_internals_path_prefix ("$heartbeat_server_path", _acl, _mark_allowed, **_overrides)
		self.protect_internals_path_prefix ("$internals_path_prefix", _acl, _mark_denied, **_overrides)
	
	
	def track (self, _acl = None, _force = False, _set_cookie = True, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_tracking_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_tracking_excluded_variable", True) .negate () if not _force else None
		self.set_header ("$http_tracking_request_header", statement_format ("%%[%s]", self._samples.variable ("$http_tracking_request_variable")), False, (_acl, _acl_enabled, _acl_included), **_overrides)
		self.set_header ("$http_tracking_session_header", statement_format ("%%[%s]", self._samples.variable ("$http_tracking_session_variable")), False, (_acl, _acl_enabled, _acl_included), **_overrides)
		if _set_cookie :
			self.set_cookie ("$http_tracking_session_cookie", statement_format ("%%[%s]", self._samples.variable ("$http_tracking_session_variable")), "/", "$http_tracking_session_cookie_max_age", False, True, False, (_acl, _acl_enabled, _acl_included), **_overrides)
	
	
	def harden_http (self, _acl = None, _force = False, _mark_denied = None, **_overrides) :
		self.harden_http_all (_acl, _force, _mark_denied, **_overrides)
		self.harden_http_get (_acl, _force, _mark_denied, **_overrides)
		self.harden_http_post (_acl, _force, _mark_denied, **_overrides)
	
	def harden_http_all (self, _acl = None, _force = False, _mark_denied = None, **_overrides) :
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "http_harden_netfilter_mark_denied")
		_status_acl = self._acl.response_status ("$http_harden_allowed_status_codes")
		_status_acl = _status_acl.negate ()
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.deny (None, (_acl, _status_acl, _acl_enabled, _acl_included, _acl_handled), _mark_denied, **_overrides)
	
	def harden_http_get (self, _acl = None, _force = False, _mark_denied = None, **_overrides) :
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "http_harden_netfilter_mark_denied")
		_method_acl = self._acl.variable_equals ("$logging_http_variable_method", ("GET", "HEAD"))
		_status_acl = self._acl.response_status ("$http_harden_allowed_get_status_codes")
		_status_acl = _status_acl.negate ()
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.deny (None, (_acl, _method_acl, _status_acl, _acl_enabled, _acl_included, _acl_handled), _mark_denied, **_overrides)
	
	def harden_http_post (self, _acl = None, _force = False, _mark_denied = None, **_overrides) :
		_mark_denied = self._value_or_parameters_get_and_expand (_mark_denied, "http_harden_netfilter_mark_denied")
		_method_acl = self._acl.variable_equals ("$logging_http_variable_method", ("POST", "PUT"))
		_status_acl = self._acl.response_status ("$http_harden_allowed_post_status_codes")
		_status_acl = _status_acl.negate ()
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.deny (None, (_acl, _method_acl, _status_acl, _acl_enabled, _acl_included, _acl_handled), _mark_denied, **_overrides)
	
	def harden_headers (self, _acl = None, _force = False, **_overrides) :
		_acl_tls = self._acl.via_tls ()
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.set_header ("Content-Security-Policy", "$http_harden_csp_descriptor", True, (_acl, _acl_enabled, _acl_included, _acl_handled, _acl_tls), **_overrides)
		self.set_header ("Referrer-Policy", "$http_harden_referrer_descriptor", True, (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
		self.set_header ("X-Frame-Options", "$http_harden_frames_descriptor", True, (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
		self.set_header ("X-Content-Type-Options", "$http_harden_cto_descriptor", True, (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
		self.set_header ("X-XSS-Protection", "$http_harden_xss_descriptor", True, (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
	
	def harden_via (self, _acl = None, _force = False, **_overrides) :
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Via", (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
		self.delete_header ("Server", (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
		self.delete_header ("X-Powered-By", (_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
	
	def harden_ranges (self, _acl = None, _force = False, **_overrides) :
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		_acl_forbidden = self._acl.variable_bool ("$http_ranges_allowed_variable", True) .negate () if not _force else None
		self.set_header ("Accept-Ranges", "none", False, (_acl, _acl_enabled, _acl_included, _acl_handled, _acl_forbidden), **_overrides)
	
	def harden_redirects (self, _acl = None, _force = False, **_overrides) :
		# FIXME:  Perhaps make configurable the source redirect status code!
		_status_acl = self._acl.response_status ((301, 302, 303, 307, 308))
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		# FIXME:  Perhaps make configurable the target redirect status code!
		self.set_status (307, (_acl, _status_acl, _acl_enabled, _acl_included, _acl_handled), **_overrides)
	
	def harden_tls (self, _acl = None, _force = False, **_overrides) :
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		_acl_tls = self._acl.via_tls ()
		_hsts_enabled = self._parameters._get_and_expand ("http_harden_hsts_enabled")
		# FIXME:  Make this deferable!
		if _hsts_enabled :
			self.set_header ("Strict-Transport-Security", "$http_harden_hsts_descriptor", False, (_acl, _acl_enabled, _acl_included, _acl_handled, _acl_tls), **_overrides)
	
	def harden_all (self, _acl = None, _force = False, _mark_allowed = None, _mark_denied = None, **_overrides) :
		_mark_allowed = self._value_or_parameters_get_and_expand (_mark_denied, "http_harden_netfilter_mark_allowed")
		self.harden_http (_acl, _force, _mark_denied, **_overrides)
		self.harden_headers (_acl, _force, **_overrides)
		self.harden_via (_acl, _force, **_overrides)
		self.harden_ranges (_acl, _force, **_overrides)
		# FIXME:  Make this configurable!
		# self.harden_redirects (_acl, _force, **_overrides)
		self.harden_tls (_acl, _force, **_overrides)
		# FIXME:  Make this deferable!
		_acl_handled = self._acl.response_header_exists ("$http_hardened_header", False) if not _force else None
		_acl_enabled = self._acl.variable_bool ("$http_harden_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_harden_excluded_variable", True) .negate () if not _force else None
		# FIXME:  Make this configurable!
		if False :
			self.set_header ("$http_hardened_header", "true", True, (_acl_enabled, _acl_included, _acl_handled, _acl), **_overrides)
		# FIXME:  Make this deferable!
		if _mark_allowed is not None and _mark_allowed != 0 :
			self.set_mark (_mark_allowed, (_acl_enabled, _acl_included, _acl_handled, _acl), **_overrides)
	
	
	def drop_caching (self, _acl = None, _force = False, _keep_etag_acl = None, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_drop_caching_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_drop_caching_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Cache-Control", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Last-Modified", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Expires", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Date", (_acl, _acl_enabled, _acl_included), **_overrides)
		if _keep_etag_acl is None or _keep_etag_acl is not True :
			self.delete_header ("ETag", (_acl, _acl_enabled, _acl_included), **_overrides)
	#!	self.delete_header ("Vary", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Age", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Pragma", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def force_caching (self, _max_age = 3600, _public = True, _no_cache = False, _must_revalidate = False, _immutable = None, _acl = None, _force = False, _store_max_age = None, _keep_etag_acl = None, _vary = None, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_caching_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_caching_excluded_variable", True) .negate () if not _force else None
		self.force_caching_control (_max_age, _public, _no_cache, _must_revalidate, _immutable, _acl, _force, _store_max_age, **_overrides)
		if _keep_etag_acl is None or _keep_etag_acl is not True :
			self.set_header ("ETag", "\"%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]%[rand(4294967295),bytes(4,4),hex,lower]\"", False, (_acl, _acl_enabled, _acl_included), **_overrides)
		if not _public :
			self.set_header ("Vary", "Authorization", False, (_acl, _acl_enabled, _acl_included), **_overrides)
			self.set_header ("Vary", "Cookie", False, (_acl, _acl_enabled, _acl_included), **_overrides)
		else :
			self.delete_header ("Set-Cookie", (_acl, _acl_enabled, _acl_included), **_overrides)
		if _vary is not None :
			for _vary in _vary :
				self.set_header ("Vary", _vary, False, (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def force_caching_control (self, _max_age = 3600, _public = True, _no_cache = False, _must_revalidate = False, _immutable = None, _acl = None, _force = False, _store_max_age = None, **_overrides) :
		_private = not _public
		if _immutable is None :
			_immutable = not _no_cache and not _must_revalidate
		if _max_age is not None :
			_max_age = statement_enforce_int (_max_age)
		if _store_max_age is not None :
			_store_max_age = statement_enforce_int (_store_max_age)
		_public = statement_enforce_bool (_public)
		_private = statement_enforce_bool (_private)
		_no_cache = statement_enforce_bool (_no_cache)
		_must_revalidate = statement_enforce_bool (_must_revalidate)
		_immutable = statement_enforce_bool (_immutable)
		_acl_enabled = self._acl.variable_bool ("$http_force_caching_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_caching_excluded_variable", True) .negate () if not _force else None
		self.set_header ("Cache-Control",
				statement_join (", ", (
						statement_choose_if (_public, "public"),
						statement_choose_if (_private, "private"),
						statement_choose_if (_no_cache, "no-cache"),
						statement_choose_if (_must_revalidate, "must-revalidate"),
						statement_choose_if (_immutable, "immutable"),
						statement_choose_if (_max_age, statement_format ("max-age=%d", _max_age)),
						statement_choose_if (_store_max_age, statement_format ("s-maxage=%d", _store_max_age)),
						# statement_choose_if (_store_max_age, statement_choose_if (_must_revalidate, statement_format ("proxy-revalidate"))),
				)), False, (_acl, _acl_enabled, _acl_included), **_overrides)
		_expire_age = _max_age
		if _store_max_age is not None :
			_expire_age = statement_choose_max (_expire_age, _store_max_age)
		self.force_caching_maxage (_expire_age, (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def force_caching_no (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_caching_enabled_variable", True) .negate () if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_caching_excluded_variable", True) .negate () if not _force else None
		self.set_header ("Cache-Control", "no-cache, no-store, must-revalidate", False, (_acl, _acl_enabled, _acl_included), **_overrides)
#!		self.force_caching_maxage (0, (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def force_caching_maxage (self, _max_age, _acl, **_overrides) :
		if _max_age is not None :
			self.set_header ("Last-Modified", statement_format ("%%[date(-%d),http_date()]", _max_age), False, _acl, **_overrides)
			self.set_header ("Expires", statement_format ("%%[date(%d),http_date()]", _max_age), False, _acl, **_overrides)
			self.set_header ("Date", statement_format ("%%[date(),http_date()]"), False, _acl, **_overrides)
			self.set_header ("Age", 0, False, _acl, **_overrides)
		else :
			self.delete_header ("Last-Modified", _acl, **_overrides)
			self.delete_header ("Expires", _acl, **_overrides)
			self.delete_header ("Date", _acl, **_overrides)
			self.delete_header ("Age", _acl, **_overrides)
		self.delete_header ("Pragma", _acl, **_overrides)
	
	
	def drop_cookies (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_drop_cookies_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_drop_cookies_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Set-Cookie", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	
	def force_cors (self, _origin = "origin", _methods = ["GET"], _headers = None, _max_age = 3600, _credentials = False, _acl = None, _force = False, **_overrides) :
		self.force_cors_unset (_acl, _force, **_overrides)
		self.force_cors_set (_origin, _methods, _headers, _max_age, _credentials, _acl, _force, **_overrides)
		self.force_cors_vary (_acl, _force, **_overrides)
	
	def force_cors_unset (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		self.delete_header ("Access-Control-Allow-Origin", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Allow-Methods", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Allow-Headers", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Expose-Headers", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Allow-Credentials", (_acl, _acl_enabled, _acl_included), **_overrides)
		self.delete_header ("Access-Control-Max-Age", (_acl, _acl_enabled, _acl_included), **_overrides)
	
	def force_cors_set (self, _origin = "origin", _methods = ["GET"], _headers = None, _max_age = 3600, _credentials = False, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		_acl_allowed = self._acl.variable_bool ("$http_force_cors_allowed_variable", True) if not _force else None
		_acl_origin = self._acl.variable_bool ("$http_force_cors_origin_present_variable", True) if not _force else None
		if _origin == "origin" :
			_origin = self._samples.variable ("$http_force_cors_origin_variable") .statement_format ()
		if _origin is not None :
			self.set_header ("Access-Control-Allow-Origin", _origin, False, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed), **_overrides)
		if _methods is not None :
			self.set_header ("Access-Control-Allow-Methods", ", ".join (_methods), False, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed), **_overrides)
		if _headers is not None :
			self.set_header ("Access-Control-Allow-Headers", ", ".join (_headers), False, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed), **_overrides)
		if _credentials is True :
			self.set_header ("Access-Control-Allow-Credentials", "true", False, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed), **_overrides)
		elif _credentials is False or _credentials is None :
			pass
		else :
			raise_error ("b00395cd", _credentials)
		if _max_age is not None :
			self.set_header ("Access-Control-Max-Age", statement_enforce_int (_max_age), False, (_acl, _acl_enabled, _acl_included, _acl_origin, _acl_allowed), **_overrides)
	
	def force_cors_vary (self, _acl = None, _force = False, **_overrides) :
		_acl_enabled = self._acl.variable_bool ("$http_force_cors_enabled_variable", True) if not _force else None
		_acl_included = self._acl.variable_bool ("$http_force_cors_excluded_variable", True) .negate () if not _force else None
		_acl_origin = self._acl.variable_bool ("$http_force_cors_origin_present_variable", True) if not _force else None
		self.append_header ("Vary", "Origin", (_acl, _acl_enabled, _acl_included, _acl_origin), **_overrides)
		self.append_header ("Vary", "Access-Control-Request-Method", (_acl, _acl_enabled, _acl_included, _acl_origin), **_overrides)
		self.append_header ("Vary", "Access-Control-Request-Headers", (_acl, _acl_enabled, _acl_included, _acl_origin), **_overrides)
	
	
	def capture (self, _sample, _acl = None, **_overrides) :
		_index = self._context._declare_response_capture (**_overrides)
		_rule_condition = self._context._condition_if (_acl)
		_rule = ("capture", _sample, "id", _index)
		self._declare_http_rule_0 (_rule, _rule_condition, **_overrides)
		return _index
	
	def capture_header (self, _header, _transforms = None, _acl = None, _index = None, **_overrides) :
		_sample = self._samples.response_header (_header, _transforms, _index)
		return self.capture (_sample, _acl, **_overrides)
	
	
	def capture_defaults (self, _acl = None, **_overrides) :
		self.capture_protocol (_acl, **_overrides)
		self.capture_caching (_acl, **_overrides)
		self.capture_cookies (_acl, **_overrides)
	
	def capture_protocol (self, _acl = None, **_overrides) :
		self.capture_header ("Location", "base64", _acl, **_overrides)
		self.capture_header ("Content-Type", "base64", _acl, **_overrides)
		self.capture_header ("Content-Encoding", "base64", _acl, **_overrides)
		self.capture_header ("Content-Length", "base64", _acl, **_overrides)
		self.capture_header ("Content-Disposition", "base64", _acl, **_overrides)
	
	def capture_caching (self, _acl = None, **_overrides) :
		self.capture_header ("Cache-Control", "base64", _acl, **_overrides)
		self.capture_header ("Last-Modified", "base64", _acl, **_overrides)
		self.capture_header ("Expires", "base64", _acl, **_overrides)
		self.capture_header ("Date", "base64", _acl, **_overrides)
		self.capture_header ("ETag", "base64", _acl, **_overrides)
		self.capture_header ("Vary", "base64", _acl, **_overrides)
		self.capture_header ("Age", "base64", _acl, **_overrides)
		self.capture_header ("Pragma", "base64", _acl, **_overrides)
	
	def capture_cookies (self, _acl = None, **_overrides) :
		self.capture_header ("Set-Cookie", "base64", _acl, 1, **_overrides)
		self.capture_header ("Set-Cookie", "base64", _acl, 2, **_overrides)
		self.capture_header ("Set-Cookie", "base64", _acl, 3, **_overrides)
		self.capture_header ("Set-Cookie", "base64", _acl, 4, **_overrides)
	
	
	def variables_defaults (self, _acl = None, **_overrides) :
		self.variables_protocol (_acl, **_overrides)
	
	def variables_protocol (self, _acl = None, **_overrides) :
		self.set_variable ("$logging_http_variable_location", self._samples.response_header ("Location"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_content_type", self._samples.response_header ("Content-Type"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_content_encoding", self._samples.response_header ("Content-Encoding"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_content_length", self._samples.response_header ("Content-Length"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_cache_control", self._samples.response_header ("Cache-Control"), _acl, **_overrides)
		self.set_variable ("$logging_http_variable_cache_etag", self._samples.response_header ("ETag"), _acl, **_overrides)
	
	
	def authenticate_trigger (self, _credentials, _acl = None, **_overrides) :
		_acl_authenticated = self._acl.variable_exists ("$http_authenticated_variable")
		self.delete_header ("$http_authenticated_header", _acl, **_overrides)
		self.set_cookie ("$http_authenticated_cookie", statement_format ("%%[%s]", self._samples.variable ("$http_authenticated_variable")), "/", "$http_authenticated_cookie_max_age", True, True, True, (_acl, _acl_authenticated), **_overrides)
		# FIXME:  Make this configurable!
		if False :
			self.set_header ("$http_authenticated_header", statement_format ("%%[%s]", self._samples.variable ("$http_authenticated_variable")), False, (_acl, _acl_authenticated), **_overrides)
	
	
	def set_debug_headers (self, _acl = None, **_overrides) :
		self.set_header ("$logging_http_header_action", statement_format ("%%[%s]", self._samples.variable ("$logging_http_variable_action")), False, _acl, **_overrides)
		self.set_header ("$http_debug_timestamp_header", "%[date(),http_date()]", False, _acl, **_overrides)
		self.append_header ("$http_debug_frontend_header", "%f", _acl, **_overrides)
		self.append_header ("$http_debug_backend_header", "%b", _acl, **_overrides)




class HaHttpFrontendBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
	
	
	def basic (self, identifier = None, tls = None, **_parameters) :
		
		_identifier = identifier if identifier is not None else "http"
		_tls = tls if tls is not None else False
		
		_frontend = self._context.http_frontend_create (_identifier, **_parameters)
		
		_frontend.declare_bind (**_parameters)
		if _tls :
			_frontend.declare_bind_tls (**_parameters)
		
		return _frontend




class HaHttpBackendBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
	
	
	def basic (self, identifier = None, endpoint = None, frontend = None, acl = None, route_order = None, **_parameters) :
		
		_identifier = identifier if identifier is not None else "http-backend"
		_endpoint = endpoint if endpoint is not None else "ipv4@127.0.0.1:8080"
		_frontend = frontend
		_acl = acl
		_route_order = route_order
		
		_backend = self._context.http_backend_create (_identifier, **_parameters)
		if _endpoint is not None :
			_backend.declare_server ("default", _endpoint)
		
		def _frontend_configure (_routes, _requests, _responses) :
			_routes.route (_backend, _acl, order = _route_order)
		self._for_each_frontend_http_builders (_frontend, _frontend_configure)
		
		return _backend
	
	
	def for_domain (self, _domain, _endpoint = None, identifier = None, frontend = None, acl = None, **_parameters) :
		
		_endpoint = endpoint if endpoint is not None else "ipv4@127.0.0.1:8080"
		_backend_identifier = parameters_coalesce (identifier, _domain)
		_frontend = frontend
		_acl = acl
		
		_parameters = parameters_defaults (_parameters, backend_http_check_request_host = _domain)
		
		_backend = self._context.http_backend_create (_backend_identifier, **_parameters)
		_backend.declare_server ("default", _endpoint)
		
		def _frontend_configure (_routes, _requests, _responses) :
			_routes.route_host (_backend, _host, _acl)
		self._for_each_frontend_http_builders (_frontend, _frontend_configure)
		
		return _backend
	
	def for_domains (self, _map, frontend = None, acl = None, **_parameters) :
		_backends = list ()
		for _domain, _endpoint in _map.iteritems () :
			_backend = self.for_domain (_domain, _endpoint, frontend = frontend, identifier = _domain, acl = acl, **_parameters)
			_backends.append (_backend)
		return _backends
	
	
	def letsencrypt (self, identifier = None, endpoint = None, frontend = None, acl = None, **_parameters) :
		
		_server_endpoint = statement_coalesce (endpoint, "$letsencrypt_server_endpoint")
		_backend_identifier = parameters_coalesce (identifier, parameters_get ("letsencrypt_backend_identifier"))
		_frontend = frontend
		_acl = acl
		
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
	
	
	def varnish (self, identifier = None, endpoint = None, frontend = None, domain = None, acl = None, **_parameters) :
		
		_server_endpoint = statement_coalesce (endpoint, "$varnish_upstream_endpoint")
		_backend_identifier = parameters_coalesce (identifier, parameters_get ("varnish_backend_identifier"))
		_frontend = frontend
		_acl = acl
		_domain = domain
		
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




class HaHttpRouteBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
		self._acl = HaHttpAclBuilder (_context, _parameters)
		self._samples = HaHttpSampleBuilder (_context, _parameters)
	
	def _declare_route_if_0 (self, _backend, _acl, **_overrides) :
		self._context.declare_route_if_0 (_backend, _acl, **_overrides)
	
	def _declare_route_unless_0 (self, _backend, _acl, **_overrides) :
		self._context.declare_route_unless_0 (_backend, _acl, **_overrides)
	
	
	def route (self, _backend, _acl = None, **_overrides) :
		self._declare_route_if_0 (_backend, _acl, **_overrides)
	
	def route_host (self, _backend, _host, _acl = None, **_overrides) :
		_acl_host = self._acl.host (_host)
		self.route (_backend, (_acl_host, _acl), **_overrides)
	
	def route_path (self, _backend, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path (_path)
		self.route (_backend, (_acl_path, _acl), **_overrides)
	
	def route_path_prefix (self, _backend, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path_prefix (_path)
		self.route (_backend, (_acl_path, _acl), **_overrides)
	
	def route_path_suffix (self, _backend, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.path_suffix (_path)
		self.route (_backend, (_acl_path, _acl), **_overrides)
	
	def route_subpath (self, _backend, _path, _acl = None, **_overrides) :
		_acl_path = self._acl.subpath (_path)
		self.route (_backend, (_acl_path, _acl), **_overrides)




