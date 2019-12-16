



from errors import *
from tools import *

from builders_core import *
from builders_samples import *




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
		if _criteria is None :
			_criteria = "src"
		if _criteria == "session" :
			_sample = self._samples.variable ("$http_tracking_session_variable", (("wt6", 1), ("mod", _count)))
		elif _criteria == "request" :
			_sample = self._samples.variable ("$http_tracking_request_variable", (("wt6", 1), ("mod", _count)))
		elif _criteria == "agent" :
			_sample = self._samples.variable ("$logging_http_variable_agent", (("wt6", 1), ("mod", _count)))
		elif _criteria == "src" :
			_sample = self._samples.client_ip ("src", (("wt6", 1), ("mod", _count)))
		elif _criteria == "X-Forwarded-For" :
			_sample = self._samples.client_ip ("X-Forwarded-For", (("wt6", 1), ("mod", _count)))
		elif _criteria == "path" :
			_sample = self._samples.variable ("$logging_http_variable_path", (("wt6", 1), ("mod", _count)))
		elif _criteria == "action" :
			_sample = self._samples.variable ("$logging_http_variable_action", (("wt6", 1), ("mod", _count)))
		else :
			raise_error ("34cca11c", _criteria)
		return self._context.acl_0 (_identifier, _sample, "int", None, "eq", (_expected,))




