



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
	
	def ip_from_variable (self, _variable, _ip, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "ip", None, None, _ip)
	
	def ip_from_request_header (self, _header, _ip, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_header), "ip", None, None, _ip)
	
	def ip_from_response_header (self, _header, _ip, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_header), "ip", None, None, _ip)
	
	
	def client_ip_in_map (self, _map, _method = None, _identifier = None) :
		return self.sample_ip_in_map (self._samples.client_ip (_method), _map, _identifier)
	
	def ip_from_variable_in_map (self, _variable, _map, _identifier = None) :
		return self.sample_ip_in_map (self._samples.variable (_variable), _map, _identifier)
	
	def ip_from_request_header_in_map (self, _header, _map, _identifier = None) :
		return self.sample_ip_in_map (self._samples.request_header (_header), _map, _identifier)
	
	def ip_from_response_header_in_map (self, _header, _map, _identifier = None) :
		return self.sample_ip_in_map (self._samples.response_header (_header), _map, _identifier)
	
	
	def string_from_variable_in_map (self, _variable, _map, _identifier = None) :
		return self.sample_string_in_map (self._samples.variable (_variable), _map, _identifier)
	
	def string_from_request_header_in_map (self, _header, _map, _identifier = None) :
		return self.sample_string_in_map (self._samples.request_header (_header), _map, _identifier)
	
	def string_from_response_header_in_map (self, _header, _map, _identifier = None) :
		return self.sample_string_in_map (self._samples.response_header (_header), _map, _identifier)
	
	
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
	
	def request_method_head (self, _identifier = None) :
		return self.request_method ("head", _identifier)
	
	def request_method_get (self, _identifier = None) :
		return self.request_method ("get", _identifier)
	
	def request_method_put (self, _identifier = None) :
		return self.request_method ("put", _identifier)
	
	def request_method_post (self, _identifier = None) :
		return self.request_method ("post", _identifier)
	
	def request_method_patch (self, _identifier = None) :
		return self.request_method ("patch", _identifier)
	
	def request_method_delete (self, _identifier = None) :
		return self.request_method ("delete", _identifier)
	
	def request_method_options (self, _identifier = None) :
		return self.request_method ("options", _identifier)
	
	
	def response_status (self, _code, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_status (), "int", None, "eq", (_code,))
	
	
	def request_header_exists (self, _header, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header_exists (_header, _expected), "bool", None, None, None)
	
	def request_header_empty (self, _name, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_name), "str", None, "eq", ("",))
	
	def request_header_equals (self, _name, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_name), "str", None, "eq", (_value,))
	
	def request_header_prefix (self, _name, _prefix, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_name), "beg", None, None, _prefix)
	
	def request_header_suffix (self, _name, _suffix, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_name), "end", None, None, _suffix)
	
	def request_header_regex (self, _name, _regex, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_header (_name), "reg", None, None, _regex)
	
	
	def response_header_exists (self, _header, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header_exists (_header, _expected), "bool", None, None, None)
	
	def response_header_empty (self, _name, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_name), "str", None, "eq", "")
	
	def response_header_equals (self, _name, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_name), "str", None, "eq", (_value,))
	
	def response_header_prefix (self, _name, _prefix, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_name), "beg", None, None, _prefix)
	
	def response_header_suffix (self, _name, _suffix, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_name), "end", None, None, _suffix)
	
	def response_header_regex (self, _name, _regex, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_header (_name), "reg", None, None, _regex)
	
	
	def request_cookie_exists (self, _cookie, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.request_cookie_exists (_cookie, _expected), "bool", None, None, None)
	
	def response_cookie_exists (self, _cookie, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.response_cookie_exists (_header, _expected), "bool", None, None, None)
	
	
	def variable_exists (self, _variable, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "found", None, None, None)
	
	def variable_empty (self, _variable, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "str", None, "eq", "")
	
	def variable_equals (self, _variable, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "str", None, "eq", (_value,))
	
	def variable_prefix (self, _variable, _prefix, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "beg", None, None, _prefix)
	
	def variable_suffix (self, _variable, _suffix, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "end", None, None, _suffix)
	
	def variable_regex (self, _variable, _regex, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable), "reg", None, None, _regex)
	
	def variable_bool (self, _variable, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable_bool (_variable, _expected), "bool", None, None, None)
	
	def variable_xxh3_64 (self, _variable, _seed, _mask, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable_xxh3_64 (_variable, _seed, _mask), "int", None, "eq", (_value,))
	
	
	def variables_equals (self, _variable_a, _variable_b, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.variable (_variable_a, (("strcmp", _variable_b),) + (("bool",) if not _expected else ("bool", "not"))), "bool", None, None, None)
	
	
	def via_tls (self, _expected = True, _method = None, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.via_tls (_expected, _method), "bool", None, None, None)
	
	def tls_client_certificate (self, _fingerprint, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_client_certificate (), "str", ("-i",), "eq", (_fingerprint,))
	
	def tls_client_certificate_issuer_cn (self, _expected_cn, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_client_certificate_issuer_cn (), "str", ("-i",), "eq", (_expected_cn,))
	
	def tls_client_certificate_subject_cn (self, _expected_cn, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_client_certificate_subject_cn (), "str", ("-i",), "eq", (_expected_cn,))
	
	
	def tls_session_sni_exists (self, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_session_sni_exists (_expected), "bool", None, None, None)
	
	def tls_session_sni_equals (self, _value, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_session_sni (), "str", None, "eq", (_value,))
	
	def tls_session_sni_equals_variable (self, _variable, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.tls_session_sni ((("strcmp", _variable),)), "int", None, "eq", (0,))
	
	
	def authenticated (self, _credentials, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.authenticated (_credentials, _expected), "bool", None, None, None)
	
	
	def backend_active (self, _backend, _expected = True, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.backend_active (_backend, _expected), "bool", None, None, None)
	
	
	def geoip_country_extracted (self, _country, _method = None, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.geoip_country_extracted (_method), "str", ("-i",), "eq", _country)
	
	def geoip_country_captured (self, _country, _identifier = None) :
		return self._context.acl_0 (_identifier, self._samples.geoip_country_captured (), "str", ("-i",), "eq", _country)
	
	
	def bogon (self, _method = None, _identifier = None) :
		return self.bogon_sample (self._samples.client_ip (_method), _identifier)
	
	def bogon_from_variable (self, _variable, _identifier = None) :
		return self.bogon_sample (self._samples.variable (_variable), _identifier)
	
	def bogon_from_request_header (self, _header, _identifier = None) :
		return self.bogon_sample (self._samples.request_header (_header), _identifier)
	
	def bogon_from_response_header (self, _header, _identifier = None) :
		return self.bogon_sample (self._samples.response_header (_header), _identifier)
	
	def bogon_sample (self, _sample, _identifier = None) :
		return self.sample_ip_in_map (_sample, "$'bogons_map", _identifier)
	
	
	def bot (self, _identifier = None) :
		return self.bot_sample (self._samples.request_header ("User-Agent", ("lower",)), _identifier)
	
	def bot_sample (self, _sample, _identifier = None) :
		return self.sample_substring_in_map (_sample, "$'bots_map", _identifier)
	
	
	def sample_ip_in_map (self, _sample, _map, _identifier = None) :
		return self._context.acl_0 (_identifier, _sample, "ip", ("-n", "-f"), None, _map)
	
	def sample_string_in_map (self, _sample, _map, _identifier = None) :
		return self._context.acl_0 (_identifier, _sample, "str", ("-i", "-f"), None, _map)
	
	def sample_substring_in_map (self, _sample, _map, _identifier = None) :
		return self._context.acl_0 (_identifier, _sample, "sub", ("-i", "-f"), None, _map)
	
	
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




