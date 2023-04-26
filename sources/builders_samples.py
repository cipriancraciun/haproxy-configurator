



from errors import *
from tools import *

from builders_core import *




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
			_transforms = ("host_only", ("ltrim", "."), ("rtrim", "."))
		return self._context.sample_0 ("req.fhdr", ("Host", -1), _transforms)
	
	def path (self, _transforms = None) :
		return self._context.sample_0 ("path", None, _transforms)
	
	def query (self, _transforms = None) :
		return self._context.sample_0 ("query", None, _transforms)
	
	def query_exists (self, _expected = True) :
		return self._context.sample_0 ("query", None, (("length", "bool") if _expected else ("length", "bool", "not")))
	
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
	
	def tls_client_certificate_issuer_cn (self) :
		return self._context.sample_0 ("ssl_c_i_dn", ("CN",), None)
	
	def tls_client_certificate_subject_cn (self) :
		return self._context.sample_0 ("ssl_c_s_dn", ("CN",), None)
	
	
	def tls_session_sni_exists (self, _expected = True) :
		return self._context.sample_0 ("ssl_fc_has_sni", None, (None if _expected else "not"))
	
	def tls_session_sni (self, _transforms = None) :
		return self._context.sample_0 ("ssl_fc_sni", None, _transforms)
	
	
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
	
	
	def variable_map_string_to_string (self, _variable, _map, _transforms = None) :
		if _transforms is None : _transforms = ()
		return self._context.sample_0 ("var", (_variable,), (("map", _map),) + _transforms)
	
	def variable_map_string_to_integer (self, _variable, _map, _transforms = None) :
		if _transforms is None : _transforms = ()
		return self._context.sample_0 ("var", (_variable,), (("map_int", _map),) + _transforms)
	
	def variable_map_ip_to_string (self, _variable, _map, _transforms = None) :
		if _transforms is None : _transforms = ()
		return self._context.sample_0 ("var", (_variable,), (("map_ip", _map),) + _transforms)
	
	def variable_map_ip_to_integer (self, _variable, _map, _transforms = None) :
		if _transforms is None : _transforms = ()
		return self._context.sample_0 ("var", (_variable,), (("map_ip_int", _map),) + _transforms)
	
	
	def uuid_v4 (self, _transforms = None) :
		return self._context.sample_0 ("uuid", ("4",), _transforms)
	
	def uuid_v4_no_dashes (self) :
		return self._context.sample_0 ("uuid", ("4",), (("regsub", "-", "", "g"),))
	
	def client_ip_hash (self, _method = None) :
		return self.client_ip (_method, (("digest", "md5"), "hex", "lower"))
	
	def agent_hash (self) :
		return self.request_header ("User-Agent", (("digest", "md5"), "hex", "lower"))
	
	def agent_regsub (self, _pattern, _substitutions, _flags = None) :
		return self.request_header ("User-Agent", (("regsub", _pattern, _substitutions, _flags),))




