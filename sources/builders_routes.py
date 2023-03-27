



from errors import *
from tools import *

from builders_core import *
from builders_acl import *




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




