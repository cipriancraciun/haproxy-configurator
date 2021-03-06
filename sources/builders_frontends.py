



from errors import *
from tools import *

from builders_core import *




class HaHttpFrontendBuilder (HaBuilder) :
	
	def __init__ (self, _context, _parameters) :
		HaBuilder.__init__ (self, _context, _parameters)
	
	
	def basic (self, _identifier = None, _tls = None, _non_tls = None, **_parameters) :
		
		_identifier = _identifier if _identifier is not None else "http"
		_tls = _tls if _tls is not None else False
		_non_tls = _non_tls if _non_tls is not None else True
		
		_frontend = self._context.http_frontend_create (_identifier, **_parameters)
		
		if _non_tls :
			_frontend.declare_bind (overrides = _parameters)
		
		if _tls :
			_frontend.declare_bind_tls (overrides = _parameters)
		
		return _frontend




