



from errors import *
from tools import *

from builders_core import *




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




