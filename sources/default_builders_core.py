



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




