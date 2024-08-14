



import sys
import time

from errors import *




fallback = object ()
no_fallback = object ()
undefined = object ()




class Parameters (object) :
	
	
	def __init__ (self, _super, _overrides, _defaults) :
		object.__setattr__ (self, "_super", _super)
		object.__setattr__ (self, "_defaults", _defaults)
		object.__setattr__ (self, "_parameters", dict ())
		object.__setattr__ (self, "_get_fallback_enabled", fallback)
		object.__setattr__ (self, "_get_fallback_disabled", no_fallback)
		self._set (parameters_timestamp = time.strftime ("%Y-%m-%d-%H-%M-%S", time.gmtime ()))
		self._set (**_overrides)
	
	
	def _fork (self, **_overrides) :
		return Parameters (self, _overrides, None)
	
	def _set (self, **_overrides) :
		for _parameter, _value in _overrides.iteritems () :
			self.__setattr__ (_parameter, _value)
	
	
	def _get_and_expand (self, _parameter, _default = fallback) :
		_value = self._get (_parameter, _default)
		_value = self._expand (_value)
		return _value
	
	
	def _get (self, _parameter, _default = fallback, _self = fallback) :
		try :
			return self._get_0 (_parameter, _default, _self)
		except Exception as _error :
			print >> sys.stderr, "[ee]  failed resolving parameter `%r`" % (_parameter,)
			raise
	
	def _get_0 (self, _parameter, _default, _self) :
		if _parameter.startswith ("_") :
			raise_error ("8b5c846b", _parameter)
		if _self is fallback :
			_self = self
		if _parameter in self._parameters :
			_value = self._parameters[_parameter]
		elif self._super is not None :
			_value = self._super._get_0 (_parameter, no_fallback, _self)
			if _value is no_fallback :
				_value = fallback
		else :
			_value = fallback
		if _value is fallback :
			if _default is not fallback :
				_value = _default
			elif self._defaults is not None and _parameter in self._defaults :
				_value = self._defaults[_parameter]
			elif self._super is not None :
				_value = self._super._get_0 (_parameter, fallback, _self)
		if _value is fallback :
			raise_error ("c652aa6d", _parameter)
		elif _value is no_fallback :
			return _value
		else :
			return _self._expand_0 (_value)
	
	
	def _expand (self, _value) :
		try :
			return self._expand_0 (_value)
		except Exception as _error :
			print >> sys.stderr, "[ee]  failed expanding parameter `%r`" % (_value,)
			raise
	
	def _expand_0 (self, _value) :
		if isinstance (_value, basestring) :
			return _value
		elif isinstance (_value, int) :
			return _value
		elif isinstance (_value, tuple) :
			_value = [self._expand_0 (_value) for _value in _value]
			_value = tuple (_value)
			return _value
		elif _value is None :
			return _value
		elif callable (_value) :
			_value = _value (self)
			return self._expand_0 (_value)
		else :
			raise_error ("873a2ceb", _value)
	
	
	def __getattr__ (self, _parameter) :
		if _parameter.startswith ("_") :
			raise_error ("8b5c846b", _parameter)
		return self._get (_parameter)
	
	def __setattr__ (self, _parameter, _value) :
		if _value is undefined :
			return
		if _parameter.startswith ("_") :
			raise_error ("8b5c846b", _parameter)
		if _parameter in self._parameters :
			raise_error ("7db0955d", _parameter)
		else :
			self._parameters[_parameter] = _value




