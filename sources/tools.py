



import inspect
import hashlib
import sys

from errors import *




def enforce_identifier (_parameters, _identifier, _null_allowed = False) :
	if _identifier is None :
		if _null_allowed :
			return _identifier
		else :
			raise_error ("99640036", _identifier)
	elif isinstance (_identifier, basestring) :
		return _identifier
	elif callable (_identifier) :
		return _identifier (_parameters)
	else :
		raise_error ("52d21d23", _identifier)




def enforce_token (_token, _schema, _raise = True) :
	try :
		return enforce_token_0 (_token, _schema, _raise)
	except Exception as _error :
		print >> sys.stderr, "[ee]  failed enforcing token `%r` for schema `%r`" % (_token, _schema)
		raise


def enforce_token_0 (_token, _schema, _raise) :
	if _schema is None :
		if _token is None :
			return enforce_token_0_return (_token, _raise)
		else :
			return enforce_token_0_raise (_raise, "8308c836", _schema, _token)
	elif type (_schema) is type :
		if isinstance (_token, _schema) :
			return enforce_token_0_return (_token, _raise)
		else :
			return enforce_token_0_raise (_raise, "a9bf09e3", _schema, _token)
	elif isinstance (_schema, tuple) or isinstance (_schema, list) :
		if isinstance (_token, type (_schema)) :
			if len (_token) == len (_schema) :
				for _index in xrange (_schema) :
					if _raise :
						enforce_token_0 (_token[_index], _schema[_index], True)
					else :
						if not enforce_token_0 (_token[_index], _schema[_index], False) :
							return False
				return enforce_token_0_return (_token, _raise)
			else :
				return enforce_token_0_raise (_raise, "e8dc8194", _schema, _token)
		else :
			return enforce_token_0_raise (_raise, "dd8fb1a0", _schema, _token)
	elif isinstance (_schema, dict) :
		_type = _schema["type"]
		if _type is tuple or _type is list :
			_element_schema = _schema["schema"]
			if isinstance (_token, _type) :
				for _element_token in _token :
					if _raise :
						enforce_token_0 (_element_token, _element_schema, True)
					else :
						if not enforce_token_0 (_element_token, _element_schema, False) :
							return False
				return enforce_token_0_return (_token, _raise)
			else :
				return enforce_token_0_raise (_raise, "391c370b", _schema, _token)
		elif _type == "or" :
			_or_schemas = _schema["schemas"]
			for _or_schema in _or_schemas :
				if enforce_token_0 (_token, _or_schema, False) :
					return enforce_token_0_return (_token, _raise)
			return enforce_token_0_raise (_raise, "ec11e65d", _schema, _token)
		elif _type == "and" :
			_and_schemas = _schema["schemas"]
			for _and_schema in _and_schemas :
				if _raise :
					return enforce_token_0 (_token, _and_schema, True)
				else :
					if not enforce_token_0 (_token, _and_schema, False) :
						return False
			return enforce_token_0_return (_token, _raise)
		else :
			return enforce_token_0_raise (_raise, "76a24902", _type, _token)
	else :
		return enforce_token_0_raise (_raise, "010e60ef", _schema, _token)


def enforce_token_0_return (_token, _raise) :
	if _raise :
		return _token
	else :
		return True

def enforce_token_0_raise (_raise, _code, *_arguments) :
	if _raise :
		raise_error (_code, *_arguments)
	else :
		return False




def expand_token (_token, _parameters, _join = None, _quote = None) :
	try :
		return expand_token_0 (_token, _parameters, _join, _quote)
	except Exception as _error :
		print >> sys.stderr, "[ee]  failed expanding token `%r`" % (_token,)
		raise


def expand_token_0 (_token, _parameters, _join, _quote) :
	if isinstance (_token, basestring) :
		if _token.startswith ("$") :
			_token = _token[1:]
			if _token.startswith ("\'") :
				_token = _token[1:]
				_quote = "\'"
			elif _token.startswith ("\"") :
				_token = _token[1:]
				_quote = "\""
			elif _token.startswith ("+") :
				_token = _token[1:]
				_token = statement_enforce_int ("$" + _token)
				return expand_token_0 (_token, _parameters, _join, _quote)
			elif _token.startswith ("?") :
				_token = _token[1:]
				if _token.startswith ("!") :
					_token = _token[1:]
					_token = statement_not (statement_enforce_bool ("$" + _token))
				else :
					_token = statement_enforce_bool ("$" + _token)
				return expand_token_0 (_token, _parameters, _join, _quote)
			elif _token.startswith ("~") :
				_token = _token[1:]
				_token = statement_enforce_keyword ("$" + _token)
				return expand_token_0 (_token, _parameters, _join, _quote)
			_token = resolve_token_0 ("$" + _token, _parameters, False)
			return expand_token_0 (_token, _parameters, _join, _quote)
		elif _token.startswith ("#") :
			_token = _token[1:]
			if _token.startswith ("\'") :
				_token = _token[1:]
				_quote = "\'"
			elif _token.startswith ("\"") :
				_token = _token[1:]
				_quote = "\""
			elif _token.startswith ("+") :
				_token = _token[1:]
				try :
					_token = int (_token)
				except :
					raise_error ("0613b0dd", _token)
			else :
				raise_error ("955a8724", _token)
			return expand_token_0 (_token, _parameters, _join, _quote)
		else :
			if _quote is not None :
				return _quote_token (_token, _quote, (lambda _token : expand_token_0 (_token, _parameters, None, None)))
			else :
				return _token
	elif isinstance (_token, int) :
		if _quote is not None :
			return _quote_token (_token, _quote, (lambda _token : expand_token_0 (_token, _parameters, None, None)))
		else :
			return _token
	elif isinstance (_token, tuple) :
		if isinstance (_join, basestring) :
			_token = [expand_token_0 (_token, _parameters, None, None) for _token in _token]
			_token = [_token for _token in _token if _token is not None]
			if len (_token) > 0 :
				_token = _join.join (_token)
			else :
				_token = None
		elif _join is None :
			_token = [expand_token_0 (_token, _parameters, None, None) for _token in _token]
			_token = [_token for _token in _token if _token is not None]
			if len (_token) > 0 :
				_token = tuple (_token)
			else :
				_token = None
		elif _join is tuple or _join is list :
			_outcome = []
			def _outcome_flatten (_token) :
				if isinstance (_token, tuple) or isinstance (_token, list) :
					for _token in _token :
						_outcome_flatten (_token)
				else :
					_token = expand_token_0 (_token, _parameters, None, None)
					if isinstance (_token, tuple) or isinstance (_token, list) :
						_outcome_flatten (_token)
					else :
						_outcome.append (_token)
			_outcome_flatten (_token)
			_token = _outcome
			if len (_token) > 0 :
				if _join is tuple :
					_token = tuple (_token)
			else :
				_token = None
		else :
			raise_error ("afae3a77", _join)
		if _token is not None and _quote is not None :
			_token = _quote_token (_token, _quote, lambda _token : expand_token_0 (_token, _parameters, None, None))
		return _token
	elif _token is None :
		return None
	elif hasattr (_token, "_self_expand_token") :
		_token = _token._self_expand_token ()
		return expand_token_0 (_token, _parameters, _join, _quote)
	elif callable (_token) :
		if len (inspect.getargspec (_token) .args) == 1 :
			_token = _token (lambda _token : expand_token_0 (_token, _parameters, None, None))
		else :
			_token = _token (lambda _token, _parameters : expand_token_0 (_token, _parameters, None, None), _parameters)
		return expand_token_0 (_token, _parameters, _join, _quote)
	else :
		_token = resolve_token_0 (_token, _parameters, False)
		return expand_token_0 (_token, _parameters, _join, _quote)




def resolve_token (_token, _parameters, _recurse = True) :
	try :
		return resolve_token_0 (_token, _parameters, _recurse)
	except Exception as _error :
		print >> sys.stderr, "[ee]  failed resolving token `%r`" % (_token,)
		raise

def resolve_token_0 (_token, _parameters, _recurse) :
	if isinstance (_token, basestring) :
		if _token.startswith ("$") :
			_token = _token[1:]
			if _token.startswith ("+") :
				_token = _token[1:]
				_token = _parameters._get (_token)
				if isinstance (_token, int) :
					return _token
				else :
					raise_error ("b6a20829", _token)
			elif _token.startswith ("?") :
				_token = _token[1:]
				if _token.startswith ("!") :
					_token = _token[1:]
					_negate = True
				else :
					_negate = False
				_token = _parameters._get (_token)
				if _token is True or _token is False :
					if _negate :
						return not _token
					else :
						return _token
				else :
					raise_error ("b5175532", _token)
			else :
				_token = _parameters._get (_token)
				if _recurse :
					return resolve_token_0 (_token, _parameters, True)
				else :
					return _token
		else :
			return _token
	elif isinstance (_token, int) :
		return _token
	elif isinstance (_token, tuple) :
		if _recurse :
			_token = [resolve_token_0 (_token, _parameters, True) for _token in _token]
			_token = tuple (_token)
			return _token
		else :
			return _token
	elif hasattr (_token, "_self_resolve_token") :
		_token = _token._self_resolve_token ()
		if _recurse :
			return resolve_token_0 (_token, _parameters, True)
		else :
			return _token
	elif callable (_token) :
		if _recurse :
			if len (inspect.getargspec (_token) .args) == 1 :
				_token = _token (lambda _token : resolve_token_0 (_token, _parameters, True))
			else :
				_token = _token (lambda _token, _parameters : resolve_token_0 (_token, _parameters, True), _parameters)
			return resolve_token_0 (_token, _parameters, True)
		else :
			return _token
	elif _token is None :
		return _token
	else :
		raise_error ("d9ff522a", _token)




def _quote_token (_token, _quote, _expand) :
	if _quote != "\"" and _quote != "\'" and _quote != "\"?" and _quote != "\'?" :
		raise_error ("9f90118a", _quote)
	if isinstance (_token, basestring) :
		if _quote == "\"" or _quote == "\"?" :
			_token = _token.replace ("\\", "\\\\")
			_token = _token.replace ("\"", "\\\"")
			_token = _token.replace ("\r", "\\r")
			_token = _token.replace ("\n", "\\n")
			_token = "\"" + _token + "\""
			return _token
		elif _quote == "\'" or _quote == "\'?" :
			_token = _token.replace ("\'", "'\\''")
			_token = _token.replace ("\r", "'\\r'")
			_token = _token.replace ("\n", "'\\n'")
			_token = "\'" + _token + "\'"
			return _token
	elif isinstance (_token, int) :
		if _quote == "\"?" or _quote == "\'?" :
			return _token
		else :
			_token = str (_token)
			return _quote_token (_token, _quote, _expand)
	elif isinstance (_token, tuple) :
		_token = [_quote_token (_token, _quote, _expand) for _token in _token]
		_token = tuple (_token)
		return _token
	elif _token is None :
		raise_error ("f4226423")
	else :
		_token = _expand (_token)
		return _quote_token (_token, _quote, _expand)


def quote_token (_quote, _token) :
	return _quote_token (_token, _quote, None)




def hash_token (_token) :
	_hasher = hashlib.md5 ()
	hash_token_update (_hasher, _token)
	return _hasher.hexdigest ()

def hash_token_update (_hasher, _token) :
	if _token is None :
		pass
	elif isinstance (_token, basestring) :
		_hasher.update (_token.encode ("utf-8"))
	elif isinstance (_token, int) :
		_hasher.update (str (_token))
	elif isinstance (_token, tuple) or isinstance (_token, list) :
		_token_is_first = True
		for _token in _token :
			if not _token_is_first :
				_hasher.update (" ")
			hash_token_update (_hasher, _token)
			_token_is_first = False
	else :
		raise_error ("b9ef067b", _token)




def statement_quote (_quote = "\'", *_token) :
	return lambda _expand : _quote_token (_expand (_token), _quote, _expand)

def statement_seconds (_value) :
	return lambda _expand : "%ds" % _expand (_value)

def statement_overrides (_value, **_overrides) :
	return lambda _expand, _parameters : _expand (_value, _parameters._fork (**_overrides))




def statement_enforce_type (_type, _value) :
	def _function (_expand) :
		_actual = _expand (_value)
		if not isinstance (_actual, _type) :
			raise_error ("97f18161", _type, _value, _actual)
		return _actual
	return _function

def statement_enforce_int (_value) :
	return statement_enforce_type (int, _value)

def statement_enforce_bool (_value) :
	return statement_enforce_type (bool, _value)

def statement_enforce_string (_value) :
	return statement_enforce_type (basestring, _value)

def statement_enforce_keyword (_value) :
	# FIXME:  Implement this!
	return _value



def statement_format (_format, *_arguments) :
	return lambda _expand : _expand (_format) % tuple ([_expand (_argument) for _argument in _arguments])

def statement_coalesce (*_values) :
	def _function (_expand) :
		for _value in _values :
			_value = _expand (_value)
			if _value is not None :
				return _value
		return None
	return _function

def statement_join (_separator, _arguments, non_null = True, null_if_empty = True) :
	def _function (_expand) :
		_separator_actual = _expand (_separator)
		_arguments_actual = _expand (_arguments)
		if _arguments_actual is None :
			return None
		else :
			if non_null :
				_arguments_actual = [_argument_actual for _argument_actual in _arguments_actual if _argument_actual is not None]
			if null_if_empty and len (_arguments_actual) == 0 :
				return None
			else :
				return _separator_actual.join (_arguments_actual)
	return _function




def statement_and (*_values) :
	def _function (_expand) :
		for _value in _values :
			_actual = _expand (_value)
			if _actual is False :
				return False
			elif _actual is True :
				continue
			else :
				raise_error ("761eef06", _value, _actual)
		return True
	return _function

def statement_or (*_values) :
	def _function (_expand) :
		for _value in _values :
			_actual = _expand (_value)
			if _actual is True :
				return True
			elif _actual is False :
				continue
			else :
				raise_error ("d851191c", _value, _actual)
		return False
	return _function

def statement_not (_value) :
	def _function (_expand) :
		_actual = _expand (_value)
		if _actual is True :
			return False
		elif _actual is False :
			return True
		else :
			raise_error ("af234e46", _value, _actual)
	return _function



def statement_choose_if (_condition, _then, _else = None) :
	return lambda _expand : _then if _expand (_condition) else _else

def statement_choose_if_is (_condition, _expected, _then, _else = None) :
	return lambda _expand : _then if _expand (_condition) is _expected else _else

def statement_choose_if_is_not (_condition, _expected, _then, _else = None) :
	return lambda _expand : _then if _expand (_condition) is not _expected else _else

def statement_choose_if_null (_condition, _then, _else = None) :
	return statement_choose_if_is (_condition, None, _then, _else)

def statement_choose_if_non_null (_condition, _then, _else = None) :
	return statement_choose_if_is_not (_condition, None, _then, _else)

def statement_choose_if_true (_condition, _then, _else = None) :
	return statement_choose_if_is (_condition, True, _then, _else)

def statement_choose_if_false (_condition, _then, _else = None) :
	return statement_choose_if_is (_condition, False, _then, _else)

def statement_choose_match (_condition, *_cases) :
	def _function (_expand) :
		_actual = _expand (_condition)
		for _case in _cases :
			if len (_case) != 2 :
				raise_error ("72ad5734", _case)
			_then = _case[1]
			_expected = _case[0]
			_expected = _expand (_expected)
			if _actual == _expected :
				return _then
		raise_error ("7e97f033", _condition, _actual)
	return _function

def statement_choose_max (*_values) :
	return lambda _expand : max (*[_expand (_value) for _value in _values])

def statement_choose_min (*_values) :
	return lambda _expand : min (*[_expand (_value) for _value in _values])




def parameters_get (_parameter) :
	return lambda _parameters : _parameters._get (_parameter)

def parameters_get_with_overrides (_parameter, **_overrides) :
	return lambda _parameters : _parameters._fork (**_overrides) ._get (_parameter)

def parameters_math (_operator, _argument_1, _argument_2, _null_if_any_null = False) :
	def _function (_parameters) :
		_argument_1_actual = _parameters._expand (_argument_1)
		_argument_2_actual = _parameters._expand (_argument_2)
		if _argument_1_actual is None or _argument_2_actual is None :
			if _null_if_any_null :
				return None
			elif _argument_1_actual is None :
				raise_error ("7df73e38", _argument_1)
			elif _argument_2_actual is None :
				raise_error ("cee20b59", _argument_2)
			else :
				raise_error ("f5fefdf7")
		if _operator == "+" :
			return _argument_1_actual + _argument_2_actual
		elif _operator == "-" :
			return _argument_1_actual - _argument_2_actual
		elif _operator == "*" :
			return _argument_1_actual * _argument_2_actual
		elif _operator == "/" :
			return _argument_1_actual / _argument_2_actual
		elif _operator == "//" :
			return _argument_1_actual // _argument_2_actual
		else :
			raise_error ("c988cf62", _operator)
	return _function




def parameters_format (_format, *_arguments) :
	return lambda _parameters : _parameters._expand (_format) % _parameters._expand (_arguments)

def parameters_coalesce (*_values) :
	def _function (_parameters) :
		for _value in _values :
			_value = _parameters._expand (_value)
			if _value is not None :
				return _value
		return None
	return _function

def parameters_join (_separator, _arguments, non_null = True, null_if_empty = True) :
	def _function (_parameters) :
		_separator_actual = _parameters._expand (_separator)
		_arguments_actual = _parameters._expand (_arguments)
		if _arguments_actual is None :
			return None
		else :
			if non_null :
				_arguments_actual = [_argument_actual for _argument_actual in _arguments_actual if _argument_actual is not None]
			if null_if_empty and len (_arguments_actual) == 0 :
				return None
			else :
				return _separator_actual.join (_arguments_actual)
	return _function




def parameters_choose_if (_condition, _then, _else = None) :
	return lambda _parameters : _then if _parameters._expand (_condition) else _else

def parameters_choose_if_is (_condition, _expected, _then, _else = None) :
	return lambda _parameters : _then if _parameters._expand (_condition) is _expected else _else

def parameters_choose_if_is_not (_condition, _expected, _then, _else = None) :
	return lambda _parameters : _then if _parameters._expand (_condition) is not _expected else _else

def parameters_choose_if_null (_condition, _then, _else = None) :
	return parameters_choose_if_is (_condition, None, _then, _else)

def parameters_choose_if_non_null (_condition, _then, _else = None) :
	return parameters_choose_if_is_not (_condition, None, _then, _else)

def parameters_choose_if_true (_condition, _then, _else = None) :
	return parameters_choose_if_is (_condition, True, _then, _else)

def parameters_choose_if_false (_condition, _then, _else = None) :
	return parameters_choose_if_is (_condition, False, _then, _else)

def parameters_choose_match (_condition, *_cases) :
	def _function (_parameters) :
		_actual = _parameters._expand (_condition)
		for _case in _cases :
			if len (_case) != 2 :
				raise_error ("1b251e89", _case)
			_then = _case[1]
			_expected = _case[0]
			_expected = _parameters._expand (_expected)
			if _actual == _expected :
				return _then
		raise_error ("29b17200", _condition, _actual)
	return _function




def parameters_overrides (_fallback, **_overrides) :
	_parameters = dict (_fallback)
	_parameters.update (_overrides)
	return _parameters

def parameters_defaults (_fallback, **_defaults) :
	_parameters = dict (_defaults)
	_parameters.update (_fallback)
	return _parameters




__default__ = object ()




