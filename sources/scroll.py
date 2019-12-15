



import sys

from errors import *




class Scroll (object) :
	
	def __init__ (self, _indent = 0) :
		self._contents = list ()
		self._indent = _indent
	
	def is_empty (self) :
		return len (self._contents) == 0
	
	def include_normal_line (self, _order, _indent, _contents) :
		if isinstance (_contents, list) :
			if len (_contents) == 0 :
				return
			elif len (_contents) == 1 :
				_contents = _contents[0]
		self._contents.append ((_order, _indent, _contents))
	
	def include_scroll_lines (self, _order, _indent, _scroll, _recurse) :
		for _line_order, _line_indent, _line_contents in _scroll._contents :
			if _line_order is None :
				_line_order = _order
			if _line_indent is not None :
				_line_indent += _indent
			else :
				_line_indent = _indent
			_line_indent += _scroll._indent
			if isinstance (_line_contents, basestring) or isinstance (_line_contents, tuple) :
				self._contents.append ((_line_order, _line_indent, _line_contents))
			elif isinstance (_line_contents, ScrollPart) :
				self._contents.append ((_line_order, _line_indent, _line_contents))
			elif isinstance (_line_contents, Scroll) :
				if _recurse :
					self.include_scroll_lines (_line_order, _line_indent, _line_contents, True)
				else :
					self._contents.append ((_line_order, _line_indent, _line_contents))
			else :
				raise_error ("a602a2e8", _line_contents)
	
	def include_comment_line (self, _order, _indent, _contents) :
		self._contents.append ((_order, _indent, ScrollCommentLine (_contents)))
	
	def include_empty_line (self, _order, _indent, _count = 1) :
		self._contents.append ((_order, _indent, ScrollEmptyLine (_count)))
	
	def output_stdout (self) :
		self.output (sys.stdout)
	
	def output (self, _stream, _indent = 0) :
		if not isinstance (_stream, ScrollOutputer) :
			_stream = ScrollOutputer (_stream)
			_stream_should_be_closed = True
		else :
			_stream_should_be_closed = False
		_contents = sorted (self._contents, key = lambda _contents : _contents[0] if _contents[0] is not None else 1 << 16)
		for _order, _indent_0, _contents in _contents :
			self._output_contents (_order, _indent_0 + _indent + self._indent, _contents, _stream)
		if _stream_should_be_closed :
			_stream.output_done ()
	
	def _output_contents (self, _order, _indent, _contents, _stream) :
		if isinstance (_contents, basestring) :
			_stream.output_marker (_indent, 0, "## ~~ %s" % _order)
			_stream.output_line (_indent, _contents)
		elif isinstance (_contents, tuple) :
			_contents = self._format_tokens (_contents)
			self._output_contents (_order, _indent, _contents, _stream)
		elif isinstance (_contents, ScrollPart) :
			_contents.output (_stream, _indent)
		elif isinstance (_contents, Scroll) :
			_stream.output_marker (_indent, +1, "## >> Scroll %s" % _order)
			_contents.output (_stream, _indent)
			_stream.output_marker (_indent, -1, "## <<")
		elif isinstance (_contents, list) :
			_stream.output_marker (_indent, +1, "## >> List %s" % _order)
			for _contents in _contents :
				self._output_contents (_order, _indent, _contents, _stream)
			_stream.output_marker (_indent, -1, "## <<")
		else :
			raise_error ("1fe1b0e1", _contents)
	
	def _format_tokens (self, _tokens) :
		if isinstance (_tokens, basestring) :
			return _tokens
		elif isinstance (_tokens, int) :
			_tokens = str (_tokens)
			return _tokens
		elif isinstance (_tokens, tuple) :
			_tokens = [self._format_tokens (_tokens) for _tokens in _tokens]
			_tokens = " ".join (_tokens)
			return _tokens
		else :
			raise_error ("4ca0c09d", _tokens)




class ScrollPart (object) :
	
	def __init__ (self) :
		pass
	
	def output (self, _stream, _indent) :
		raise_error ("0d8d2498")


class ScrollCommentLine (ScrollPart) :
	
	def __init__ (self, _contents) :
		ScrollPart.__init__ (self)
		self._contents = _contents
	
	def output (self, _stream, _indent) :
		_stream.output_line (_indent, self._contents)


class ScrollEmptyLine (ScrollPart) :
	
	def __init__ (self, _count = 1) :
		ScrollPart.__init__ (self)
		self._count = _count
	
	def output (self, _stream, _indent) :
		_stream.output_empty (self._count)




class ScrollOutputer (object) :
	
	def __init__ (self, _stream) :
		self._stream = _stream
		self._just_opened = True
		self._pending_empty = 1
		self._opened = True
		self._adjust_indent = 0
	
	def output_empty (self, _count = 1) :
		if not self._opened :
			raise_error ("f75bc7b0")
		self._pending_empty = max (self._pending_empty, _count)
	
	def output_line (self, _indent, _line) :
		if not isinstance (_line, basestring) :
			raise_error ("0512b71a", _line)
		if not self._opened :
			raise_error ("fbce7fc3")
		if self._just_opened :
			self._stream.write ("\n")
			self._pending_empty = 0
			self._just_opened = False
		elif self._pending_empty > 0 :
			self._stream.write ("\n" * self._pending_empty)
			self._pending_empty = 0
		self._stream.write ("    " * (self._adjust_indent + _indent))
		self._stream.write (_line)
		self._stream.write ("\n")
	
	def output_marker (self, _indent, _adjust_indent, _line) :
		if False :
			if _adjust_indent < 0 :
				self._adjust_indent += _adjust_indent
			self.output_line (_indent, _line)
			if _adjust_indent > 0 :
				self._adjust_indent += _adjust_indent
	
	def output_done (self) :
		if not self._just_opened :
			self._stream.write ("\n")
		self._opened = False




