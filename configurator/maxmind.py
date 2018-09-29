

import csv
import json
import sys

import ipaddr



def load (_blocks_path, _countries_path) :
	
	_blocks = _load_csv (_blocks_path)
	_countries = _load_csv (_countries_path)
	
	_countries_map = {}
	for _country in _countries :
		_key = _country["geoname_id"]
		if _key in _countries_map :
			raise Exception (("e139c9ff", _key))
		_value = (_country["continent_code"], _country["country_iso_code"], _country["country_name"])
		_countries_map[_key] = _value
	
	_blocks_map = {}
	for _block in _blocks :
		_key = _block["network"]
		if _key in _blocks_map :
			raise Exception (("d9afa5d6", _key))
		_country = _block["geoname_id"]
		if _country == "" :
			_country = None
		if _country is not None :
			if _country not in _countries_map :
				raise Exception (("83d60991", _country))
			_continent, _country_code, _country_name = _countries_map[_country]
			if _continent == "" :
				_continent = None
			if _country_code == "" :
				_country_code = None
			if _country_name == "" :
				_country_name = None
		else :
			_continent = None
			_country_code = None
			_country_name = None
		_blocks_map[_key] = {
				"network" : _key,
				"continent" : _continent,
				"country_code" : _country_code,
				"country_name" : _country_name,
			}
	
	return _blocks_map


def _load_csv (_path) :
	_header = None
	_records = []
	with open (_path, "rb") as _stream :
		_stream = csv.reader (_stream, dialect = "excel", strict = True)
		for _row in _stream :
			if _header is None :
				_header = _row
			else :
				if len (_header) != len (_row) :
					raise Exception ("8ff3b9bb")
				_record = {_key : _value for _key, _value in zip (_header, _row)}
				_records.append (_record)
	return _records




def export_json (_blocks_path, _countries_path) :
	_output_stream = sys.stdout
	_blocks = load (_blocks_path, _countries_path)
	json.dump (_blocks, _output_stream, ensure_ascii = True, indent = 4, separators = (",", " : "), sort_keys = True)


def export_map (_blocks_path, _countries_path) :
	_output_stream = sys.stdout
	_blocks = load (_blocks_path, _countries_path)
	_lines = []
	for _block in _blocks.values () :
		_country_code = _block["country_code"]
		if _country_code is None :
			_country_code = "00"
		_line = "%-20s  %2s" % (_block["network"], _country_code)
		_lines.append (_line)
	_lines.sort ()
	for _line in _lines :
		_output_stream.write (_line)
		_output_stream.write ("\n")




if __name__ == "__main__" :
	if sys.argv[1] == "json" :
		export_json (*sys.argv[2:])
	elif sys.argv[1] == "map" :
		export_map (*sys.argv[2:])
	else :
		raise Exception (("ebc9e156", sys.argv[1]))

