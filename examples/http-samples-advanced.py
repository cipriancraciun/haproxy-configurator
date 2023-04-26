

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()




_fe.requests.set_header_from_sample ("agent_hash", _fe.samples.agent_hash ())
_fe.requests.set_header_from_sample ("agent_regsub", _fe.samples.agent_regsub ("^.* id-([0-9a-f]+) .*$", "\\1"))




_ha.output_stdout ()

