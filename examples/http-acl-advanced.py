

import ha


_ha = ha.haproxy (
		minimal_configure = True,
	)


_fe = _ha.http_frontends.basic ()




_fe.requests.deny (601, _fe.acls.geoip_country_extracted ("XX", _method = "src"))
_fe.requests.deny (601, _fe.acls.geoip_country_extracted ("XX", _method = "X-Forwarded-For"))

_fe.requests.deny (601, _fe.acls.geoip_country_captured ("XX"))

_fe.requests.deny (601, _fe.acls.bogon ())

_fe.requests.deny (601, _fe.acls.bot ())




_ha.output_stdout ()

