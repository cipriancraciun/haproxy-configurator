

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
		only_frontends_and_backends = True,
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)


_ha.output_stdout ()

