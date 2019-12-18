

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
	)


_fe = _ha.http_frontends.basic ()
_be = _ha.http_backends.basic (_frontend = _fe)


_ha.output_stdout ()

