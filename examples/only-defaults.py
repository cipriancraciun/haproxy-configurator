

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
		defaults_configure = True,
		global_configure = False,
	)


_ha.output_stdout ()

