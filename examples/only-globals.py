

import ha


_ha = ha.haproxy (
		daemon_node = "haproxy-sandbox-1.servers.example.com",
		global_configure = True,
		defaults_configure = False,
	)


_ha.output_stdout ()

