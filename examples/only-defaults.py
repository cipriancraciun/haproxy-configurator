

import ha


_ha = ha.haproxy (
		defaults_configure = True,
		globals_configure = False,
	)


_ha.output_stdout ()

