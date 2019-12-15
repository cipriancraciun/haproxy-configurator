

import ha


_ha = ha.haproxy (
		globals_configure = True,
		defaults_configure = False,
	)


_ha.output_stdout ()

