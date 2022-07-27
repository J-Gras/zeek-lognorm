##! Log file analyzing with liblognorm.
##!
##! Note: This module is in testing and is not yet considered stable!

module Lognorm;

event syslog_message(c: connection, facility: count, severity: count, msg: string)
	{
	if ( ! normalize(msg) )
		Reporter::warning(fmt("Unable to normalize syslog message (facility = %s).",
			facility));
	}
