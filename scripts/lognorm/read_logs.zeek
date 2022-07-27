##! Log file analyzing with liblognorm.
##!
##! Note: This module is in testing and is not yet considered stable!

module Lognorm;

export {
	## Logfiles to read for normalization.
	const log_files: set[string] = {} &redef;
}

type LogLine: record {
	line: string;
};

event read_log(desc: Input::EventDescription, t: Input::Event,
	line: string)
	{
	if ( ! normalize(line) )
		Reporter::warning(fmt("Unable to normalize log line (%s).",
			desc$source));
	}

event zeek_init() &priority=5
	{
	for ( lf in log_files )
		{
		Input::add_event([$name=fmt("normlog-%s", lf),
		                  $source=lf,
		                  $reader=Input::READER_RAW,
		                  $mode=Input::STREAM,
		                  $fields=LogLine,
		                  $ev=read_log,
		                  $want_record=F]);
		}
	}
