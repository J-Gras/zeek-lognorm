##! Log file analyzing with liblognorm.
##!
##! Note: This module is in testing and is not yet considered stable!

module Lognorm;

export {
	## Rule files in liblognorm format that will be used for the
	## normalization of log lines.
	const rule_files: set[string] = {} &redef;

	## Function to normalize a log line. For each tag the matching
	## rule defines, the corresponding event will be scheduled.
	## Each field the rule defines, will be passed as parameter
	## to the event.
	##
	## line: The log line to normalize.
	##
	## Returns: T on success.
	global normalize: function(line: string): bool;

	## Event that is raised in case there is no matching rule for
	## a given log line.
	##
	## line: The unparsed log line.
	global unparsed_line: event(line: string);
}

global default_normalizer: opaque of lognormalizer;

event bro_init() &priority=5
	{
	default_normalizer = lognormalizer_init_ex(unparsed_line);

	for ( rf in rule_files )
		{
		if ( !lognormalizer_load_rules(default_normalizer, rf) )
			Reporter::error(fmt("Failed to load LogNormalizer rule file '%s'.", rf));
		}
	}

function normalize(line: string): bool
	{
	return lognormalizer_normalize(default_normalizer,
		gsub(line, /\x00/, ""));
	}
