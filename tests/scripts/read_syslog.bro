# @TEST-EXEC: bro -r $TRACES/syslog-single-udp.trace %INPUT > output
# @TEST-EXEC: btest-diff output

#@TEST-START-FILE test.rulebase
rule=test_event:%date:date-rfc3164% %user:word% %msg:rest%
#@TEST-END-FILE

@load Bro/Lognorm
@load Bro/Lognorm/read_syslog

module Lognorm;

redef rule_files += {"test.rulebase"};

event test_event(msg: string)
	{
	print fmt("Msg = '%s'", msg);
	}
