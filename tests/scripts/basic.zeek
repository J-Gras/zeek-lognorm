# @TEST-EXEC: ZEEK_ALLOW_INIT_ERRORS=T zeek %INPUT > output
# @TEST-EXEC: cat reporter.log >> output
# @TEST-EXEC: btest-diff output

#@TEST-START-FILE test.rulebase
rule=greeting,help:Hello %who:word%
rule=farewell:Bye %who:word%
rule=typetest:Type %num:rest%
#@TEST-END-FILE

@load lognorm

module Lognorm;

redef rule_files += {"test.rulebase"};

event zeek_init()
	{
	#generate_event("test_event");
	normalize("Hello world");
	normalize("Hello Annette");
	normalize("Type not matching!");
	normalize("Crash me if you can!");
	normalize("Bye Annette");
	}

event greeting(who: string)
	{
	print fmt("Greetings to '%s'", who);
	}

event farewell(who: string)
	{
	print fmt("Good bye to '%s'", who);
	}

event typetest(num: count)
	{
	print fmt("Detected type %s", num);
	}

event help(who: string, me: int)
	{
	print fmt("Why %s?", who);
	}

event unparsed_line(line: string)
	{
	print fmt("No rule for: '%s'", line);
	}
