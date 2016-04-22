# @TEST-EXEC: bro %INPUT >output
# @TEST-EXEC: btest-diff output

#@TEST-START-FILE test.rulebase
rule=test_event:Hello %who:word%
rule=test2_event:Bye %who:word%
#@TEST-END-FILE

module Lognorm;

redef rule_file = "test.rulebase";

event bro_init() 
	{
	#generate_event("test_event");
	normalize("Hello world");
	normalize("Hello Anna");
	normalize("Bye Anna");
	}

event test_event(s: string)
	{
	print fmt("Greetings to '%s'", s);
	}

event test2_event(s: string)
	{
	print fmt("Good bye to '%s'", s);
	}
