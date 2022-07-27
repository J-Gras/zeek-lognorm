# @TEST-EXEC: btest-bg-run filetest zeek %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: echo "Hello files" >> test.log
# @TEST-EXEC: sleep 2
# @TEST-EXEC: echo "Bye all" >> test.log
# @TEST-EXEC: sleep 2
# @TEST-EXEC: cat filetest/reporter.log >> output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$TOOLS/diff-remove-abspath | $TOOLS/diff-remove-timestamps" btest-diff output

#@TEST-START-FILE test.rulebase
rule=greeting:Hello %who:word%
rule=farewell:Bye %who:word%
#@TEST-END-FILE

#@TEST-START-FILE test.log
Hello logs
#@TEST-END-FILE

@load Lognorm
@load Lognorm/read_logs

redef exit_only_after_terminate = T;

redef Lognorm::rule_files += {"../test.rulebase"};
redef Lognorm::log_files += {"../test.log"};

event greeting(who: string)
	{
	Reporter::info(fmt("Greetings to '%s'", who));
	}

event farewell(who: string)
	{
	Reporter::info(fmt("Good bye to '%s'", who));
	terminate();
	}
