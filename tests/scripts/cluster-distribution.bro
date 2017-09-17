# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: btest-bg-run worker-1 BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2 BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: cat add.rulebase >> test.rulebase
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: cat manager-1/.stdout > output
# @TEST-EXEC: cat worker-1/.stdout >> output
# @TEST-EXEC: cat worker-2/.stdout >> output
# @TEST-EXEC: btest-diff output

#@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_type=Cluster::MANAGER, $ip=127.0.0.1, $p=37757/tcp, $workers=set("worker-1", "worker-2")],
	["worker-1"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37760/tcp, $manager="manager-1"],
	["worker-2"]  = [$node_type=Cluster::WORKER,  $ip=127.0.0.1, $p=37761/tcp, $manager="manager-1"],
};
#@TEST-END-FILE

#@TEST-START-FILE test.rulebase
rule=greeting:Hello %who:word%
rule=farewell:Bye %who:word%
#@TEST-END-FILE

#@TEST-START-FILE add.rulebase
rule=progress:Add %who:word%
#@TEST-END-FILE

@load Bro/Lognorm
@load base/frameworks/control
redef Log::default_rotation_interval=0sec;

module Lognorm;

redef rule_files += { "../test.rulebase" };

event Lognorm::cluster_new_rule(rule: string) &priority=-5
	{
	print fmt("Received new rule: '%s'", rule);
	}

event run_test3()
	{
	normalize("Bye Cluster");
	}

event run_test2()
	{
	normalize(fmt("Add %s", Cluster::node));
	schedule 1sec { run_test3() };
	}

event run_test1()
	{
	normalize("Hello Cluster");
	schedule 6sec { run_test2() };
	}

event bro_init()
	{
	# Delay to allow for the data distribution mechanism to
	# distribute the data to the workers
	schedule 2sec { run_test1() };
	}

event greeting(who: string)
	{
	print fmt("Greetings to '%s' from %s", who, Cluster::node);
	}

event progress(who: string)
	{
	print fmt("Progress on '%s'", who);
	}

event farewell(who: string)
	{
	print fmt("Good bye to '%s' from %s", who, Cluster::node);
	# Shutdown the cluster
	schedule 1sec { Control::shutdown_request() };
	}
