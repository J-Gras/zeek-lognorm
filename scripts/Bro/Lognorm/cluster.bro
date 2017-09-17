##! Cluster transparency support for the bro-lognorm plugin.
##! TODO: Rewrite the rule distribution using broker.

module Lognorm;

global rules: set[string];

# Distribution of rules.
global cluster_new_rule: event(rule: string);
global cluster_init_rules: event(node: string);
redef Cluster::manager2worker_events += /^Lognorm::(cluster_new_rule|cluster_init_rules)$/;

# Load rule into default_normalizer.
function load_rule(rule: string)
	{
	# NOTE: The unparsed_line event won't trigger if rules are added one by one
	if ( !lognormalizer_load_rule(default_normalizer, rule) )
		Reporter::error(fmt("Failed to load LogNormalizer rule '%s'.", rule));
	}

# Initialize rulebase on new peers.
event Lognorm::cluster_init_rules(node: string)
	{
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		return;

	for ( rule in rules )
		load_rule(rule);

	clear_table(rules);
	}

# Load new rule on all peers.
event Lognorm::cluster_new_rule(rule: string)
	{
	load_rule(rule);
	}

# Read single rule from file.
event Lognorm::read_rule(desc: Input::EventDescription, tpe: Input::Event, rule: string)
	{
	add rules[rule];
	event Lognorm::cluster_new_rule(rule);
	}

# Initialize rulebase of new workers.
event remote_connection_handshake_done(p: event_peer)
	{
	if ( Cluster::nodes[p$descr]$node_type == Cluster::WORKER )
		{
		send_id(p, "Lognorm::rules");
		event Lognorm::cluster_init_rules(p$descr);
		}
	}
