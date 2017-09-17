#
# This is loaded when a user activates the plugin. Include scripts here that should be
# loaded automatically at that point.
# 

@load ./main

@load base/frameworks/cluster

@if ( Cluster::is_enabled() )
@load ./cluster
@endif
