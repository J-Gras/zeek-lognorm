
#include "Plugin.h"

namespace plugin::Zeek_Lognorm { Plugin plugin; }

using namespace plugin::Zeek_Lognorm;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Zeek::Lognorm";
	config.description = "Log file analyzing (experimental)";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
