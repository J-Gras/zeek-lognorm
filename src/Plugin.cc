
#include "Plugin.h"

namespace plugin { namespace Bro_Lognorm { Plugin plugin; } }

using namespace plugin::Bro_Lognorm;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Bro::Lognorm";
	config.description = "Log file analyzing (in development)";
	config.version.major = 0;
	config.version.minor = 2;
	return config;
	}
