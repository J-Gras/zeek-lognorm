
#include "Plugin.h"

namespace plugin { namespace Bro_Liblognorm { Plugin plugin; } }

using namespace plugin::Bro_Liblognorm;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Bro_Liblognorm::Lognorm";
	config.description = "Log file analyzing (in development)";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
