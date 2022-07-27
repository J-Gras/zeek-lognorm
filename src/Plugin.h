
#ifndef ZEEK_PLUGIN_ZEEK_LOGNORM
#define ZEEK_PLUGIN_ZEEK_LOGNORM

#include <zeek/plugin/Plugin.h>

namespace plugin::Zeek_Lognorm {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}

#endif
