
#ifndef BRO_PLUGIN_BRO_LOGNORM
#define BRO_PLUGIN_BRO_LOGNORM

#include <plugin/Plugin.h>

namespace plugin {
namespace Bro_Lognorm {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
