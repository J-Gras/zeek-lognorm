
#ifndef BRO_PLUGIN_BRO_LIBLOGNORM
#define BRO_PLUGIN_BRO_LIBLOGNORM

#include <plugin/Plugin.h>

namespace plugin {
namespace Bro_Liblognorm {

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
