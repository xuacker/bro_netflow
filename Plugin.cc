
#include "plugin/Plugin.h"

#include "NETFLOW.h"

namespace plugin {
namespace Bro_NETFLOW {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
	{
		AddComponent(new ::analyzer::Component("NETFLOW", ::analyzer::netflow::NETFLOW_Analyzer::Instantiate));

				plugin::Configuration config;
				config.name = "Bro::NETFLOW";
				config.description = "NETFLOW analyzer";
				return config;
			}
} plugin;

}
}
