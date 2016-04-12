
#include "LogNormalizer.h"
#include <Event.h>
#include <EventRegistry.h>

extern "C" {
#include <json-c/json.h>
}

using namespace plugin::Bro_Liblognorm;

LogNormalizer::LogNormalizer()
	{
	ctx = ln_initCtx();
	}

LogNormalizer::~LogNormalizer()
	{
	ln_exitCtx(ctx);
	}

bool LogNormalizer::LoadRules(const char* filename)
	{
	return ln_loadSamples(ctx, filename) == 0;
	}

bool LogNormalizer::Normalize(const char* line)
	{
	json_object* json = NULL;

	int err = ln_normalize(ctx, line, strlen(line), &json);
	if ( err != 0 )
		return false;

	json_object* tags = NULL;
	val_list* vl = new val_list;
	json_object_iter it;
	
	// Retrieve tags and parameters
	json_object_object_foreachC ( json, it )
		{
		if ( strcmp(it.key, "event.tags") == 0 )
			{
			tags = it.val;
			}
		else
			{
			const char* param_val = json_object_get_string(it.val);
			vl->append(new StringVal(param_val));
			}
		}

	// Generate events for each tag
	int tags_len = json_object_array_length(tags);
	for ( int i = 0; i < tags_len; i++ )
		{
		json_object* tag = json_object_array_get_idx(tags, i);
		const char* evt_name = json_object_get_string(tag);

		EventHandlerPtr evt = event_registry->Lookup(evt_name);
		if ( ! evt )
			return false;

		mgr.QueueEvent(evt, vl);
		}

	return true;
	}

void LogNormalizer::GenerateEvent(const char* name)
	{
	printf("Hello Bro world!\n");

	EventHandlerPtr e = event_registry->Lookup(name);

	if ( e )
		{
		val_list* vl = new val_list;
		vl->append(new StringVal("Hello event world!"));

		mgr.QueueEvent(e, vl);
		}
	else
		{
		printf("Event not found!\n");
		}
	}