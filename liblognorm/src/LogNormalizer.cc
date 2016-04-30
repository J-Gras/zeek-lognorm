
#include "LogNormalizer.h"
#include <Event.h>
#include <EventRegistry.h>

extern "C" {
#include <json-c/json.h>
}

using namespace plugin::Bro_Lognorm;

static OpaqueType* lognormalizer_type = new OpaqueType("lognormalizer");

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
			{
			reporter->Warning("No handler found for event triggered by lognorm: %s", evt_name);
			continue;
			}

		// Create a separate parameter list for each event
		val_list* evt_vl = new val_list;
		loop_over_list(*vl, j)
			evt_vl->append((*vl)[j]->Ref());
		mgr.QueueEvent(evt, evt_vl);
		}

	// Consume initial reference
	loop_over_list(*vl, i)
		Unref((*vl)[i]);
	delete vl;

	json_object_put(json);
	return true;
	}

LogNormalizerVal::LogNormalizerVal(LogNormalizer* ln) : OpaqueVal(lognormalizer_type)
	{
	normalizer = ln;
	}

LogNormalizerVal::~LogNormalizerVal()
	{
	delete normalizer;
	}

LogNormalizer* LogNormalizerVal::GetNormalizer() const
	{
	return normalizer;
	}