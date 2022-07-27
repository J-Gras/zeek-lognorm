
#include "LogNormalizer.h"
#include <broker/data.hh>
#include <zeek/Event.h>
#include <zeek/EventRegistry.h>

extern "C" {
#include <json.h>
}

using namespace plugin::Zeek_Lognorm;

static zeek::OpaqueTypePtr lognormalizer_type =
	zeek::make_intrusive<zeek::OpaqueType>("lognormalizer");

LogNormalizer::LogNormalizer(zeek::EventHandlerPtr evt_unparsed) : evt_unparsed(evt_unparsed)
	{
	ctx = ln_initCtx();
	}

LogNormalizer::~LogNormalizer()
	{
	ln_exitCtx(ctx);
	}

bool LogNormalizer::LoadRuleFile(const char* filename)
	{
	return ln_loadSamples(ctx, filename) == 0;
	}

bool LogNormalizer::LoadRuleFromString(const char* str)
	{
	return ln_loadSamplesFromString(ctx, str) == 0;
	}

bool LogNormalizer::Normalize(const char* line)
	{
	json_object* json = NULL;

	if ( ln_normalize(ctx, line, strlen(line), &json) != 0 )
		return false;

	// Raise an event for unparsed lines
	if ( json_object_object_get_ex(json, "unparsed-data", NULL) )
		{
		if ( evt_unparsed )
			{
			zeek::Args args;
			args.emplace_back(zeek::make_intrusive<zeek::StringVal>(line));
			zeek::event_mgr.Enqueue(evt_unparsed, std::move(args));
			}
		return false;
		}

	// Retrieve tags and parameters
	json_object* tags = NULL;
	FieldList fields;
	
	json_object_iterator it = json_object_iter_begin(json);
	json_object_iterator it_end = json_object_iter_end(json);
	while ( !json_object_iter_equal(&it, &it_end) )
		{
		const char* key = json_object_iter_peek_name(&it);
		json_object* val = json_object_iter_peek_value(&it);

		if ( strcmp(key, "event.tags") == 0 )
			tags = val;
		else
			fields[key] = ParseField(val);

		json_object_iter_next(&it);
		}

	// Generate events for each tag
	int tags_len = json_object_array_length(tags);
	for ( int i = 0; i < tags_len; i++ )
		{
		json_object* tag = json_object_array_get_idx(tags, i);
		const char* evt_name = json_object_get_string(tag);

		zeek::EventHandlerPtr evt = zeek::event_registry->Lookup(evt_name);
		if ( ! evt )
			{
			zeek::reporter->Warning("No handler found for event triggered by lognorm: %s", evt_name);
			continue;
			}

		// Create a separate parameter list for each event
		zeek::event_mgr.Enqueue(evt, BuildArgs(evt, fields));
		}

	//FIXME: Consume initial reference?
	//for ( auto &fld : fields )
	//	Unref(fld.second);

	json_object_put(json);
	return true;
	}

zeek::ValPtr LogNormalizer::ParseField(json_object* field)
	{
	zeek::ValPtr field_val = nullptr;
	int field_type = json_object_get_type(field);

	switch ( field_type ) {
	case json_type_boolean:
		field_val = zeek::val_mgr->Bool(json_object_get_boolean(field));
		break;
	case json_type_int:
		field_val = zeek::val_mgr->Int(json_object_get_int64(field));
		break;
	case json_type_double:
		field_val = zeek::make_intrusive<zeek::DoubleVal>(json_object_get_double(field));
		break;
	case json_type_string:
		field_val = zeek::make_intrusive<zeek::StringVal>(json_object_get_string(field));
		break;
	default:
		field_val = zeek::make_intrusive<zeek::StringVal>("Unsupported type: " + std::to_string(field_type));
	}

	return field_val;
	}

zeek::Args LogNormalizer::BuildArgs(zeek::EventHandlerPtr evt, const FieldList &fields)
	{
	zeek::Args args;
	zeek::RecordTypePtr evt_args = evt->GetType()->Params();

	for ( int i = 0; i < evt_args->NumFields(); i++ )
		{
		FieldList::const_iterator fld = fields.find(evt_args->FieldName(i));
		if ( fld != fields.end() )
			{
			if ( same_type(fld->second->GetType(), evt_args->GetFieldType(i)) )
				{
				args.emplace_back(fld->second);
				continue;
				}
			else
				{
				zeek::reporter->Error("Incompatible argument types for event and "
					"liblognorm rule. Expected %s(%s: %s)",
					evt->Name(), evt_args->FieldName(i),
					type_name(fld->second->GetType()->Tag()));
				}
			}
		else
			{
			zeek::reporter->Warning("Argument not defined by lognorm rule: %s(%s: %s)",
				evt->Name(), evt_args->FieldName(i),
				type_name(evt_args->GetFieldType(i)->Tag()));
			}
		//FIXME: This will blow up. Create value of requested type?
		args.emplace_back(zeek::val_mgr->Bool(false));
		}

	return args;
	}

LogNormalizerVal::LogNormalizerVal() : zeek::OpaqueVal(lognormalizer_type)
	{
	normalizer = nullptr;
	}

LogNormalizerVal::LogNormalizerVal(LogNormalizer* ln) : zeek::OpaqueVal(lognormalizer_type)
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

IMPLEMENT_OPAQUE_VALUE(LogNormalizerVal)

broker::expected<broker::data> LogNormalizerVal::DoSerialize() const
	{
	//TODO: Implement serialization.
	broker::vector d;
	return {std::move(d)};
	}

bool LogNormalizerVal::DoUnserialize(const broker::data& data)
	{
	//TODO: Implement serialization.
	return false;
	}
