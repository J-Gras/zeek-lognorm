// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_PLUGIN_LOGNORM_LOGNORMALIZER_H
#define BRO_PLUGIN_LOGNORM_LOGNORMALIZER_H

#include <Val.h>
#include <EventRegistry.h>

extern "C" {
#include <liblognorm.h>
}

namespace plugin {
namespace Bro_Lognorm {


typedef std::map<string, Val*> FieldList;

/**
* This class provides an interface to a liblognorm context.
*/
class LogNormalizer {
public:
	/**
	* Construct a LogNormalizer.
	*
	* @param evt_unparsed Event that is raised for unparsed log lines.
	*
	* @return A new LogNormalizer.
	*/
	LogNormalizer(EventHandlerPtr evt_unparsed = NULL);
	/**
	* Destructor.
	*/
	virtual ~LogNormalizer();

	/**
	* Loads a rule file in liblognorm format.
	*
	* @param filename The rule file name.
	*
	* @return `true` on success.
	*/
	bool LoadRules(const char* filename);
	/**
	* Executes log normalization for the given line by scheduling
	* events based on the rule's tags.
	*
	* @param line The log line to parse.
	*
	* @return `true` on success.
	*/
	bool Normalize(const char* line);
protected:
	ln_ctx ctx;
	EventHandlerPtr evt_unparsed;

	/**
	* Helper to parse a log field.
	*
	* @param field The field to parse.
	*
	* @return A value representing the field content.
	*/
	Val* ParseField(json_object* field);
	/**
	* Helper to generate a list of arguments for the given event.
	*
	* @param evt The event handler to prepare.
	*
	* @param fields The fields to pass to the event.
	*
	* @return A value list of arguments for the given event handler.
	*/
	val_list* BuildArgs(EventHandlerPtr evt, const FieldList &fields);
};

//extern OpaqueType* lognormalizer_type;

/**
* This class defines an opaque value wrapping a LogNormalizer.
*/
class LogNormalizerVal : public OpaqueVal {
public:
	/**
	* Construct a LogNormalizerVal.
	*
	* @param ln The wrapped LogNormalizer instance.
	*
	* @return A new LogNormalizerVal.
	*/
	explicit LogNormalizerVal(LogNormalizer* ln);
	/**
	* Destructor.
	*/
	~LogNormalizerVal();
	/**
	* Returns the wrapped LogNormalizer.
	*
	* @return The wrapped LogNormalizer.
	*/
	LogNormalizer* GetNormalizer() const;
private:
	LogNormalizer* normalizer;
};

}
}

#endif