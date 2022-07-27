// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ZEEK_PLUGIN_LOGNORM_LOGNORMALIZER_H
#define ZEEK_PLUGIN_LOGNORM_LOGNORMALIZER_H

#include <map>
#include <zeek/EventHandler.h>
#include <zeek/OpaqueVal.h>
#include <zeek/Val.h>

extern "C" {
#include <liblognorm.h>
}

namespace plugin::Zeek_Lognorm {


typedef std::map<std::string, zeek::ValPtr> FieldList;

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
	LogNormalizer(zeek::EventHandlerPtr evt_unparsed = NULL);
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
	bool LoadRuleFile(const char* filename);
	/**
	* Loads a liblognorm rule (v2 only) from string.
	*
	* @param str The rule string.
	*
	* @return `true` on success.
	*/
	bool LoadRuleFromString(const char* filename);
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
	zeek::EventHandlerPtr evt_unparsed;

	/**
	* Helper to parse a log field.
	*
	* @param field The field to parse.
	*
	* @return A value representing the field content.
	*/
	zeek::ValPtr ParseField(json_object* field);
	/**
	* Helper to generate a list of arguments for the given event.
	*
	* @param evt The event handler to prepare.
	*
	* @param fields The fields to pass to the event.
	*
	* @return A list of arguments for the given event handler.
	*/
	zeek::Args BuildArgs(zeek::EventHandlerPtr evt, const FieldList &fields);
};

//extern OpaqueType* lognormalizer_type;

/**
* This class defines an opaque value wrapping a LogNormalizer.
*/
class LogNormalizerVal : public zeek::OpaqueVal {
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
protected:
	LogNormalizerVal();
	DECLARE_OPAQUE_VALUE(LogNormalizerVal)
private:
	LogNormalizer* normalizer;
};

}

#endif