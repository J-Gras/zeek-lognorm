// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_PLUGIN_LOGNORM_LOGNORMALIZER_H
#define BRO_PLUGIN_LOGNORM_LOGNORMALIZER_H

#include <Val.h>

extern "C" {
#include <liblognorm.h>
}

namespace plugin {
namespace Bro_Lognorm {

/**
* This class provides an interface to a liblognorm context.
*/
class LogNormalizer {
public:
	/**
	* Construct a LogNormalizer.
	*
	* @return A new LogNormalizer.
	*/
	LogNormalizer();
	/**
	* Destructor.
	*/
	virtual ~LogNormalizer();

	/**
	* Loads a rule file in liblognorm format.
	*
	* @param The rule file name.
	*
	* @return `true` on success.
	*/
	bool LoadRules(const char* filename);
	/**
	* Executes log normalization for the given line by scheduling
	* events based on the rule's tags.
	*
	* @param The log line to parse.
	*
	* @return `true` on success.
	*/
	bool Normalize(const char* line);
protected:
	ln_ctx ctx;
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