#ifndef PHP_TRACER_H
#define PHP_TRACER_H

extern zend_module_entry tracer_module_entry;
#define phpext_tracer_ptr &tracer_module_entry

#define PHP_TRACER_VERSION "2.0.0"

#ifdef PHP_WIN32
#	define PHP_TRACER_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_TRACER_API __attribute__ ((visibility("default")))
#else
#	define PHP_TRACER_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(tracer)
    zend_bool enabled;
    zend_bool capture_args;
    char *project_root;
ZEND_END_MODULE_GLOBALS(tracer)

#ifdef ZTS
#define TRACER_G(v) TSRMG(tracer_globals_id, zend_tracer_globals *, v)
extern int tracer_globals_id;
#else
#define TRACER_G(v) (tracer_globals.v)
extern zend_tracer_globals tracer_globals;
#endif

PHP_MINIT_FUNCTION(tracer);
PHP_MSHUTDOWN_FUNCTION(tracer);
PHP_RINIT_FUNCTION(tracer);
PHP_RSHUTDOWN_FUNCTION(tracer);
PHP_MINFO_FUNCTION(tracer);

PHP_FUNCTION(tracer_enable);
PHP_FUNCTION(tracer_disable);
PHP_FUNCTION(tracer_enable_args);
PHP_FUNCTION(tracer_disable_args);
PHP_FUNCTION(tracer_status);

#endif	/* PHP_TRACER_H */
