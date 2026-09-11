#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "zend_vm_opcodes.h"
#include "ext/standard/info.h"
#include "php_tracer.h"

#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Tracing rules:
 *
 * On function entry, the recorded file/line is the call site.
 * On function return, the recorded file/line is where the return occurs.
 *
 * 1. FCALL: record if call_site_in_target || callee_in_target
 * 2. RETURN: record if returning_func_in_target || return_target_in_target
 *    This also captures returns from non-target functions called by target functions.
 */

static const zend_uchar target_opcodes[] = {
    ZEND_DO_FCALL,
    ZEND_DO_FCALL_BY_NAME,
    ZEND_RETURN,
#if PHP_VERSION_ID >= 50400
    ZEND_RETURN_BY_REF,
#endif
};

#define TARGET_OPCODES_COUNT (sizeof(target_opcodes) / sizeof(target_opcodes[0]))
#define MAX_TRACE_BUFFER_SIZE 1024

ZEND_DECLARE_MODULE_GLOBALS(tracer)

static user_opcode_handler_t original_handlers[256];
static int handlers_registered = 0;

static int devnull_fd = -1;

static inline int should_trace_file(const char *filename TSRMLS_DC) {
    if (!filename) {
        return 0;
    }

    const char *project_root = TRACER_G(project_root);
    if (!project_root || project_root[0] == '\0') {
        return 1;
    }

    size_t root_len = strlen(project_root);
    if (strncmp(filename, project_root, root_len) == 0) {
        return 1;
    }

    return 0;
}

static inline int is_target_opcode(zend_uchar opcode) {
    int i;
    for (i = 0; i < TARGET_OPCODES_COUNT; i++) {
        if (target_opcodes[i] == opcode) {
            return 1;
        }
    }
    return 0;
}

static int is_internal_function(const char *function_name TSRMLS_DC) {
    if (!function_name) {
        return 0;
    }

    zend_function *func_entry = NULL;
    char *lcname = zend_str_tolower_dup(function_name, strlen(function_name));

    if (zend_hash_find(EG(function_table), lcname, strlen(lcname) + 1,
                      (void **) &func_entry) == SUCCESS) {
        efree(lcname);
        if (func_entry && func_entry->type == ZEND_INTERNAL_FUNCTION) {
            return 1;
        }
        return 0;
    }

    efree(lcname);
    return 0;
}

/* Get current function name.
   Note: yield, exception, and exit are not handled. */
static const char* get_current_function_name(zend_execute_data *execute_data, zend_uchar opcode TSRMLS_DC) {
    static char function_name_buffer[1024];
    const char *function_name = NULL;
    zend_function *func = NULL;

    if (!execute_data) {
        return "unknown";
    }

    zend_op *opline = execute_data->opline;

    if (opcode == ZEND_DO_FCALL) {
        #if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
        # define OP1_CONSTANT_PTR(n) (&(n)->op1.u.constant)
        #else
        # define OP1_CONSTANT_PTR(n) ((n)->op1.zv)
        #endif

        zval *fname = OP1_CONSTANT_PTR(opline);
        if (fname && Z_TYPE_P(fname) == IS_STRING && Z_STRVAL_P(fname)) {
            function_name = Z_STRVAL_P(fname);

            const char *def_filename = NULL;
            uint32_t def_line_start = 0;
            uint32_t def_line_end = 0;

            zend_function *func_entry = NULL;
            char *lcname = zend_str_tolower_dup(function_name, strlen(function_name));
            if (zend_hash_find(EG(function_table), lcname, strlen(lcname) + 1,
                              (void **) &func_entry) == SUCCESS) {
                if (func_entry && func_entry->type == ZEND_USER_FUNCTION) {
                    def_filename = func_entry->op_array.filename;
                    def_line_start = func_entry->op_array.line_start;
                    def_line_end = func_entry->op_array.line_end;
                }
            }
            efree(lcname);

            const char *type_prefix = is_internal_function(function_name TSRMLS_CC) ? "[I]" : "[U]";

            if (def_filename && def_line_start > 0) {
                snprintf(function_name_buffer, sizeof(function_name_buffer),
                        "%s%s[DEF:%s:%u-%u]",
                        type_prefix, function_name, def_filename, def_line_start, def_line_end);
            } else {
                snprintf(function_name_buffer, sizeof(function_name_buffer),
                        "%s%s", type_prefix, function_name);
            }
            return function_name_buffer;
        }
    }
    else if (opcode == ZEND_DO_FCALL_BY_NAME) {
#if PHP_VERSION_ID >= 50400
        if (execute_data->call && execute_data->call->fbc) {
            func = execute_data->call->fbc;
#else
        if (execute_data->fbc) {
            func = execute_data->fbc;
#endif
            if (func && func->common.function_name) {
                const char *type_prefix = (func->type == ZEND_INTERNAL_FUNCTION) ? "[I]" : "[U]";

                const char *def_filename = NULL;
                uint32_t def_line_start = 0;
                uint32_t def_line_end = 0;

                if (func->type == ZEND_USER_FUNCTION) {
                    def_filename = func->op_array.filename;
                    def_line_start = func->op_array.line_start;
                    def_line_end = func->op_array.line_end;
                }

                if (func->common.scope && func->common.scope->name) {
                    if (def_filename && def_line_start > 0) {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "%s%s::%s[DEF:%s:%u-%u]",
                                type_prefix,
                                func->common.scope->name,
                                func->common.function_name,
                                def_filename, def_line_start, def_line_end);
                    } else {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "%s%s::%s",
                                type_prefix,
                                func->common.scope->name,
                                func->common.function_name);
                    }
                } else {
                    if (def_filename && def_line_start > 0) {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "%s%s[DEF:%s:%u-%u]",
                                type_prefix, func->common.function_name,
                                def_filename, def_line_start, def_line_end);
                    } else {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "%s%s",
                                type_prefix,
                                func->common.function_name);
                    }
                }
                return function_name_buffer;
            }
        }
    }
#if PHP_VERSION_ID >= 50400
    else if (opcode == ZEND_RETURN || opcode == ZEND_RETURN_BY_REF) {
#else
    else if (opcode == ZEND_RETURN) {
#endif
        if (execute_data->function_state.function) {
            func = execute_data->function_state.function;
            if (func && func->common.function_name) {
                const char *def_filename = NULL;
                uint32_t def_line_start = 0;
                uint32_t def_line_end = 0;

                if (func->type == ZEND_USER_FUNCTION) {
                    def_filename = func->op_array.filename;
                    def_line_start = func->op_array.line_start;
                    def_line_end = func->op_array.line_end;
                }

                if (func->common.scope && func->common.scope->name) {
                    if (def_filename && def_line_start > 0) {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s::%s[DEF:%s:%u-%u]",
                                func->common.scope->name,
                                func->common.function_name,
                                def_filename,
                                def_line_start,
                                def_line_end);
                    } else {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s::%s",
                                func->common.scope->name,
                                func->common.function_name);
                    }
                } else {
                    if (def_filename && def_line_start > 0) {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s[DEF:%s:%u-%u]",
                                func->common.function_name,
                                def_filename,
                                def_line_start,
                                def_line_end);
                    } else {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s",
                                func->common.function_name);
                    }
                }
                return function_name_buffer;
            }
        }
    }

    return "main";
}

static const char* get_opcode_name(zend_uchar opcode) {
    switch (opcode) {
        case ZEND_DO_FCALL:  return "FCALL";
        case ZEND_DO_FCALL_BY_NAME:  return "FCALL_BY_NAME";
        case ZEND_RETURN:  return "RETURN";
#if PHP_VERSION_ID >= 50400
        case ZEND_RETURN_BY_REF: return "RETURN_BY_REF";
#endif
        default:  return "UNKNOWN";
    }
}

static void ensure_devnull_open() {
    if (devnull_fd < 0) {
        devnull_fd = open("/dev/null", O_WRONLY);
        if (devnull_fd < 0) {
            devnull_fd = 2; // fallback to stderr
        }
    }
}

/* Send a trace record via write() syscall to /dev/null. */
static void send_trace_record(const char *filename, uint32_t lineno,
                             const char *function_name, zend_uchar opcode) {
    char trace_buffer[MAX_TRACE_BUFFER_SIZE];
    int len;

    ensure_devnull_open();

    len = snprintf(trace_buffer, sizeof(trace_buffer),
                   "[%s][%s:%u]%s\n",
                   get_opcode_name(opcode),
                   filename,
                   lineno,
                   function_name);

    if (len >= sizeof(trace_buffer)) {
        len = sizeof(trace_buffer) - 1;
    }
    if (len > 0) {
        syscall(SYS_write, devnull_fd, trace_buffer, len);
    }
}

/* Opcode handler for PHP 5: checks both call site and definition site. */
static int tracer_opcode_handler(zend_execute_data *execute_data TSRMLS_DC) {
    if (TRACER_G(enabled)) {
        zend_op *opline = execute_data->opline;

        if (opline && opline->lineno > 0) {
            int should_record = 0;
            const char *record_filename = NULL;

#if PHP_VERSION_ID >= 50400
            if (opline->opcode == ZEND_RETURN || opline->opcode == ZEND_RETURN_BY_REF) {
#else
            if (opline->opcode == ZEND_RETURN) {
#endif
                // Handle function return
                const char *returning_func_filename = NULL;
                int returning_func_in_target = 0;
                int return_target_in_target = 0;

                if (EG(active_op_array) && EG(active_op_array)->filename) {
                    returning_func_filename = EG(active_op_array)->filename;
                    returning_func_in_target = should_trace_file(returning_func_filename TSRMLS_CC);
                }
                else if (CG(active_op_array) && CG(active_op_array)->filename) {
                    returning_func_filename = CG(active_op_array)->filename;
                    returning_func_in_target = should_trace_file(returning_func_filename TSRMLS_CC);
                }

                zend_execute_data *prev = execute_data->prev_execute_data;
                if (prev && prev->op_array && prev->op_array->filename) {
                    return_target_in_target = should_trace_file(prev->op_array->filename TSRMLS_CC);
                }

                if (returning_func_in_target || return_target_in_target) {
                    should_record = 1;
                    record_filename = returning_func_filename;
                }

            } else if (opline->opcode == ZEND_DO_FCALL || opline->opcode == ZEND_DO_FCALL_BY_NAME) {
                // Handle function call
                const char *call_site_filename = NULL;
                const char *callee_def_filename = NULL;
                int call_site_in_target = 0;
                int callee_in_target = 0;

                if (EG(active_op_array) && EG(active_op_array)->filename) {
                    call_site_filename = EG(active_op_array)->filename;
                    call_site_in_target = should_trace_file(call_site_filename TSRMLS_CC);
                }
                else if (CG(active_op_array) && CG(active_op_array)->filename) {
                    call_site_filename = CG(active_op_array)->filename;
                    call_site_in_target = should_trace_file(call_site_filename TSRMLS_CC);
                }

                zend_function *func = NULL;
                if (opline->opcode == ZEND_DO_FCALL_BY_NAME) {
#if PHP_VERSION_ID >= 50400
                    if (execute_data->call && execute_data->call->fbc) {
                        func = execute_data->call->fbc;
#else
                    if (execute_data->fbc) {
                        func = execute_data->fbc;
#endif
                    }
                } else {  // ZEND_DO_FCALL
#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
# define OP1_CONSTANT_PTR(n) (&(n)->op1.u.constant)
#else
# define OP1_CONSTANT_PTR(n) ((n)->op1.zv)
#endif
                    zval *fname = OP1_CONSTANT_PTR(opline);
                    if (fname && Z_TYPE_P(fname) == IS_STRING && Z_STRVAL_P(fname)) {
                        const char *function_name = Z_STRVAL_P(fname);
                        char *lcname = zend_str_tolower_dup(function_name, strlen(function_name));
                        if (zend_hash_find(EG(function_table), lcname, strlen(lcname) + 1,
                                          (void **) &func) != SUCCESS) {
                            func = NULL;
                        }
                        efree(lcname);
                    }
                }

                if (func && func->type == ZEND_USER_FUNCTION && func->op_array.filename) {
                    callee_def_filename = func->op_array.filename;
                    callee_in_target = should_trace_file(callee_def_filename TSRMLS_CC);
                }

                if (call_site_in_target || callee_in_target) {
                    should_record = 1;
                    record_filename = call_site_filename;
                }
            }

            if (should_record && record_filename) {
                const char *function_name = get_current_function_name(execute_data, opline->opcode TSRMLS_CC);
                send_trace_record(record_filename, opline->lineno, function_name, opline->opcode);
            }
        }
    }

    zend_op *opline = execute_data->opline;
    if (opline && original_handlers[opline->opcode]) {
        return original_handlers[opline->opcode](execute_data TSRMLS_CC);
    }

    return ZEND_USER_OPCODE_DISPATCH;
}

static void register_opcode_handlers() {
    int i;

    if (handlers_registered) {
        return;
    }

    for (i = 0; i < TARGET_OPCODES_COUNT; i++) {
        zend_uchar opcode = target_opcodes[i];
        original_handlers[opcode] = zend_get_user_opcode_handler(opcode);
        zend_set_user_opcode_handler(opcode, tracer_opcode_handler);
    }

    handlers_registered = 1;
}

static void restore_opcode_handlers() {
    int i;

    if (!handlers_registered) {
        return;
    }

    for (i = 0; i < TARGET_OPCODES_COUNT; i++) {
        zend_uchar opcode = target_opcodes[i];

        if (original_handlers[opcode]) {
            zend_set_user_opcode_handler(opcode, original_handlers[opcode]);
        } else {
            zend_set_user_opcode_handler(opcode, NULL);
        }
        original_handlers[opcode] = NULL;
    }

    handlers_registered = 0;
}

static void close_devnull() {
    if (devnull_fd >= 0 && devnull_fd != 2) {
        close(devnull_fd);
        devnull_fd = -1;
    }
}

PHP_FUNCTION(tracer_enable) {
    TRACER_G(enabled) = 1;
    register_opcode_handlers();
    ensure_devnull_open();
    RETURN_TRUE;
}

PHP_FUNCTION(tracer_disable) {
    TRACER_G(enabled) = 0;
    restore_opcode_handlers();
    close_devnull();
    RETURN_TRUE;
}

PHP_FUNCTION(tracer_status) {
    array_init(return_value);
    add_assoc_bool(return_value, "enabled", TRACER_G(enabled));
    add_assoc_bool(return_value, "handlers_registered", handlers_registered);
    add_assoc_bool(return_value, "devnull_open", devnull_fd >= 0);
    add_assoc_long(return_value, "devnull_fd", devnull_fd);

    add_assoc_string(return_value, "trace_method", "write_to_devnull", 1);
    add_assoc_long(return_value, "registered_opcodes", TARGET_OPCODES_COUNT);
    add_assoc_string(return_value, "syscall", "write", 1);
    add_assoc_long(return_value, "syscall_number", SYS_write);
    add_assoc_string(return_value, "target_file", "/dev/null", 1);
    add_assoc_string(return_value, "format", "[OPCODE][FILE:LINE] function_name", 1);
}

ZEND_BEGIN_ARG_INFO(arginfo_tracer_enable, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_tracer_disable, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_tracer_status, 0)
ZEND_END_ARG_INFO()

const zend_function_entry tracer_functions[] = {
    PHP_FE(tracer_enable, arginfo_tracer_enable)
    PHP_FE(tracer_disable, arginfo_tracer_disable)
    PHP_FE(tracer_status, arginfo_tracer_status)
    {NULL, NULL, NULL}
};

PHP_INI_BEGIN()
    STD_PHP_INI_BOOLEAN("tracer.enabled", "0", PHP_INI_ALL, OnUpdateBool, enabled, zend_tracer_globals, tracer_globals)
    STD_PHP_INI_ENTRY("tracer.project_root", "", PHP_INI_ALL, OnUpdateString, project_root, zend_tracer_globals, tracer_globals)
PHP_INI_END()

static void php_tracer_init_globals(zend_tracer_globals *tracer_globals) {
    tracer_globals->enabled = 0;
    tracer_globals->project_root = NULL;
}

PHP_MINIT_FUNCTION(tracer) {
    ZEND_INIT_MODULE_GLOBALS(tracer, php_tracer_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    memset(original_handlers, 0, sizeof(original_handlers));
    handlers_registered = 0;
    devnull_fd = -1;

    if (TRACER_G(enabled)) {
        register_opcode_handlers();
        ensure_devnull_open();
    }

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(tracer) {
    restore_opcode_handlers();
    close_devnull();
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_RINIT_FUNCTION(tracer) {
    ensure_devnull_open();
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(tracer) {
    return SUCCESS;
}

PHP_MINFO_FUNCTION(tracer) {
    php_info_print_table_start();
    php_info_print_table_header(2, "tracer support", "enabled");
    php_info_print_table_row(2, "Version", PHP_TRACER_VERSION);
    php_info_print_table_row(2, "Trace Method", "write() to /dev/null");
    php_info_print_table_row(2, "System Call", "write");
    php_info_print_table_row(2, "Target File", "/dev/null");
    php_info_print_table_row(2, "Trace Status", TRACER_G(enabled) ? "enabled" : "disabled");
    php_info_print_table_row(2, "Handlers Registered", handlers_registered ? "yes" : "no");
    php_info_print_table_row(2, "Function Name Tracking", "enabled");

    char fd_info[32];
    if (devnull_fd >= 0) {
        sprintf(fd_info, "%d (open)", devnull_fd);
    } else {
        sprintf(fd_info, "closed");
    }
    php_info_print_table_row(2, "/dev/null FD", fd_info);

    char opcodes_info[32];
    sprintf(opcodes_info, "%d", TARGET_OPCODES_COUNT);
    php_info_print_table_row(2, "Registered OpCodes", opcodes_info);

    char syscall_info[32];
    sprintf(syscall_info, "%d", SYS_write);
    php_info_print_table_row(2, "Syscall Number", syscall_info);

    php_info_print_table_row(2, "Trace Format", "[OPCODE][FILE:LINE] function_name");
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

zend_module_entry tracer_module_entry = {
    STANDARD_MODULE_HEADER,
    "tracer",
    tracer_functions,
    PHP_MINIT(tracer),
    PHP_MSHUTDOWN(tracer),
    PHP_RINIT(tracer),
    PHP_RSHUTDOWN(tracer),
    PHP_MINFO(tracer),
    PHP_TRACER_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_TRACER
ZEND_GET_MODULE(tracer)
#endif
