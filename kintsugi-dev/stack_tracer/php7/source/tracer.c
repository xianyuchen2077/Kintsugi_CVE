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

/*
 * Tracing rules:
 *
 * On function entry, the recorded file/line is the call site.
 * On function return, the recorded file/line is where the return occurs (inside the callee).
 *
 * 1. FCALL: record if call_site_in_target || callee_in_target
 * 2. RETURN: record if returning_func_in_target || return_target_in_target
 *    This also captures returns from non-target functions called by target functions.
 */

static const zend_uchar target_opcodes[] = {
    ZEND_DO_FCALL,
    ZEND_DO_ICALL,
    ZEND_DO_UCALL,
    ZEND_DO_FCALL_BY_NAME,
    ZEND_RETURN,
    ZEND_RETURN_BY_REF,
};

#define TARGET_OPCODES_COUNT (sizeof(target_opcodes) / sizeof(target_opcodes[0]))
#define MAX_TRACE_BUFFER_SIZE 4096
#define MAX_NAME_DISPLAY_LENGTH 256
#define MAX_ARG_DISPLAY_LENGTH 1024

ZEND_DECLARE_MODULE_GLOBALS(tracer)

static user_opcode_handler_t original_handlers[256];
static int handlers_registered = 0;

static int devnull_fd = -1;

static inline int should_trace_file(const char *filename) {
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

static int is_internal_function(const char *function_name) {
    if (!function_name) {
        return 0;
    }

    zend_function *func_entry = NULL;
    zend_string *lcname = zend_string_tolower(zend_string_init(function_name, strlen(function_name), 0));

    func_entry = zend_hash_find_ptr(EG(function_table), lcname);
    zend_string_release(lcname);

    if (func_entry) {
        if (func_entry->type == ZEND_INTERNAL_FUNCTION) {
            return 1;
        }
        return 0;
    }
    return 0;
}

/* Format a zval for trace output. */
static void format_zval_for_trace(zval *val, char *buffer, size_t buffer_size) {
    if (!val || !buffer || buffer_size < 2) {
        return;
    }

    ZVAL_DEREF(val);

    switch (Z_TYPE_P(val)) {
        case IS_NULL:
            snprintf(buffer, buffer_size, "null");
            break;

        case IS_FALSE:
            snprintf(buffer, buffer_size, "false");
            break;

        case IS_TRUE:
            snprintf(buffer, buffer_size, "true");
            break;

        case IS_LONG:
            snprintf(buffer, buffer_size, "%ld", Z_LVAL_P(val));
            break;

        case IS_DOUBLE:
            snprintf(buffer, buffer_size, "%.6g", Z_DVAL_P(val));
            break;

       case IS_STRING: {
            zend_string *str = Z_STR_P(val);
            size_t str_len = ZSTR_LEN(str);
            const char *str_val = ZSTR_VAL(str);

            if (str_len == 0) {
                snprintf(buffer, buffer_size, "\"\"");
            } else {
                size_t copy_len = str_len < MAX_ARG_DISPLAY_LENGTH ? str_len : MAX_ARG_DISPLAY_LENGTH;
                if (str_len <= MAX_ARG_DISPLAY_LENGTH) {
                    snprintf(buffer, buffer_size, "\"%.*s\"", (int)copy_len, str_val);
                } else {
                    snprintf(buffer, buffer_size, "\"%.*s...\"", (int)copy_len, str_val);
                }
            }
            break;
        }

        case IS_ARRAY:
            snprintf(buffer, buffer_size, "Array(%d)", zend_array_count(Z_ARRVAL_P(val)));
            break;

        case IS_OBJECT: {
            zend_class_entry *ce = Z_OBJCE_P(val);
            if (ce && ce->name) {
                snprintf(buffer, buffer_size, "Object(%s)", ZSTR_VAL(ce->name));
            } else {
                snprintf(buffer, buffer_size, "Object(?)");
            }
            break;
        }

        case IS_RESOURCE: {
            zend_resource *res = Z_RES_P(val);
            snprintf(buffer, buffer_size, "Resource(#%d)", res->handle);
            break;
        }

        default:
            snprintf(buffer, buffer_size, "Unknown(%d)", Z_TYPE_P(val));
            break;
    }
}

/* Format function arguments into a parenthesized string. */
static void format_function_arguments(zend_execute_data *call_data, char *buffer, size_t buffer_size) {
    if (!call_data || !buffer) {
        return;
    }

    uint32_t arg_count = ZEND_CALL_NUM_ARGS(call_data);
    uint32_t i;

    if (arg_count == 0) {
        snprintf(buffer, buffer_size, "()");
        return;
    }

    char *current_pos = buffer;
    size_t remaining = buffer_size;
    int written = snprintf(current_pos, remaining, "(");

    if (written < 0 || written >= remaining)
        return;

    current_pos += written;
    remaining -= written;

    for (i = 1; i <= arg_count && remaining > 2; i++) {
        if (i > 1) {
            written = snprintf(current_pos, remaining, ", ");
            if (written < 0 || written >= remaining)
                break;
            current_pos += written;
            remaining -= written;
        }

        zval *arg = ZEND_CALL_ARG(call_data, i);
        if (arg) {
            char arg_buffer[MAX_ARG_DISPLAY_LENGTH];
            format_zval_for_trace(arg, arg_buffer, sizeof(arg_buffer));

            written = snprintf(current_pos, remaining, "%s", arg_buffer);
            if (written < 0 || written >= remaining)
                break;
            current_pos += written;
            remaining -= written;
        } else {
            written = snprintf(current_pos, remaining, "?");
            if (written < 0 || written >= remaining)
                break;
            current_pos += written;
            remaining -= written;
        }
    }

    if (remaining > 1) {
        snprintf(current_pos, remaining, ")");
    }
}

static const char* get_current_function_name_with_args(zend_execute_data *execute_data, zend_uchar opcode) {
    static char function_name_buffer[MAX_TRACE_BUFFER_SIZE];
    const char *function_name = NULL;
    zend_function *func = NULL;

    if (!execute_data) {
        return "unknown";
    }

    const zend_op *opline = execute_data->opline;

    if (opcode == ZEND_DO_FCALL || opcode == ZEND_DO_ICALL || opcode == ZEND_DO_UCALL || opcode == ZEND_DO_FCALL_BY_NAME) {
        if (execute_data->call && execute_data->call->func) {
            func = execute_data->call->func;
            if (func && func->common.function_name) {
                const char *type_prefix;
                if (func->type == ZEND_INTERNAL_FUNCTION) {
                    type_prefix = "[I]";
                } else {
                    type_prefix = "[U]";
                }

                const char *def_filename = NULL;
                uint32_t def_line_start = 0;
                uint32_t def_line_end = 0;

                if (func->type == ZEND_USER_FUNCTION) {
                    def_filename = ZSTR_VAL(func->op_array.filename);
                    def_line_start = func->op_array.line_start;
                    def_line_end = func->op_array.line_end;
                }

                char base_name[MAX_NAME_DISPLAY_LENGTH];
                if (func->common.scope && func->common.scope->name) {
                    snprintf(base_name, sizeof(base_name),
                            "%s%s::%s",
                            type_prefix,
                            ZSTR_VAL(func->common.scope->name),
                            ZSTR_VAL(func->common.function_name));
                } else {
                    snprintf(base_name, sizeof(base_name),
                            "%s%s",
                            type_prefix,
                            ZSTR_VAL(func->common.function_name));
                }

                char name_with_def[MAX_NAME_DISPLAY_LENGTH + 512];
                if (def_filename && def_line_start > 0) {
                    snprintf(name_with_def, sizeof(name_with_def),
                            "%s[DEF:%s:%u-%u]",
                            base_name, def_filename, def_line_start, def_line_end);
                } else {
                    snprintf(name_with_def, sizeof(name_with_def), "%s", base_name);
                }

                if (TRACER_G(capture_args)) {
                    char args_buffer[MAX_ARG_DISPLAY_LENGTH];
                    format_function_arguments(execute_data->call, args_buffer, sizeof(args_buffer));
                    snprintf(function_name_buffer, sizeof(function_name_buffer),
                            "%s%s", name_with_def, args_buffer);
                } else {
                    snprintf(function_name_buffer, sizeof(function_name_buffer), "%s", name_with_def);
                }

                return function_name_buffer;
            }
        }
    }
    else if (opcode == ZEND_RETURN || opcode == ZEND_RETURN_BY_REF) {
        if (execute_data->func) {
            func = execute_data->func;
            if (func && func->common.function_name) {
                const char *def_filename = NULL;
                uint32_t def_line_start = 0;
                uint32_t def_line_end = 0;

                if (func->type == ZEND_USER_FUNCTION) {
                    def_filename = ZSTR_VAL(func->op_array.filename);
                    def_line_start = func->op_array.line_start;
                    def_line_end = func->op_array.line_end;
                }

                if (func->common.scope && func->common.scope->name) {
                    if (def_filename && def_line_start > 0) {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s::%s[DEF:%s:%u-%u]",
                                ZSTR_VAL(func->common.scope->name),
                                ZSTR_VAL(func->common.function_name),
                                def_filename,
                                def_line_start,
                                def_line_end);
                    } else {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s::%s",
                                ZSTR_VAL(func->common.scope->name),
                                ZSTR_VAL(func->common.function_name));
                    }
                } else {
                    if (def_filename && def_line_start > 0) {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s[DEF:%s:%u-%u]",
                                ZSTR_VAL(func->common.function_name),
                                def_filename,
                                def_line_start,
                                def_line_end);
                    } else {
                        snprintf(function_name_buffer, sizeof(function_name_buffer),
                                "[U]%s",
                                ZSTR_VAL(func->common.function_name));
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
        case ZEND_DO_FCALL:         return "FCALL";
        case ZEND_DO_ICALL:         return "ICALL";
        case ZEND_DO_UCALL:         return "UCALL";
        case ZEND_DO_FCALL_BY_NAME: return "FCALL_BY_NAME";
        case ZEND_RETURN:           return "RETURN";
        case ZEND_RETURN_BY_REF:    return "RETURN_BY_REF";
        default:                    return "UNKNOWN";
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

/*
 * Send a trace record via write() syscall to /dev/null.
 *
 * Output format examples:
 *   [FCALL][/var/www/html/src/Foo.php:42][U]Bar::baz("arg1", 123)
 *   [RETURN][/var/www/html/src/Foo.php:50][U]Bar::baz[DEF:/var/www/html/src/Foo.php:40-51]
 */
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

/* Opcode handler: checks both call site and definition site. */
static int tracer_opcode_handler(zend_execute_data *execute_data) {
    if (TRACER_G(enabled)) {
        const zend_op *opline = execute_data->opline;

        if (opline && opline->lineno > 0) {
            int should_record = 0;
            const char *record_filename = NULL;

            if (opline->opcode == ZEND_RETURN || opline->opcode == ZEND_RETURN_BY_REF) {
                /* Handle function return */
                const char *returning_func_filename = NULL;
                int returning_func_in_target = 0;
                int return_target_in_target = 0;

                if (execute_data->func && execute_data->func->type == ZEND_USER_FUNCTION) {
                    returning_func_filename = ZSTR_VAL(execute_data->func->op_array.filename);
                    returning_func_in_target = should_trace_file(returning_func_filename);
                }

                zend_execute_data *prev = execute_data->prev_execute_data;
                if (prev && prev->func && prev->func->type == ZEND_USER_FUNCTION &&
                    prev->func->op_array.filename) {
                    const char *prev_filename = ZSTR_VAL(prev->func->op_array.filename);
                    if (prev_filename) {
                        return_target_in_target = should_trace_file(prev_filename);
                    }
                }

                if (returning_func_in_target || return_target_in_target) {
                    should_record = 1;
                    record_filename = returning_func_filename;
                }

            } else if (opline->opcode == ZEND_DO_FCALL || opline->opcode == ZEND_DO_ICALL ||
                       opline->opcode == ZEND_DO_UCALL || opline->opcode == ZEND_DO_FCALL_BY_NAME) {
                /* Handle function call */
                const char *call_site_filename = NULL;
                const char *callee_def_filename = NULL;
                int call_site_in_target = 0;
                int callee_in_target = 0;

                if (execute_data->func && execute_data->func->type == ZEND_USER_FUNCTION) {
                    call_site_filename = ZSTR_VAL(execute_data->func->op_array.filename);
                    call_site_in_target = should_trace_file(call_site_filename);
                }

                if (execute_data->call && execute_data->call->func &&
                    execute_data->call->func->type == ZEND_USER_FUNCTION) {
                    callee_def_filename = ZSTR_VAL(execute_data->call->func->op_array.filename);
                    callee_in_target = should_trace_file(callee_def_filename);
                }

                if (call_site_in_target || callee_in_target) {
                    should_record = 1;
                    record_filename = call_site_filename;
                }
            }

            if (should_record && record_filename) {
                const char *function_name = get_current_function_name_with_args(execute_data, opline->opcode);
                send_trace_record(record_filename, opline->lineno, function_name, opline->opcode);
            }
        }
    }

    const zend_op *opline = execute_data->opline;
    if (opline && original_handlers[opline->opcode]) {
        return original_handlers[opline->opcode](execute_data);
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

PHP_FUNCTION(tracer_enable_args) {
    TRACER_G(capture_args) = 1;
    RETURN_TRUE;
}

PHP_FUNCTION(tracer_disable_args) {
    TRACER_G(capture_args) = 0;
    RETURN_TRUE;
}

PHP_FUNCTION(tracer_status) {
    array_init(return_value);
    add_assoc_bool(return_value, "enabled", TRACER_G(enabled));
    add_assoc_bool(return_value, "capture_args", TRACER_G(capture_args));
    add_assoc_bool(return_value, "handlers_registered", handlers_registered);
    add_assoc_bool(return_value, "devnull_open", devnull_fd >= 0);
    add_assoc_long(return_value, "devnull_fd", devnull_fd);

    add_assoc_string(return_value, "trace_method", "write_to_devnull");
    add_assoc_long(return_value, "registered_opcodes", TARGET_OPCODES_COUNT);
    add_assoc_string(return_value, "syscall", "write");
    add_assoc_long(return_value, "syscall_number", SYS_write);
    add_assoc_string(return_value, "target_file", "/dev/null");
    add_assoc_string(return_value, "format", "[OPCODE][FILE:LINE] function_name(args)");
}

ZEND_BEGIN_ARG_INFO(arginfo_tracer_enable, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_tracer_disable, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_tracer_enable_args, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_tracer_disable_args, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_tracer_status, 0)
ZEND_END_ARG_INFO()

const zend_function_entry tracer_functions[] = {
    PHP_FE(tracer_enable, arginfo_tracer_enable)
    PHP_FE(tracer_disable, arginfo_tracer_disable)
    PHP_FE(tracer_enable_args, arginfo_tracer_enable_args)
    PHP_FE(tracer_disable_args, arginfo_tracer_disable_args)
    PHP_FE(tracer_status, arginfo_tracer_status)
    PHP_FE_END
};

PHP_INI_BEGIN()
    STD_PHP_INI_BOOLEAN("tracer.enabled", "0", PHP_INI_ALL, OnUpdateBool, enabled, zend_tracer_globals, tracer_globals)
    STD_PHP_INI_BOOLEAN("tracer.capture_args", "0", PHP_INI_ALL, OnUpdateBool, capture_args, zend_tracer_globals, tracer_globals)
    STD_PHP_INI_ENTRY("tracer.project_root", "", PHP_INI_ALL, OnUpdateString, project_root, zend_tracer_globals, tracer_globals)
PHP_INI_END()

static void php_tracer_init_globals(zend_tracer_globals *tracer_globals) {
    tracer_globals->enabled = 0;
    tracer_globals->capture_args = 0;
    tracer_globals->project_root = NULL;
}

PHP_MINIT_FUNCTION(tracer) {
    ZEND_INIT_MODULE_GLOBALS(tracer, php_tracer_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    memset(original_handlers, 0, sizeof(original_handlers));
    handlers_registered = 0;
    devnull_fd = -1;

    if (TRACER_G(enabled)) {
        TRACER_G(capture_args) = 1;
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
    php_info_print_table_row(2, "Argument Capture", TRACER_G(capture_args) ? "enabled" : "disabled");
    php_info_print_table_row(2, "Handlers Registered", handlers_registered ? "yes" : "no");
    php_info_print_table_row(2, "Function Name Tracking", "enabled");

    char fd_info[32];
    if (devnull_fd >= 0) {
        sprintf(fd_info, "%d (open)", devnull_fd);
    } else {
        sprintf(fd_info, "closed");
    }
    php_info_print_table_row(2, "/dev/null FD", fd_info);

    char opcodes_info[64];
    sprintf(opcodes_info, "%d (FCALL,ICALL,UCALL,FCALL_BY_NAME,RETURN,RETURN_BY_REF)", TARGET_OPCODES_COUNT);
    php_info_print_table_row(2, "Registered OpCodes", opcodes_info);

    char syscall_info[32];
    sprintf(syscall_info, "%d", SYS_write);
    php_info_print_table_row(2, "Syscall Number", syscall_info);

    php_info_print_table_row(2, "Trace Format", "[OPCODE][FILE:LINE] function_name(args)");
    php_info_print_table_row(2, "Argument Types", "Basic types + simplified complex types");
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
