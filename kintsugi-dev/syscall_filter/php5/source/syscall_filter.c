/*
 * syscall_filter.c - PHP Extension for eBPF Syscall Filtering
 *
 * 支持路径参数白名单的系统调用过滤 (批量传输协议)
 *
 * PHP API (统一关联数组语法):
 *   syscall_filter_begin([
 *       'read' => [],                // 无路径约束（空数组）
 *       'openat' => ['/etc/', '/tmp/'],  // 带路径白名单
 *   ])
 *   syscall_filter_end([...])
 *
 * 新协议: 单次prctl发送所有规则(哈希+长度格式)
 *
 * PHP5 适配说明:
 * - 使用 zend_parse_parameters() 而非 ZEND_PARSE_PARAMETERS_START
 * - 使用 zval** 双指针而非 zval* 单指针
 * - 使用 Z_*_PP() 宏而非 Z_*_P() 宏
 * - 使用 zend_hash_*_ex() 手动遍历而非 ZEND_HASH_FOREACH_* 宏
 * - 所有 Zend API 调用添加 TSRMLS_CC
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"

#include <sys/prctl.h>
#include <string.h>
#include <stdio.h>

#include "syscall_filter.h"

#define PHP_SYSCALL_FILTER_VERSION "4.0.0"
#define PHP_SYSCALL_FILTER_EXTNAME "syscall_filter"

/* Module entry forward declaration */
zend_module_entry syscall_filter_module_entry;

#ifdef COMPILE_DL_SYSCALL_FILTER
ZEND_GET_MODULE(syscall_filter)
#endif

/* ======================================== Syscall Table ======================================== */

typedef struct {
    const char *name;
    int nr;
} syscall_entry_t;

static const syscall_entry_t SYSCALL_TABLE[] = {
    {"read", 0}, {"write", 1}, {"open", 2}, {"close", 3}, {"stat", 4}, {"fstat", 5}, {"lstat", 6}, {"poll", 7},
    {"lseek", 8}, {"mmap", 9}, {"mprotect", 10}, {"munmap", 11}, {"brk", 12}, {"rt_sigaction", 13}, {"rt_sigprocmask", 14}, {"rt_sigreturn", 15},
    {"ioctl", 16}, {"pread64", 17}, {"pwrite64", 18}, {"readv", 19}, {"writev", 20}, {"access", 21}, {"pipe", 22}, {"select", 23},
    {"sched_yield", 24}, {"mremap", 25}, {"msync", 26}, {"mincore", 27}, {"madvise", 28}, {"shmget", 29}, {"shmat", 30}, {"shmctl", 31},
    {"dup", 32}, {"dup2", 33}, {"pause", 34}, {"nanosleep", 35}, {"getitimer", 36}, {"alarm", 37}, {"setitimer", 38}, {"getpid", 39},
    {"sendfile", 40}, {"socket", 41}, {"connect", 42}, {"accept", 43}, {"sendto", 44}, {"recvfrom", 45}, {"sendmsg", 46}, {"recvmsg", 47},
    {"shutdown", 48}, {"bind", 49}, {"listen", 50}, {"getsockname", 51}, {"getpeername", 52}, {"socketpair", 53}, {"setsockopt", 54}, {"getsockopt", 55},
    {"clone", 56}, {"fork", 57}, {"vfork", 58}, {"execve", 59}, {"exit", 60}, {"wait4", 61}, {"kill", 62}, {"uname", 63},
    {"semget", 64}, {"semop", 65}, {"semctl", 66}, {"shmdt", 67}, {"msgget", 68}, {"msgsnd", 69}, {"msgrcv", 70}, {"msgctl", 71},
    {"fcntl", 72}, {"flock", 73}, {"fsync", 74}, {"fdatasync", 75}, {"truncate", 76}, {"ftruncate", 77}, {"getdents", 78}, {"getcwd", 79},
    {"chdir", 80}, {"fchdir", 81}, {"rename", 82}, {"mkdir", 83}, {"rmdir", 84}, {"creat", 85}, {"link", 86}, {"unlink", 87},
    {"symlink", 88}, {"readlink", 89}, {"chmod", 90}, {"fchmod", 91}, {"chown", 92}, {"fchown", 93}, {"lchown", 94}, {"umask", 95},
    {"gettimeofday", 96}, {"getrlimit", 97}, {"getrusage", 98}, {"sysinfo", 99}, {"times", 100}, {"ptrace", 101}, {"getuid", 102}, {"syslog", 103},
    {"getgid", 104}, {"setuid", 105}, {"setgid", 106}, {"geteuid", 107}, {"getegid", 108}, {"setpgid", 109}, {"getppid", 110}, {"getpgrp", 111},
    {"setsid", 112}, {"setreuid", 113}, {"setregid", 114}, {"getgroups", 115}, {"setgroups", 116}, {"setresuid", 117}, {"getresuid", 118}, {"setresgid", 119},
    {"getresgid", 120}, {"getpgid", 121}, {"setfsuid", 122}, {"setfsgid", 123}, {"getsid", 124}, {"capget", 125}, {"capset", 126}, {"rt_sigpending", 127},
    {"rt_sigtimedwait", 128}, {"rt_sigqueueinfo", 129}, {"rt_sigsuspend", 130}, {"sigaltstack", 131}, {"utime", 132}, {"mknod", 133}, {"uselib", 134}, {"personality", 135},
    {"ustat", 136}, {"statfs", 137}, {"fstatfs", 138}, {"sysfs", 139}, {"getpriority", 140}, {"setpriority", 141}, {"sched_setparam", 142}, {"sched_getparam", 143},
    {"sched_setscheduler", 144}, {"sched_getscheduler", 145}, {"sched_get_priority_max", 146}, {"sched_get_priority_min", 147}, {"sched_rr_get_interval", 148}, {"mlock", 149}, {"munlock", 150}, {"mlockall", 151},
    {"munlockall", 152}, {"vhangup", 153}, {"modify_ldt", 154}, {"pivot_root", 155}, {"_sysctl", 156}, {"prctl", 157}, {"arch_prctl", 158}, {"adjtimex", 159},
    {"setrlimit", 160}, {"chroot", 161}, {"sync", 162}, {"acct", 163}, {"settimeofday", 164}, {"mount", 165}, {"umount2", 166}, {"swapon", 167},
    {"swapoff", 168}, {"reboot", 169}, {"sethostname", 170}, {"setdomainname", 171}, {"iopl", 172}, {"ioperm", 173}, {"create_module", 174}, {"init_module", 175},
    {"delete_module", 176}, {"get_kernel_syms", 177}, {"query_module", 178}, {"quotactl", 179}, {"nfsservctl", 180}, {"getpmsg", 181}, {"putpmsg", 182}, {"afs_syscall", 183},
    {"tuxcall", 184}, {"security", 185}, {"gettid", 186}, {"readahead", 187}, {"setxattr", 188}, {"lsetxattr", 189}, {"fsetxattr", 190}, {"getxattr", 191},
    {"lgetxattr", 192}, {"fgetxattr", 193}, {"listxattr", 194}, {"llistxattr", 195}, {"flistxattr", 196}, {"removexattr", 197}, {"lremovexattr", 198}, {"fremovexattr", 199},
    {"tkill", 200}, {"time", 201}, {"futex", 202}, {"sched_setaffinity", 203}, {"sched_getaffinity", 204}, {"set_thread_area", 205}, {"io_setup", 206}, {"io_destroy", 207},
    {"io_getevents", 208}, {"io_submit", 209}, {"io_cancel", 210}, {"get_thread_area", 211}, {"lookup_dcookie", 212}, {"epoll_create", 213}, {"epoll_ctl_old", 214}, {"epoll_wait_old", 215},
    {"remap_file_pages", 216}, {"getdents64", 217}, {"set_tid_address", 218}, {"restart_syscall", 219}, {"semtimedop", 220}, {"fadvise64", 221}, {"timer_create", 222}, {"timer_settime", 223},
    {"timer_gettime", 224}, {"timer_getoverrun", 225}, {"timer_delete", 226}, {"clock_settime", 227}, {"clock_gettime", 228}, {"clock_getres", 229}, {"clock_nanosleep", 230}, {"exit_group", 231},
    {"epoll_wait", 232}, {"epoll_ctl", 233}, {"tgkill", 234}, {"utimes", 235}, {"vserver", 236}, {"mbind", 237}, {"set_mempolicy", 238}, {"get_mempolicy", 239},
    {"mq_open", 240}, {"mq_unlink", 241}, {"mq_timedsend", 242}, {"mq_timedreceive", 243}, {"mq_notify", 244}, {"mq_getsetattr", 245}, {"kexec_load", 246}, {"waitid", 247},
    {"add_key", 248}, {"request_key", 249}, {"keyctl", 250}, {"ioprio_set", 251}, {"ioprio_get", 252}, {"inotify_init", 253}, {"inotify_add_watch", 254}, {"inotify_rm_watch", 255},
    {"migrate_pages", 256}, {"openat", 257}, {"mkdirat", 258}, {"mknodat", 259}, {"fchownat", 260}, {"futimesat", 261}, {"newfstatat", 262}, {"unlinkat", 263},
    {"renameat", 264}, {"linkat", 265}, {"symlinkat", 266}, {"readlinkat", 267}, {"fchmodat", 268}, {"faccessat", 269}, {"pselect6", 270}, {"ppoll", 271},
    {"unshare", 272}, {"set_robust_list", 273}, {"get_robust_list", 274}, {"splice", 275}, {"tee", 276}, {"sync_file_range", 277}, {"vmsplice", 278}, {"move_pages", 279},
    {"utimensat", 280}, {"epoll_pwait", 281}, {"signalfd", 282}, {"timerfd_create", 283}, {"eventfd", 284}, {"fallocate", 285}, {"timerfd_settime", 286}, {"timerfd_gettime", 287},
    {"accept4", 288}, {"signalfd4", 289}, {"eventfd2", 290}, {"epoll_create1", 291}, {"dup3", 292}, {"pipe2", 293}, {"inotify_init1", 294}, {"preadv", 295},
    {"pwritev", 296}, {"rt_tgsigqueueinfo", 297}, {"perf_event_open", 298}, {"recvmmsg", 299}, {"fanotify_init", 300}, {"fanotify_mark", 301}, {"prlimit64", 302}, {"name_to_handle_at", 303},
    {"open_by_handle_at", 304}, {"clock_adjtime", 305}, {"syncfs", 306}, {"sendmmsg", 307}, {"setns", 308}, {"getcpu", 309}, {"process_vm_readv", 310}, {"process_vm_writev", 311},
    {"kcmp", 312}, {"finit_module", 313}, {"sched_setattr", 314}, {"sched_getattr", 315}, {"renameat2", 316}, {"seccomp", 317}, {"getrandom", 318}, {"memfd_create", 319},
    {"kexec_file_load", 320}, {"bpf", 321}, {"execveat", 322}, {"userfaultfd", 323}, {"membarrier", 324}, {"mlock2", 325}, {"copy_file_range", 326}, {"preadv2", 327},
    {"pwritev2", 328}, {"pkey_mprotect", 329}, {"pkey_alloc", 330}, {"pkey_free", 331}, {"statx", 332}, {"io_pgetevents", 333}, {"rseq", 334}, {"pidfd_send_signal", 424},
    {"io_uring_setup", 425}, {"io_uring_enter", 426}, {"io_uring_register", 427}, {"open_tree", 428}, {"move_mount", 429}, {"fsopen", 430}, {"fsconfig", 431}, {"fsmount", 432},
    {"fspick", 433}, {"pidfd_open", 434}, {"clone3", 435}, {"close_range", 436}, {"openat2", 437}, {"pidfd_getfd", 438}, {"faccessat2", 439}, {"process_madvise", 440},
    {"epoll_pwait2", 441}, {"mount_setattr", 442}, {"quotactl_fd", 443}, {"landlock_create_ruleset", 444}, {"landlock_add_rule", 445}, {"landlock_restrict_self", 446}, {"memfd_secret", 447}, {"process_mrelease", 448},
    {NULL, -1}
};

static int get_syscall_nr(const char *name) {
    int i;
    for (i = 0; SYSCALL_TABLE[i].name != NULL; i++) {
        if (strcmp(SYSCALL_TABLE[i].name, name) == 0) {
            return SYSCALL_TABLE[i].nr;
        }
    }
    return -1;
}

/* ======================================== PHP Functions ======================================== */

// FNV-1a 哈希算法 (与eBPF侧保持一致)
static uint32_t hash_string(const char *str, uint8_t len)
{
    uint32_t hash = 2166136261u;  // FNV offset basis
    uint8_t i;

    for (i = 0; i < len && i < MAX_PATH_LEN && str[i] != '\0'; i++) {
        hash ^= (uint32_t)str[i];
        hash *= 16777619u;  // FNV prime
    }

    return hash;
}

// 辅助函数: 发送单个packet到内核
static int send_packet(struct syscall_filter_packet *pkt)
{
    return prctl(PR_SYSCALL_FILTER_CMD, (unsigned long)pkt, 0, 0, 0);
}

// syscall_filter_begin: 激活监控并批量添加规则 (PHP5 适配版本)
static void syscall_filter_execute_begin(INTERNAL_FUNCTION_PARAMETERS)
{
    zval *syscalls_arg;
    HashTable *syscalls_ht;
    HashPosition pos;
    zval **entry;
    char *key;
    uint key_len;
    ulong idx;
    struct syscall_filter_packet pkt;
    uint32_t rule_idx;
    int i;

    // PHP5 参数解析
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a",
                              &syscalls_arg) == FAILURE) {
        RETURN_FALSE;
    }

    // 初始化：whitelist 填充 0xFFFF，其他填充 0
    memset(&pkt, 0, sizeof(pkt));
    for (i = 0; i < MAX_RULES; i++) {
        pkt.whitelist[i] = SYSCALL_SLOT_EMPTY;
    }
    pkt.cmd = CMD_FILTER_BEGIN;

    syscalls_ht = Z_ARRVAL_P(syscalls_arg);
    rule_idx = 0;

    // PHP5 风格的哈希表遍历
    for (zend_hash_internal_pointer_reset_ex(syscalls_ht, &pos);
         zend_hash_get_current_data_ex(syscalls_ht, (void **)&entry, &pos) == SUCCESS;
         zend_hash_move_forward_ex(syscalls_ht, &pos))
    {
        // 获取键名（必须是字符串键）
        int key_type = zend_hash_get_current_key_ex(syscalls_ht, &key, &key_len, &idx, 0, &pos);

        if (key_type != HASH_KEY_IS_STRING) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                           "Must use associative array: 'syscall' => [paths]");
            continue;
        }

        const char *syscall_name = key;
        int syscall_nr = get_syscall_nr(syscall_name);

        if (syscall_nr < 0) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                           "Unknown syscall: %s", syscall_name);
            continue;
        }

        // 值必须是数组
        if (Z_TYPE_PP(entry) != IS_ARRAY) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                           "Value for '%s' must be an array (use empty array [] for no path constraint)",
                           syscall_name);
            continue;
        }

        HashTable *path_ht = Z_ARRVAL_PP(entry);
        uint32_t path_count = zend_hash_num_elements(path_ht);

        if (path_count == 0) {
            // 情况A: 无路径约束 (空数组 [])
            if (rule_idx >= MAX_RULES) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR,
                               "Exceeded max rules limit (%d)", MAX_RULES);
                RETURN_FALSE;
            }

            pkt.whitelist[rule_idx] = (uint16_t)syscall_nr;
            pkt.path_hash[rule_idx] = 0;
            pkt.path_len[rule_idx] = 0;
            rule_idx++;

        } else {
            // 情况B: 有路径约束 - 每个路径占一个槽位
            HashPosition path_pos;
            zval **path_entry;

            for (zend_hash_internal_pointer_reset_ex(path_ht, &path_pos);
                 zend_hash_get_current_data_ex(path_ht, (void **)&path_entry, &path_pos) == SUCCESS;
                 zend_hash_move_forward_ex(path_ht, &path_pos))
            {
                if (rule_idx >= MAX_RULES) {
                    php_error_docref(NULL TSRMLS_CC, E_ERROR,
                                   "Exceeded max rules limit (%d)", MAX_RULES);
                    RETURN_FALSE;
                }

                if (Z_TYPE_PP(path_entry) != IS_STRING) {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                   "Path must be string for %s", syscall_name);
                    continue;
                }

                const char *path = Z_STRVAL_PP(path_entry);
                size_t path_len = Z_STRLEN_PP(path_entry);

                if (path_len >= MAX_PATH_LEN) {
                    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                                   "Path too long (max %d): %s", MAX_PATH_LEN-1, path);
                    continue;
                }

                // 计算哈希并填充数组
                pkt.whitelist[rule_idx] = (uint16_t)syscall_nr;
                pkt.path_hash[rule_idx] = hash_string(path, (uint8_t)path_len);
                pkt.path_len[rule_idx] = (uint8_t)path_len;
                rule_idx++;
            }
        }
    }

    // 单次prctl调用发送所有规则
    if (send_packet(&pkt) != 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to send CMD_FILTER_BEGIN");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

// syscall_filter_end: 批量删除规则并停止监控 (PHP5 适配版本)
static void syscall_filter_execute_end(INTERNAL_FUNCTION_PARAMETERS)
{
    zval *syscalls_arg;
    HashTable *syscalls_ht;
    HashPosition pos;
    zval **entry;
    char *key;
    uint key_len;
    ulong idx;
    struct syscall_filter_packet pkt;
    uint32_t rule_idx;
    int i;

    // PHP5 参数解析
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a",
                              &syscalls_arg) == FAILURE) {
        RETURN_FALSE;
    }

    // 初始化：whitelist 填充 0xFFFF，其他填充 0
    memset(&pkt, 0, sizeof(pkt));
    for (i = 0; i < MAX_RULES; i++) {
        pkt.whitelist[i] = SYSCALL_SLOT_EMPTY;
    }
    pkt.cmd = CMD_FILTER_END;

    syscalls_ht = Z_ARRVAL_P(syscalls_arg);
    rule_idx = 0;

    // PHP5 风格的哈希表遍历 (镜像begin逻辑)
    for (zend_hash_internal_pointer_reset_ex(syscalls_ht, &pos);
         zend_hash_get_current_data_ex(syscalls_ht, (void **)&entry, &pos) == SUCCESS;
         zend_hash_move_forward_ex(syscalls_ht, &pos))
    {
        int key_type = zend_hash_get_current_key_ex(syscalls_ht, &key, &key_len, &idx, 0, &pos);

        if (key_type != HASH_KEY_IS_STRING) {
            continue;
        }

        const char *syscall_name = key;
        int syscall_nr = get_syscall_nr(syscall_name);

        if (syscall_nr < 0) {
            continue;
        }

        if (Z_TYPE_PP(entry) != IS_ARRAY) {
            continue;
        }

        HashTable *path_ht = Z_ARRVAL_PP(entry);
        uint32_t path_count = zend_hash_num_elements(path_ht);

        if (path_count == 0) {
            // 情况A: 无路径约束
            if (rule_idx >= MAX_RULES) {
                php_error_docref(NULL TSRMLS_CC, E_ERROR,
                               "Exceeded max rules limit (%d)", MAX_RULES);
                RETURN_FALSE;
            }

            pkt.whitelist[rule_idx] = (uint16_t)syscall_nr;
            pkt.path_hash[rule_idx] = 0;
            pkt.path_len[rule_idx] = 0;
            rule_idx++;

        } else {
            // 情况B: 有路径约束
            HashPosition path_pos;
            zval **path_entry;

            for (zend_hash_internal_pointer_reset_ex(path_ht, &path_pos);
                 zend_hash_get_current_data_ex(path_ht, (void **)&path_entry, &path_pos) == SUCCESS;
                 zend_hash_move_forward_ex(path_ht, &path_pos))
            {
                if (rule_idx >= MAX_RULES) {
                    php_error_docref(NULL TSRMLS_CC, E_ERROR,
                                   "Exceeded max rules limit (%d)", MAX_RULES);
                    RETURN_FALSE;
                }

                if (Z_TYPE_PP(path_entry) != IS_STRING) {
                    continue;
                }

                const char *path = Z_STRVAL_PP(path_entry);
                size_t path_len = Z_STRLEN_PP(path_entry);

                if (path_len >= MAX_PATH_LEN) {
                    continue;
                }

                // 计算哈希并填充数组(与begin完全一致)
                pkt.whitelist[rule_idx] = (uint16_t)syscall_nr;
                pkt.path_hash[rule_idx] = hash_string(path, (uint8_t)path_len);
                pkt.path_len[rule_idx] = (uint8_t)path_len;
                rule_idx++;
            }
        }
    }

    // 单次prctl调用发送所有规则(用于精确删除)
    if (send_packet(&pkt) != 0) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to send CMD_FILTER_END");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(syscall_filter_begin)
{
    syscall_filter_execute_begin(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

PHP_FUNCTION(syscall_filter_end)
{
    syscall_filter_execute_end(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ======================================== Module Lifecycle ======================================== */

PHP_MINIT_FUNCTION(syscall_filter) { return SUCCESS; }
PHP_MSHUTDOWN_FUNCTION(syscall_filter) { return SUCCESS; }
PHP_RINIT_FUNCTION(syscall_filter) { return SUCCESS; }
PHP_RSHUTDOWN_FUNCTION(syscall_filter) { return SUCCESS; }

PHP_MINFO_FUNCTION(syscall_filter)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "syscall_filter support", "enabled");
    php_info_print_table_row(2, "Version", PHP_SYSCALL_FILTER_VERSION);
    php_info_print_table_row(2, "Path parameter support", "yes");
    php_info_print_table_row(2, "Max rules per command", "8");
    php_info_print_table_row(2, "Max path length", "32");
    php_info_print_table_end();
}

static const zend_function_entry syscall_filter_functions[] = {
    PHP_FE(syscall_filter_begin, NULL)
    PHP_FE(syscall_filter_end, NULL)
    PHP_FE_END
};

zend_module_entry syscall_filter_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_SYSCALL_FILTER_EXTNAME,
    syscall_filter_functions,
    PHP_MINIT(syscall_filter),
    PHP_MSHUTDOWN(syscall_filter),
    PHP_RINIT(syscall_filter),
    PHP_RSHUTDOWN(syscall_filter),
    PHP_MINFO(syscall_filter),
    PHP_SYSCALL_FILTER_VERSION,
    STANDARD_MODULE_PROPERTIES
};
