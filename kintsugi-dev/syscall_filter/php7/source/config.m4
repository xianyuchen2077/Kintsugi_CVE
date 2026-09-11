dnl config.m4 for syscall_filter extension

PHP_ARG_ENABLE(syscall_filter, whether to enable syscall_filter support,
[  --enable-syscall-filter   Enable syscall_filter support], no)

if test "$PHP_SYSCALL_FILTER" != "no"; then
  dnl No external libraries needed - using direct syscalls
  dnl PHP_ADD_LIBRARY(bpf, , SYSCALL_FILTER_SHARED_LIBADD)
  dnl PHP_SUBST(SYSCALL_FILTER_SHARED_LIBADD)

  PHP_NEW_EXTENSION(syscall_filter, syscall_filter.c, $ext_shared)
fi
