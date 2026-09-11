PHP_ARG_ENABLE([tracer],
  [whether to enable tracer support],
  [AS_HELP_STRING([--enable-tracer],
    [Enable tracer support])],
  [no])

if test "$PHP_TRACER" != "no"; then
  AC_DEFINE(HAVE_TRACER, 1, [Whether you have tracer])
  PHP_NEW_EXTENSION(tracer, tracer.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi