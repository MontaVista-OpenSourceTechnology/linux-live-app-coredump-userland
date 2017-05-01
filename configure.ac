# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(pcoredump, 0.2.0, source@mvista.com)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# May use kernel headers from custom location.
AC_ARG_WITH(kernel-headers,
[  --with-kernel-headers=DIR specifies directory to find kernel headers],
[if test x$withval != x; then
   CPPFLAGS=$(echo $CPPFLAGS -I$withval)
fi])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h stdlib.h string.h errno.h getopt.h \
	 	  asm/resource.h sys/ptrace.h linux/livedump.h linux/oom.h])

# Checks for library functions.
AC_CHECK_FUNCS([strtol error getopt_long])

AC_CONFIG_FILES([Makefile pcoredump.spec])
AC_OUTPUT
