AC_INIT(vmcam, 0.1)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_PROG_CC
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_CHECK_LIB([ssl], [main], [], [AC_MSG_FAILURE([could not find ssl])])
AC_CHECK_LIB([crypto], [main], [], [AC_MSG_FAILURE([could not find crypto])])
AC_CHECK_LIB([pthread], [main], [], [AC_MSG_FAILURE([could not find pthread])])
AC_OUTPUT