ACLOCAL_AMFLAGS = -I aux

bin_PROGRAMS      = yk-secret-tool

yk_secret_tool_LDADD = @YKPIV_LIBS@ -lcrypto
yk_secret_tool_CFLAGS = @YKPIV_CFLAGS@ -Wall
yk_secret_tool_SOURCES = src/piv.c src/piv-pin.c \
						 src/yk-secret-tool.c src/safe-mem.c


