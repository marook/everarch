AM_LIBS = $(EVERARCH_LIBS) $(PTHREAD_LIBS)
AM_CFLAGS = -std=c11 -Wall -Werror $(EVERARCH_CFLAGS) $(PTHREAD_CFLAGS)

bin_PROGRAMS = \
	concurrent-glacier-test \
	memory-test \
	files-test \
	glacier-cmd-test \
	glacier-test \
	keys-test

concurrent_glacier_test_SOURCES = \
	assert.c \
	concurrent-glacier-test.c \
	concurrent-glacier.c \
	configuration.c \
	configuration-testutil.c \
	memory.c \
	files.c \
	logger.c
concurrent_glacier_test_LDADD = $(EVERARCH_LIBS)

memory_test_SOURCES = \
	assert.c \
	memory.c \
	memory-test.c
memory_test_LDADD = $(EVERARCH_LIBS)

files_test_SOURCES = \
	assert.c \
	memory.c \
	files.c \
	files-test.c
files_test_LDADD = $(EVERARCH_LIBS)

glacier_cmd_test_SOURCES = \
	assert.c \
	glacier-cmd.c \
	glacier-cmd-test.c \
	keys.c
glacier_cmd_test_LDADD = $(EVERARCH_LIBS)

glacier_test_SOURCES = \
	assert.c \
	configuration.c \
	memory.c \
	files.c \
	glacier.c \
	glacier-test.c \
	configuration-testutil.c \
	keys.c \
	logger.c
glacier_test_LDADD = $(EVERARCH_LIBS)

keys_test_SOURCES = \
	assert.c \
	keys.c \
	keys-test.c \
	logger.c
keys_test_LDADD = $(EVERARCH_LIBS)
