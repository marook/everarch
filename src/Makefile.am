AM_LIBS = $(EVERARCH_LIBS) $(PTHREAD_LIBS)
AM_CFLAGS = -std=c11 -Wall -Werror $(EVERARCH_CFLAGS) $(PTHREAD_CFLAGS)

bin_PROGRAMS = \
	concurrent-glacier-test \
	dyn-mem-test \
	evr-glacier-storage \
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
	dyn-mem.c \
	files.c \
	logger.c
concurrent_glacier_test_LDADD = $(EVERARCH_LIBS)

dyn_mem_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	dyn-mem-test.c
dyn_mem_test_LDADD = $(EVERARCH_LIBS)

evr_glacier_storage_SOURCES = \
	configuration.c \
	dyn-mem.c \
	evr-glacier-storage.c \
	files.c \
	glacier-cmd.c \
	keys.c \
	logger.c
evr_glacier_storage_LDADD = $(EVERARCH_LIBS)

files_test_SOURCES = \
	assert.c \
	dyn-mem.c \
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
	dyn-mem.c \
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
