AM_CFLAGS = -std=c11 -Wall -Werror $(EVERARCH_CFLAGS) $(GCRYPT_CFLAGS) $(PTHREAD_CFLAGS) $(XML_CFLAGS) $(GPGME_CFLAGS)

bin_PROGRAMS = \
	claims-test \
	concurrent-glacier-test \
	dyn-mem-test \
	evr-glacier-cli \
	evr-glacier-storage \
	files-test \
	glacier-cmd-test \
	glacier-test \
	keys-test \
	signatures-test

claims_test_SOURCES = \
	assert.c \
	claims.c \
	claims-test.c \
	keys.c
claims_test_LDADD = $(XML_LIBS) $(GCRYPT_LIBS)

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

evr_glacier_cli_SOURCES = \
	dyn-mem.c \
	evr-glacier-cli.c \
	files.c \
	glacier-cmd.c \
	keys.c \
	logger.c
evr_glacier_cli_LDADD = $(GCRYPT_LIBS)

evr_glacier_storage_SOURCES = \
	concurrent-glacier.c \
	configuration.c \
	dyn-mem.c \
	evr-glacier-storage.c \
	files.c \
	glacier.c \
	glacier-cmd.c \
	keys.c \
	logger.c
evr_glacier_storage_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

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
glacier_cmd_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

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
glacier_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

keys_test_SOURCES = \
	assert.c \
	keys.c \
	keys-test.c \
	logger.c
keys_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

signatures_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	signatures.c \
	signatures-test.c
signatures_test_LDADD = $(GPGME_LIBS)
