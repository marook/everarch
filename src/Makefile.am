AM_CFLAGS = -Wall -Werror $(EVERARCH_CFLAGS) $(GCRYPT_CFLAGS) $(PTHREAD_CFLAGS) $(XML_CFLAGS) $(GPGME_CFLAGS)
BUILT_SOURCES = attr-query-parser.h
AM_YFLAGS = -d

bin_PROGRAMS = \
	attr-index-db-test \
	basics-test \
	claims-test \
	concurrent-glacier-test \
	dyn-mem-test \
	evr-attr-index \
	evr-glacier-cli \
	evr-glacier-storage \
	files-test \
	glacier-cmd-test \
	glacier-test \
	keys-test \
	rollsum-test \
	signatures-test

attr_index_db_test_SOURCES = \
	assert.c \
	attr-index-db.c \
	attr-index-db-configuration.c \
	attr-index-db-test.c \
	attr-query-lexer.l \
	attr-query-parser.y \
	attr-query-sql.c \
	configuration-testutil.c \
	configurations.c \
	db.c \
	dyn-mem.c \
	files.c \
	glacier.c \
	glacier-storage-configuration.c \
	keys.c \
	logger.c
attr_index_db_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)
attr_index_db_test_LFLAGS = --header-file=attr-query-lexer.h

basics_test_SOURCES = \
	assert.c \
	basics.c \
	basics-test.c

claims_test_SOURCES = \
	assert.c \
	claims.c \
	claims-test.c \
	keys.c \
	logger.c
claims_test_LDADD = $(XML_LIBS) $(GCRYPT_LIBS)

concurrent_glacier_test_SOURCES = \
	assert.c \
	attr-index-db-configuration.c \
	concurrent-glacier-test.c \
	concurrent-glacier.c \
	configuration-testutil.c \
	configurations.c \
	dyn-mem.c \
	files.c \
	glacier-storage-configuration.c \
	logger.c
concurrent_glacier_test_LDADD = $(EVERARCH_LIBS)

dyn_mem_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	dyn-mem-test.c
dyn_mem_test_LDADD = $(EVERARCH_LIBS)

evr_attr_index_SOURCES = \
	claims.c \
	dyn-mem.c \
	evr-attr-index.c \
	evr-glacier-client.c \
	files.c \
	glacier-cmd.c \
	keys.c \
	logger.c \
	server.c \
	signatures.c
evr_attr_index_LDADD = $(GCRYPT_LIBS) $(XML_LIBS) $(GPGME_LIBS)

evr_glacier_cli_SOURCES = \
	claims.c \
	dyn-mem.c \
	evr-glacier-cli.c \
	evr-glacier-client.c \
	files.c \
	glacier-cmd.c \
	keys.c \
	logger.c \
	signatures.c
evr_glacier_cli_LDADD = $(XML_LIBS) $(GCRYPT_LIBS) $(GPGME_LIBS)

evr_glacier_storage_SOURCES = \
	concurrent-glacier.c \
	configurations.c \
	db.c \
	dyn-mem.c \
	evr-glacier-storage.c \
	files.c \
	glacier.c \
	glacier-cmd.c \
	glacier-storage-configuration.c \
	keys.c \
	logger.c \
	server.c
evr_glacier_storage_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

files_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	files.c \
	files-test.c \
	logger.c
files_test_LDADD = $(EVERARCH_LIBS)

glacier_cmd_test_SOURCES = \
	assert.c \
	glacier-cmd.c \
	glacier-cmd-test.c \
	keys.c
glacier_cmd_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

glacier_test_SOURCES = \
	assert.c \
	attr-index-db-configuration.c \
	configuration-testutil.c \
	configurations.c \
	db.c \
	dyn-mem.c \
	files.c \
	glacier.c \
	glacier-storage-configuration.c \
	glacier-test.c \
	keys.c \
	logger.c
glacier_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

keys_test_SOURCES = \
	assert.c \
	keys.c \
	keys-test.c \
	logger.c
keys_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS)

rollsum_test_SOURCES = \
	assert.c \
	logger.c \
	rollsum.c \
	rollsum-test.c

signatures_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	signatures.c \
	signatures-test.c
signatures_test_LDADD = $(GPGME_LIBS)
