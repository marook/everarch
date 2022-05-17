AM_CFLAGS = -Wall -Werror $(EVERARCH_CFLAGS) $(GCRYPT_CFLAGS) $(PTHREAD_CFLAGS) $(XML_CFLAGS) $(GPGME_CFLAGS)
BUILT_SOURCES = attr-query-parser.h attr_index_db_test-attr-query-lexer.c evr_attr_index-attr-query-lexer.c
AM_YFLAGS = -d

info_TEXINFOS = evr.texi

bin_PROGRAMS = \
	evr-attr-index \
	evr \
	evr-glacier-storage

check_PROGRAMS = \
	attr-index-db-test \
	basics-test \
	claims-test \
	concurrent-glacier-test \
	configp-test \
	dyn-mem-test \
	files-test \
	glacier-cmd-test \
	glacier-test \
	keys-test \
	rollsum-test \
	signatures-test \
	subprocess-test

TESTS = \
	attr-index-db-test \
	basics-test \
	claims-test \
	configp-test \
	concurrent-glacier-test \
	dyn-mem-test \
	files-test \
	glacier-cmd-test \
	glacier-test \
	keys-test \
	rollsum-test \
	signatures-test \
	subprocess-test

attr_index_db_test_SOURCES = \
	assert.c \
	attr-index-db.c \
	attr-index-db-test.c \
	attr-query-lexer.l \
	attr-query-parser.y \
	attr-query-sql.c \
	basics.c \
	claims.c \
	configuration-testutil.c \
	configurations.c \
	db.c \
	dyn-mem.c \
	files.c \
	glacier.c \
	glacier-storage-configuration.c \
	keys.c \
	logger.c \
	subprocess.c
attr_index_db_test_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS) $(XSLT_LIBS) -lm
attr_index_db_test_LFLAGS = --header-file=attr-query-lexer.h

basics_test_SOURCES = \
	assert.c \
	basics.c \
	basics-test.c \
	logger.c

claims_test_SOURCES = \
	assert.c \
	basics.c \
	claims.c \
	claims-test.c \
	keys.c \
	logger.c
claims_test_LDADD = $(XML_LIBS) $(GCRYPT_LIBS)

concurrent_glacier_test_SOURCES = \
	assert.c \
	concurrent-glacier-test.c \
	concurrent-glacier.c \
	configuration-testutil.c \
	configurations.c \
	dyn-mem.c \
	files.c \
	glacier-storage-configuration.c \
	logger.c
concurrent_glacier_test_LDADD = $(EVERARCH_LIBS)

configp_test_SOURCES = \
	assert.c \
	configp.c \
	configp-test.c \
	logger.c

dyn_mem_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	dyn-mem-test.c
dyn_mem_test_LDADD = $(EVERARCH_LIBS)

evr_attr_index_SOURCES = \
	attr-index-db.c \
	attr-query-lexer.l \
	attr-query-parser.y \
	attr-query-sql.c \
	basics.c \
	claims.c \
	configurations.c \
	configp.c \
	db.c \
	dyn-mem.c \
	evr-attr-index.c \
	evr-glacier-client.c \
	files.c \
	glacier-cmd.c \
	handover.c \
	keys.c \
	logger.c \
	server.c \
	signatures.c \
	subprocess.c
evr_attr_index_LDADD = $(EVERARCH_LIBS) $(GCRYPT_LIBS) $(XML_LIBS) $(GPGME_LIBS) $(XSLT_LIBS) -lm
evr_attr_index_LFLAGS = --header-file=attr-query-lexer.h

evr_SOURCES = \
	basics.c \
	claims.c \
	configp.c \
	dyn-mem.c \
	evr-cli.c \
	evr-glacier-client.c \
	files.c \
	glacier-cmd.c \
	handover.c \
	keys.c \
	logger.c \
	signatures.c
evr_LDADD = $(XML_LIBS) $(GCRYPT_LIBS) $(GPGME_LIBS) $(XSLT_LIBS)

evr_glacier_storage_SOURCES = \
	basics.c \
	concurrent-glacier.c \
	configurations.c \
	configp.c \
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
	basics.c \
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

subprocess_test_SOURCES = \
	assert.c \
	dyn-mem.c \
	files.c \
	logger.c \
	subprocess.c \
	subprocess-test.c
