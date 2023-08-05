# CFLAGS_WARN contains the cflags related to compiler errors and
# warnings.
CFLAGS_WARN=\
	-Wall \
	-Werror \
	-Wextra \
	-Wpedantic \
	-Wno-discarded-qualifiers \
	-Wno-missing-field-initializers \
	-Wno-unused-parameter \
	-Wno-variadic-macros

AM_CFLAGS = $(CFLAGS_WARN) $(SQLITE_CFLAGS) $(LIBGCRYPT_CFLAGS) $(PTHREAD_CFLAGS) $(XML_CFLAGS) $(GPGME_CFLAGS) $(SSL_CFLAGS) $(FUSE_CFLAGS) $(GTK_CFLAGS)
BUILT_SOURCES =
AM_YFLAGS = -d

info_TEXINFOS = evr.texi

resdir = $(prefix)/share/everarch
dist_res_DATA = attr-ui-spec-interface.xslt

bin_PROGRAMS = \
	evr \
	evr-glacier-storage \
	evr-glacier-tool

dist_bin_SCRIPTS = evr-backup

if HAS_LEX
bin_PROGRAMS += evr-attr-index

BUILT_SOURCES += \
	attr-query-parser.h \
	attr_index_db_test-attr-query-lexer.c \
	evr_attr_index-attr-query-lexer.c
endif

if HAS_GTK
bin_PROGRAMS += evr-attr-ui
endif

if HAS_FUSE
bin_PROGRAMS += evr-fs
endif

evr_c_unit_tests = \
	attr-index-db-test \
	auth-test \
	basics-test \
	claims-test \
	concurrent-glacier-test \
	configp-test \
	dyn-mem-test \
	evr-attr-index-client-test \
	evr-tls-test \
	files-test \
	glacier-cmd-test \
	glacier-test \
	keys-test \
	notify-test \
	open-files-test \
	queue-test \
	rollsum-test \
	seed-desc-test \
	signatures-test \
	subprocess-test

if HAS_FUSE
evr_c_unit_tests += fs-inode-test
endif

check_PROGRAMS = \
	$(evr_c_unit_tests) \
	glacier-benchmark \
	zipper

TESTS = $(evr_c_unit_tests)

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
	evr-tls.c \
	files.c \
	glacier.c \
	glacier-storage-configuration.c \
	keys.c \
	logger.c \
	subprocess.c
attr_index_db_test_LDADD = $(SQLITE_LIBS) $(LIBGCRYPT_LIBS) -lm $(SSL_LIBS) $(XML_LIBS)
attr_index_db_test_LFLAGS = --header-file=attr-query-lexer.h

auth_test_SOURCES = \
	assert.c \
	auth.c \
	auth-test.c \
	basics.c \
	logger.c

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
claims_test_LDADD = $(XML_LIBS) $(LIBGCRYPT_LIBS)

concurrent_glacier_test_SOURCES = \
	assert.c \
	basics.c \
	concurrent-glacier-test.c \
	concurrent-glacier.c \
	configuration-testutil.c \
	configurations.c \
	dyn-mem.c \
	files.c \
	glacier-storage-configuration.c \
	keys.c \
	logger.c \
	notify.c \
	queue.c
concurrent_glacier_test_LDADD = $(SQLITE_LIBS) $(LIBGCRYPT_LIBS)

configp_test_SOURCES = \
	assert.c \
	basics.c \
	configp.c \
	configp-test.c \
	logger.c

dyn_mem_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	dyn-mem-test.c \
	logger.c
dyn_mem_test_LDADD = $(SQLITE_LIBS)

evr_attr_index_SOURCES = \
	attr-index-db.c \
	attr-query-lexer.l \
	attr-query-parser.y \
	attr-query-sql.c \
	auth.c \
	basics.c \
	claims.c \
	configurations.c \
	configp.c \
	daemon.c \
	db.c \
	dyn-mem.c \
	evr-attr-index.c \
	evr-glacier-client.c \
	evr-tls.c \
	files.c \
	glacier-cmd.c \
	handover.c \
	keys.c \
	logger.c \
	metadata.c \
	notify.c \
	queue.c \
	server.c \
	signatures.c \
	subprocess.c
evr_attr_index_LDADD = @ARGP_LIBS@ $(SQLITE_LIBS) $(LIBGCRYPT_LIBS) $(XML_LIBS) $(GPGME_LIBS) -lm $(SSL_LIBS)
evr_attr_index_LFLAGS = --header-file=attr-query-lexer.h

evr_attr_ui_SOURCES = \
	auth.c \
	basics.c \
	claims.c \
	configp.c \
	dyn-mem.c \
	evr-attr-ui.c \
	evr-glacier-client.c \
	evr-tls.c \
	files.c \
	glacier-cmd.c \
	keys.c \
	logger.c \
	metadata.c \
	signatures.c
evr_attr_ui_LDADD = $(GTK_LIBS) $(XML_LIBS) $(SSL_LIBS) $(LIBGCRYPT_LIBS) $(GPGME_LIBS)

evr_SOURCES = \
	auth.c \
	basics.c \
	claims.c \
	configp.c \
	dyn-mem.c \
	evr-attr-index-client.c \
	evr-cli.c \
	evr-glacier-client.c \
	evr-tls.c \
	files.c \
	glacier-cmd.c \
	handover.c \
	keys.c \
	logger.c \
	metadata.c \
	seed-desc.c \
	signatures.c
evr_LDADD = @ARGP_LIBS@ $(XML_LIBS) $(LIBGCRYPT_LIBS) $(GPGME_LIBS) $(SSL_LIBS)

evr_fs_SOURCES = \
	auth.c \
	basics.c \
	claims.c \
	configp.c \
	daemon.c \
	dyn-mem.c \
	evr-attr-index-client.c \
	evr-fs.c \
	evr-glacier-client.c \
	evr-tls.c \
	files.c \
	fs-inode.c \
	glacier-cmd.c \
	keys.c \
	logger.c \
	metadata.c \
	open-files.c \
	seed-desc.c \
	signatures.c
evr_fs_LDADD = @ARGP_LIBS@ $(XML_LIBS) $(FUSE_LIBS) $(LIBGCRYPT_LIBS) $(GPGME_LIBS) $(SSL_LIBS)

evr_glacier_storage_SOURCES = \
	auth.c \
	basics.c \
	concurrent-glacier.c \
	configurations.c \
	configp.c \
	daemon.c \
	db.c \
	dyn-mem.c \
	evr-glacier-storage.c \
	evr-tls.c \
	files.c \
	glacier.c \
	glacier-cmd.c \
	glacier-storage-configuration.c \
	keys.c \
	logger.c \
	notify.c \
	queue.c \
	server.c
evr_glacier_storage_LDADD = @ARGP_LIBS@ $(SQLITE_LIBS) $(LIBGCRYPT_LIBS) $(SSL_LIBS)

evr_glacier_tool_SOURCES = \
	basics.c \
	configp.c \
	db.c \
	dyn-mem.c \
	evr-glacier-tool.c \
	files.c \
	glacier.c \
	keys.c \
	logger.c
evr_glacier_tool_LDADD = @ARGP_LIBS@ $(SQLITE_LIBS) $(LIBGCRYPT_LIBS)

evr_attr_index_client_test_SOURCES = \
	assert.c \
	auth.c \
	basics.c \
	dyn-mem.c \
	evr-attr-index-client.c \
	evr-attr-index-client-test.c \
	file-mem.c \
	files.c \
	keys.c \
	logger.c
evr_attr_index_client_test_LDADD = $(LIBGCRYPT_LIBS)

evr_tls_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	evr-tls.c \
	evr-tls-test.c \
	files.c \
	logger.c \
	server.c
evr_tls_test_LDADD = $(SSL_LIBS)

files_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	file-mem.c \
	files.c \
	files-test.c \
	logger.c
files_test_LDADD = $(SQLITE_LIBS)

fs_inode_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	fs-inode.c \
	fs-inode-test.c \
	keys.c \
	logger.c
fs_inode_test_LDADD = $(LIBGCRYPT_LIBS)

glacier_benchmark_SOURCES = \
	auth.c \
	basics.c \
	claims.c \
	configp.c \
	dyn-mem.c \
	evr-glacier-client.c \
	evr-tls.c \
	files.c \
	glacier-benchmark.c \
	glacier-cmd.c \
	keys.c \
	logger.c \
	metadata.c \
	signatures.c
glacier_benchmark_LDADD = @ARGP_LIBS@ $(XML_LIBS) $(LIBGCRYPT_LIBS) $(SSL_LIBS) $(GPGME_LIBS)

glacier_cmd_test_SOURCES = \
	assert.c \
	basics.c \
	glacier-cmd.c \
	glacier-cmd-test.c \
	keys.c \
	logger.c
glacier_cmd_test_LDADD = $(SQLITE_LIBS) $(LIBGCRYPT_LIBS)

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
glacier_test_LDADD = $(SQLITE_LIBS) $(LIBGCRYPT_LIBS)

keys_test_SOURCES = \
	assert.c \
	basics.c \
	keys.c \
	keys-test.c \
	logger.c
keys_test_LDADD = $(SQLITE_LIBS) $(LIBGCRYPT_LIBS)

notify_test_SOURCES = \
	assert.c \
	basics.c \
	logger.c \
	notify.c \
	notify-test.c \
	queue.c

open_files_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	files.c \
	keys.c \
	logger.c \
	open-files.c \
	open-files-test.c
open_files_test_LDADD = $(LIBGCRYPT_LIBS)

queue_test_SOURCES = \
	assert.c \
	basics.c \
	logger.c \
	queue.c \
	queue-test.c

rollsum_test_SOURCES = \
	assert.c \
	basics.c \
	logger.c \
	rollsum.c \
	rollsum-test.c

seed_desc_test_SOURCES = \
	assert.c \
	basics.c \
	claims.c \
	keys.c \
	logger.c \
	seed-desc.c \
	seed-desc-test.c
seed_desc_test_LDADD = $(XML_LIBS) $(LIBGCRYPT_LIBS)

signatures_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	file-mem.c \
	files.c \
	logger.c \
	metadata.c \
	signatures.c \
	signatures-test.c
signatures_test_LDADD = $(GPGME_LIBS)

subprocess_test_SOURCES = \
	assert.c \
	basics.c \
	dyn-mem.c \
	files.c \
	logger.c \
	subprocess.c \
	subprocess-test.c

zipper_SOURCES = \
	logger.c \
	zipper.c
