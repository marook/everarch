/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2022  Markus Peröbner
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "assert.h"
#include "configuration-testutil.h"
#include "errors.h"
#include "test.h"
#include "logger.h"
#include "attr-index-db.h"
#include "files.h"

// the following declarations are "private" functions from
// attr-index-db.c which we want to test in this file, despite they
// are not part of the public api.
int evr_move_claims(xmlDocPtr dest, xmlDocPtr src, char *dest_name, char *src_name);

#define permutations 4
#define merge_attrs_len 4

int found_tag_a = 0;
int found_tag_b = 0;

int found_claim_0 = 0;

int never_called_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref);
void reset_visit_attrs();
int visit_attrs(void *ctx, const char *key, const char *value);
void assert_attrs(int expected_found_tag_a, int expected_found_tag_b);
void reset_visit_claims();
int claims_status_ok(void *ctx, int parse_res, char *parse_error);
int visit_claims(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);
void assert_claims(int expected_found_claim_0);
struct evr_attr_index_db *create_prepared_attr_index_db(struct evr_attr_index_cfg *cfg, struct evr_attr_spec_claim *custom_spec, evr_blob_file_writer custom_writer);

int asserting_claims_visitor_calls;
evr_claim_ref asserting_claims_visitor_expected_ref;
int asserting_claims_visitor(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);

xsltStylesheetPtr create_attr_mapping_stylesheet();

xmlDocPtr create_xml_doc(char *content);

void test_open_new_attr_index_db_twice(){
    struct evr_attr_def attr_def[2];
    attr_def[0].key = "tag";
    attr_def[0].type = evr_type_str;
    attr_def[1].key = "size";
    attr_def[1].type = evr_type_int;
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 2;
    spec.attr_def = attr_def;
    spec.attr_factories_len = 0;
    spec.attr_factories = NULL;
    memset(spec.transformation_blob_ref, 0, evr_blob_ref_size);
    xsltStylesheetPtr style = create_attr_mapping_stylesheet();
#define seed_ref "sha3-224-c0000000000000000000000000000000000000000000000000000000-0000"
    char *merge_claim_refs[merge_attrs_len] = {
        "sha3-224-c0000000000000000000000000000000000000000000000000000001",
        "sha3-224-c0000000000000000000000000000000000000000000000000000002",
        "sha3-224-c0000000000000000000000000000000000000000000000000000003",
        "sha3-224-c0000000000000000000000000000000000000000000000000000004",
    };
#define tstr(s) "1970-01-01T00:00:" to_string(s) ".000000Z"
#define hdr "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
#define ns "xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\""
#define seed_attr "seed=\"" seed_ref "\""
    char *merge_claims[merge_attrs_len] = {
        hdr "<claim-set " ns " dc:created=\"" tstr(10) "\"><attr " seed_attr "><a op=\"=\" k=\"tag\" v=\"A\"/></attr></claim-set>",
        hdr "<claim-set " ns " dc:created=\"" tstr(20) "\"><attr " seed_attr "><a op=\"+\" k=\"tag\" v=\"B\"/></attr></claim-set>",
        hdr "<claim-set " ns " dc:created=\"" tstr(30) "\"><attr " seed_attr "><a op=\"-\" k=\"tag\"/></attr></claim-set>",
        hdr "<claim-set " ns " dc:created=\"" tstr(40) "\"><archive " seed_attr "/></claim-set>",
    };
#undef ns
#undef hdr
    evr_time t00, t10, t15, t20, t25, t30, t35, t45;
    assert(is_ok(evr_time_from_iso8601(&t00, tstr(0))));
    assert(is_ok(evr_time_from_iso8601(&t10, tstr(10))));
    assert(is_ok(evr_time_from_iso8601(&t15, tstr(15))));
    assert(is_ok(evr_time_from_iso8601(&t20, tstr(20))));
    assert(is_ok(evr_time_from_iso8601(&t25, tstr(25))));
    assert(is_ok(evr_time_from_iso8601(&t30, tstr(30))));
    assert(is_ok(evr_time_from_iso8601(&t35, tstr(35))));
    assert(is_ok(evr_time_from_iso8601(&t45, tstr(45))));
    const int attr_merge_permutations[permutations][merge_attrs_len] = {
        { 0, 1, 2, 3 },
        { 1, 0, 2, 3 },
        { 2, 1, 0, 3 },
        { 3, 0, 1, 2 },
    };
    evr_claim_ref ref;
    assert(is_ok(evr_parse_claim_ref(ref, seed_ref)));
#undef seed_ref
    evr_claim_ref other_ref;
    assert(is_ok(evr_parse_claim_ref(other_ref, "sha3-224-00000100003000050000070000000080000000900000100000000001-0000")));
    for(size_t pi = 0; pi < permutations; ++pi){
        log_info("Permutation %d…", pi);
        struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
        for(int round = 0; round < 2; ++round){
            log_info("Round %d…", round);
            struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db", never_called_blob_file_writer, NULL);
            assert(db);
            if(round == 0){
                assert(is_ok(evr_setup_attr_index_db(db, &spec)));
            }
            assert(is_ok(evr_prepare_attr_index_db(db)));
            if(round == 0){
                for(size_t rai = 0; rai < merge_attrs_len; ++rai){
                    size_t aai = attr_merge_permutations[pi][rai];
                    evr_blob_ref claim_set_ref;
                    assert(is_ok(evr_parse_blob_ref(claim_set_ref, merge_claim_refs[aai])));
                    xmlDoc *claim_set_doc = create_xml_doc(merge_claims[aai]);
                    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, claim_set_doc, 0, NULL)));
                    xmlFreeDoc(claim_set_doc);
                }
            }
            log_info("Assert t=00");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t00, ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert t=10");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t10, ref, visit_attrs, NULL)));
            assert_attrs(1, 0);
            log_info("Assert t=15");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t15, ref, visit_attrs, NULL)));
            assert_attrs(1, 0);
            log_info("Assert t=20");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t20, ref, visit_attrs, NULL)));
            assert_attrs(1, 1);
            log_info("Assert t=25");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t25, ref, visit_attrs, NULL)));
            assert_attrs(1, 1);
            log_info("Assert t=30");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t30, ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert t=45");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t35, ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert not existing ref");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, t25, other_ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            // TODO make the assert calls after here declarative
            log_info("Assert evr_attr_query_claims tag=A t=0");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A at " tstr(0), claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=X t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=X at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A && tag=B t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A && tag=B at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=A || tag=X t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A || tag=X at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=X && tag=A || tag=Y && tag=B t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=X && tag=A || tag=Y && tag=B at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims (tag=X && tag=Y || tag=A) && tag=B t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "(tag=X && tag=Y || tag=A) && tag=B at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=X || tag=A && tag=B || tag=Y t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=X || tag=A && tag=B || tag=Y at " tstr(25), claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims t=45");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "at " tstr(45), claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A && tag=B t=15");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A && tag=B at " tstr(15), claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            assert(is_ok(evr_free_attr_index_db(db)));
        }
        evr_free_attr_index_cfg(cfg);
    }
#undef t0_str
#undef t1_str
#undef t2_str
    xsltFreeStylesheet(style);
}

int never_called_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, ref);
    fail_msg("never_called_blob_file_writer was called with path %s and ref %s\n", path, ref_str);
    return evr_error;
}

#define attr_factory_fail_flag_file_path "attr-factory-fail.flag"

void one_attr_factory_blob_file_writer_should_fail(struct evr_attr_index_db *db, int should_fail){
    if(should_fail){
        int f = open(attr_factory_fail_flag_file_path, O_WRONLY | O_CREAT, 0644);
        assert_msg(f >= 0, "Create attr-factory fail flag file failed: %s", strerror(errno));
        assert(close(f) == 0);
    } else {
        if(unlink(attr_factory_fail_flag_file_path) != 0){
            assert_msg(errno == ENOENT, "Failed to delete attr-factory fail flag file: %s", strerror(errno));
        }
    }
}

int one_attr_factory_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    assert(ctx == NULL);
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, ref);
    log_debug("one_attr_factory_blob_file_writer invoked with ref %s and path %s", ref_str, path);
    int fd = creat(path, mode);
    assert(fd >= 0);
    struct evr_file f;
    evr_file_bind_fd(&f, fd);
    char content[] =
        "#!/bin/sh\n"
        "if [ -e '" attr_factory_fail_flag_file_path "' ]\n"
        "then\n"
        "  echo '" attr_factory_fail_flag_file_path " found' >&2\n"
        "  exit 1\n"
        "fi\n"
        "cat <<EOF\n"
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">\n"
        "<attr seed=\"sha3-224-c0000000000000000000000000000000000000000000000000000000-0000\">"
        "<a op=\"+\" k=\"source\" v=\"factory\"/>"
        "</attr>"
        "</claim-set>\n"
        "EOF\n";
    assert(is_ok(write_n(&f, content, sizeof(content) - 1)));
    assert(f.close(&f) == 0);
    return evr_ok;
}

void reset_visit_attrs(){
    found_tag_a = 0;
    found_tag_b = 0;
}

int visit_attrs(void *ctx, const char *key, const char *value){
    assert(ctx == NULL);
    assert(is_str_eq(key, "tag"));
    assert(value != NULL);
    if(strcmp(value, "A") == 0){
        found_tag_a = 1;
    } else if(strcmp(value, "B") == 0){
        found_tag_b = 1;
    } else {
        fail_msg("Unknown tag value visited: %s", value);
    }
    return evr_ok;
}

void assert_attrs(int expected_found_tag_a, int expected_found_tag_b){
    assert_msg(found_tag_a == expected_found_tag_a, "Expected found_a to be %d but was %d\n", expected_found_tag_a, found_tag_a);
    assert_msg(found_tag_b == expected_found_tag_b, "Expected found_b to be %d but was %d\n", expected_found_tag_b, found_tag_b);
}

void reset_visit_claims(){
    found_claim_0 = 0;
}

int claims_status_ok(void *ctx, int parse_res, char *parse_error){
    assert(is_ok(parse_res));
    assert(parse_error == NULL);
    return evr_ok;
}

int visit_claims(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len){
    assert(ctx == NULL);
    evr_claim_ref_str ref_str;
    evr_fmt_claim_ref(ref_str, ref);
    if(strcmp(ref_str, "sha3-224-c0000000000000000000000000000000000000000000000000000000-0000") == 0){
        found_claim_0 = 1;
    }
    assert(attrs == NULL);
    assert(attrs_len == 0);
    return evr_ok;
}

void assert_claims(int expected_found_claim_0){
    assert_msg(found_claim_0 == expected_found_claim_0, "Expected to %shave found claim 0 but found it%s", expected_found_claim_0 ? "" : "not ", found_claim_0 ? "" : " not");
}

struct evr_attr_index_db *create_prepared_attr_index_db(struct evr_attr_index_cfg *cfg, struct evr_attr_spec_claim *custom_spec, evr_blob_file_writer custom_writer){
    evr_blob_file_writer writer = custom_writer ? custom_writer : never_called_blob_file_writer;
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db", writer, NULL);
    assert(db);
    struct evr_attr_spec_claim default_spec;
    default_spec.attr_def_len = 0;
    default_spec.attr_def = NULL;
    default_spec.attr_factories_len = 0;
    default_spec.attr_factories = NULL;
    struct evr_attr_spec_claim *spec = custom_spec ? custom_spec : &default_spec;
    assert(is_ok(evr_setup_attr_index_db(db, spec)));
    assert(is_ok(evr_prepare_attr_index_db(db)));
    return db;
}

void test_add_two_attr_claims_for_same_target(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    struct evr_attr_claim c;
    c.seed_type = evr_seed_type_claim;
    assert(is_ok(evr_parse_claim_ref(c.seed, "sha3-224-10000000000000000000000000000000000000000000000000000000-0001")));
    c.index_seed = 1;
    c.attr_len = 0;
    c.attr = NULL;
    for(int i = 0; i < 2; ++i){
        log_info("Claim merge #%d", i+1);
        assert(is_ok(evr_merge_attr_index_claim(db, 10, c.seed, &c)));
    }
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

void test_get_set_state(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    sqlite3_int64 value = -1;
    assert(is_ok(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &value)));
    assert_msg(value == 0, "Expected initial last_indexed_claim_ts to be 0 but was %lu", value);
    assert(is_ok(evr_attr_index_set_state(db, evr_state_key_last_indexed_claim_ts, 42)));
    value = -1;
    assert(is_ok(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &value)));
    assert_msg(value == 42, "Expected last_indexed_claim_ts to be 42 but was %lu", value);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

void test_setup_attr_index_db_twice(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    assert(is_ok(evr_free_attr_index_db(db)));
    db = create_prepared_attr_index_db(cfg, NULL, NULL);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

int claims_status_syntax_error_calls;

int claims_status_syntax_error(void *ctx, int parse_res, char *parse_error);

void test_query_syntax_error(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    claims_status_syntax_error_calls = 0;
    assert(is_ok(evr_attr_query_claims(db, "tag=todo && tachjen at 1970-01-01T00:00:07.000000Z", claims_status_syntax_error, NULL, NULL)));
    assert(claims_status_syntax_error_calls == 1);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

int claims_status_syntax_error(void *ctx, int parse_res, char *parse_error){
    ++claims_status_syntax_error_calls;
    assert(is_err(parse_res));
    assert(is_str_eq(parse_error, "syntax error, unexpected AT, expecting EQ or CONTAINS"));
    return evr_ok;
}

void assert_query_no_result(struct evr_attr_index_db *db, char *query);
void assert_query_one_result(struct evr_attr_index_db *db, char *query, evr_claim_ref expected_ref);

int visited_seed_refs = 0;

int visit_claims_for_seed(void *ctx, const evr_claim_ref claim);

void test_attr_factories(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    evr_blob_ref attr_factory_ref;
    assert(is_ok(evr_parse_blob_ref(attr_factory_ref, "sha3-224-fac00000000000000000000000000000000000000000000000000000")));
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    spec.attr_factories_len = 1;
    spec.attr_factories = &attr_factory_ref;
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, &spec, one_attr_factory_blob_file_writer);
    one_attr_factory_blob_file_writer_should_fail(db, 0);
    xsltStylesheetPtr style = create_attr_mapping_stylesheet();
    char raw_claim_set_content[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">"
        "<attr>"
        "<a op=\"+\" k=\"source\" v=\"original\"/>"
        "</attr>"
        "</claim-set>";
    xmlDocPtr raw_claim_set = create_xml_doc(raw_claim_set_content);
    evr_blob_ref claim_set_ref;
    assert(is_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000")));
    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, raw_claim_set, 0, NULL)));
    evr_claim_ref static_claim_ref;
    evr_build_claim_ref(static_claim_ref, claim_set_ref, 0);
#define t_str "2022-01-01T00:00:00.000000Z"
    assert_query_one_result(db, "source=original at " t_str, static_claim_ref);
    assert_query_one_result(db, "source=factory at " t_str, static_claim_ref);
#undef t_str
    xmlFreeDoc(raw_claim_set);
    xsltFreeStylesheet(style);
    evr_claim_ref visited_refs[2];
    assert(is_ok(evr_attr_visit_claims_for_seed(db, static_claim_ref, visit_claims_for_seed, visited_refs)));
    assert_msg(visited_seed_refs == 2, "Expected to visit 2 claims for seed but got %d\n", visited_seed_refs);
    evr_claim_ref_str claim_ref_str;
    evr_fmt_claim_ref(claim_ref_str, visited_refs[0]);
    assert(is_str_eq(claim_ref_str, "sha3-224-c0000000000000000000000000000000000000000000000000000000-0000"));
    evr_fmt_claim_ref(claim_ref_str, visited_refs[1]);
    assert(is_str_eq(claim_ref_str, "sha3-224-c0000000000000000000000000000000000000000000000000000000-0001"));
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

xmlDocPtr get_claim_set_adapter(void *ctx, evr_blob_ref claim_set_ref){
    char *claim_set_content = ctx;
    return create_xml_doc(claim_set_content);
}

void test_attr_factories_fail_and_reindex(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    evr_blob_ref attr_factory_ref;
    assert(is_ok(evr_parse_blob_ref(attr_factory_ref, "sha3-224-fac00000000000000000000000000000000000000000000000000000")));
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    spec.attr_factories_len = 1;
    spec.attr_factories = &attr_factory_ref;
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, &spec, one_attr_factory_blob_file_writer);
    one_attr_factory_blob_file_writer_should_fail(db, 1);
    xsltStylesheetPtr style = create_attr_mapping_stylesheet();
    char raw_claim_set_content[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">"
        "</claim-set>";
    xmlDocPtr raw_claim_set = create_xml_doc(raw_claim_set_content);
    evr_blob_ref claim_set_ref;
    assert(is_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000")));
    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, raw_claim_set, 0, NULL)));
    xmlFreeDoc(raw_claim_set);
    evr_claim_ref static_claim_ref;
    evr_build_claim_ref(static_claim_ref, claim_set_ref, 0);
    assert_query_no_result(db, "at 2022-01-01T00:00:00.000000Z");
    one_attr_factory_blob_file_writer_should_fail(db, 0);
    assert(is_ok(evr_reindex_failed_claim_sets(db, &spec, style, 30, get_claim_set_adapter, raw_claim_set_content, NULL)));
    assert_query_no_result(db, "at 2022-01-01T00:00:00.000000Z");
    assert(is_ok(evr_reindex_failed_claim_sets(db, &spec, style, 60*60*1000, get_claim_set_adapter, raw_claim_set_content, NULL)));
    xsltFreeStylesheet(style);
    assert_query_one_result(db, "at 2022-01-01T00:00:00.000000Z", static_claim_ref);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

int visit_claims_for_seed(void *ctx, const evr_claim_ref claim){
    evr_claim_ref *visited_refs = ctx;
    memcpy(visited_refs[visited_seed_refs], claim, evr_claim_ref_size);
    visited_seed_refs++;
    return evr_ok;
}

void test_attr_attribute_factories(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    spec.attr_factories_len = 0;
    spec.attr_factories = NULL;
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, &spec, never_called_blob_file_writer);
    xsltStylesheetPtr style = create_attr_mapping_stylesheet();
    char raw_claim_set_content[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">"
        "<attr>"
        "<a op=\"=\" k=\"my-key\" v=\"ye-value\"/>"
        "<a op=\"=\" k=\"my-static-key\" vf=\"static\" v=\"ye-value\"/>"
        "<a op=\"=\" k=\"my-claim-ref-key\" vf=\"claim-ref\"/>"
        // the following line tests a query bug which was caused by
        // the dot in the file name.
        "<a op=\"=\" k=\"title\" v=\"win10.jpg\"/>"
        "</attr>"
        "</claim-set>";
    xmlDocPtr raw_claim_set = create_xml_doc(raw_claim_set_content);
    evr_blob_ref claim_set_ref;
    assert(is_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000")));
    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, raw_claim_set, 0, NULL)));
    evr_claim_ref attr_claim_ref;
    evr_build_claim_ref(attr_claim_ref, claim_set_ref, 0);
#define t_str "2022-01-01T00:00:00.000000Z"
    assert_query_one_result(db, "my-key=ye-value at " t_str, attr_claim_ref);
    assert_query_one_result(db, "my-static-key=ye-value at " t_str, attr_claim_ref);
    assert_query_one_result(db, "my-claim-ref-key=sha3-224-c0000000000000000000000000000000000000000000000000000000-0000 at " t_str, attr_claim_ref);
    assert_query_one_result(db, "title=win10.jpg at " t_str, attr_claim_ref);
#undef t_str
    xmlFreeDoc(raw_claim_set);
    xsltFreeStylesheet(style);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_cfg(cfg);
}

void test_attr_value_type_self_claim_ref(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    spec.attr_factories_len = 0;
    spec.attr_factories = NULL;
    memset(spec.transformation_blob_ref, 0, evr_blob_ref_size);
    xsltStylesheetPtr style = create_attr_mapping_stylesheet();
#define seed_str "sha3-224-00000000000000000000000000000000000000000000000000000000-0000"
    char doc_str[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:00.000000Z\">"
        "<attr seed=\"" seed_str "\">"
        "<a op=\"=\" k=\"my-key\" vf=\"claim-ref\"/>"
        "</attr>"
        "</claim-set>";
    xmlDoc *claim_set_doc = create_xml_doc(doc_str);
    assert(claim_set_doc);
    evr_blob_ref claim_set_ref;
    assert(is_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000")));
    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, claim_set_doc, 0, NULL)));
    xmlFreeDoc(claim_set_doc);
    evr_claim_ref seed;
    assert(is_ok(evr_parse_claim_ref(seed, seed_str)));
#undef seed_str
    assert_query_one_result(db, "my-key=sha3-224-c0000000000000000000000000000000000000000000000000000000-0000 at 1970-01-01T00:00:00.020000Z", seed);
    assert_query_one_result(db, "at 1970-01-01T00:00:00.020000Z", seed);
    assert_query_one_result(db, "my-key~224 at 1970-01-01T00:00:00.020000Z", seed);
    assert_query_one_result(db, "my-key~SHA at 1970-01-01T00:00:00.020000Z", seed);
    assert(is_ok(evr_free_attr_index_db(db)));
    xsltFreeStylesheet(style);
    evr_free_attr_index_cfg(cfg);
}

void test_attr_type_claim_ref_invalid_value(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_def defs[] = {
        {
            "my-ref", evr_type_claim_ref
        },
    };
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 1;
    spec.attr_def = defs;
    spec.attr_factories_len = 0;
    spec.attr_factories = NULL;
    memset(spec.transformation_blob_ref, 0, evr_blob_ref_size);
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, &spec, NULL);
    xsltStylesheetPtr style = create_attr_mapping_stylesheet();
#define seed_str "sha3-224-00000000000000000000000000000000000000000000000000000000-0000"
    char doc_str[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:00.000000Z\">"
        "<attr seed=\"" seed_str "\">"
        "<a op=\"=\" k=\"my-ref\" v=\"sha3-224-whatever-0000\"/>"
        "</attr>"
        "</claim-set>";
    xmlDoc *claim_set_doc = create_xml_doc(doc_str);
    assert(claim_set_doc);
    evr_blob_ref claim_set_ref;
    assert(is_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000")));
    assert(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, claim_set_doc, 0, NULL) == evr_user_data_invalid);
    xmlFreeDoc(claim_set_doc);
    evr_claim_ref seed;
    assert(is_ok(evr_parse_claim_ref(seed, seed_str)));
#undef seed_str
    assert_query_no_result(db, "my-ref=sha3-224-whatever-0000 at 1970-01-01T00:00:00.020000Z");
    assert(is_ok(evr_free_attr_index_db(db)));
    xsltFreeStylesheet(style);
    evr_free_attr_index_cfg(cfg);
}

void test_failed_transformation(){
    struct evr_attr_index_cfg *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    spec.attr_factories_len = 0;
    spec.attr_factories = NULL;
    memset(spec.transformation_blob_ref, 0, evr_blob_ref_size);
    char style_str[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:evr=\"https://evr.ma300k.de/claims/\">"
        "<xsl:output encoding=\"UTF-8\"/>"
        "<xsl:template match=\"/evr:claim-set\"><xsl:call-template name=\"no-such-template\"/></xsl:template>"
        "</xsl:stylesheet>";
    xmlDocPtr style_doc = create_xml_doc(style_str);
    xsltStylesheetPtr style = xsltParseStylesheetDoc(style_doc);
    assert(style);
    char doc_str[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">"
        "</claim-set>";
    xmlDoc *claim_set_doc = create_xml_doc(doc_str);
    assert(claim_set_doc);
    evr_blob_ref claim_set_ref;
    assert(is_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000")));
    assert(is_err(evr_merge_attr_index_claim_set(db, &spec, style, 0, claim_set_ref, claim_set_doc, 0, NULL)));
    xmlFreeDoc(claim_set_doc);
    const size_t state_dir_path_len = strlen(cfg->state_dir_path);
    const char log_path_suffix[] = "/ye-db/claim-logs/00/sha3-224-c0000000000000000000000000000000000000000000000000000000.log";
    char log_path[state_dir_path_len + sizeof(log_path_suffix)];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, log_path);
    evr_push_n(&bp, cfg->state_dir_path, state_dir_path_len);
    evr_push_n(&bp, log_path_suffix, sizeof(log_path_suffix));
    assert(path_exists(log_path));
    assert(is_ok(evr_free_attr_index_db(db)));
    xsltFreeStylesheet(style);
    evr_free_attr_index_cfg(cfg);
}

xsltStylesheetPtr create_attr_mapping_stylesheet(){
    char content[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:evr=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" >"
        "<xsl:output encoding=\"UTF-8\"/>"
        "<xsl:template match=\"/evr:claim-set\"><evr:claim-set dc:created=\"{@dc:created}\"><xsl:apply-templates/></evr:claim-set></xsl:template>"
        "<xsl:template match=\"evr:attr\"><xsl:copy-of select=\".\"/></xsl:template>"
        "<xsl:template match=\"evr:archive\"><xsl:copy-of select=\".\"/></xsl:template>"
        "</xsl:stylesheet>";
    xmlDocPtr doc = create_xml_doc(content);
    xsltStylesheetPtr style = xsltParseStylesheetDoc(doc);
    assert_msg(style, "Failed to parse attr mapping XML document as stylesheet", NULL);
    return style;
}

xmlDocPtr create_xml_doc(char *content){
    xmlDocPtr doc = NULL;
    assert_msg(is_ok(evr_parse_xml(&doc, content, strlen(content))), "Failed to parse XML document: %s", content);
    return doc;
}

void assert_query_no_result(struct evr_attr_index_db *db, char *query){
    log_info("Asserting query '%s' has no results", query);
    asserting_claims_visitor_calls = 0;
    memset(asserting_claims_visitor_expected_ref, 0, evr_claim_ref_size);
    assert(is_ok(evr_attr_query_claims(db, query, claims_status_ok, asserting_claims_visitor, NULL)));
    assert_msg(asserting_claims_visitor_calls == 0, "Claims found but expected none for query: %s", query);
}

void assert_query_one_result(struct evr_attr_index_db *db, char *query, evr_claim_ref expected_ref){
    log_info("Asserting query '%s' has one result", query);
    asserting_claims_visitor_calls = 0;
    memcpy(asserting_claims_visitor_expected_ref, expected_ref, evr_claim_ref_size);
    assert(is_ok(evr_attr_query_claims(db, query, claims_status_ok, asserting_claims_visitor, NULL)));
    assert_msg(asserting_claims_visitor_calls == 1, "No claim found but expected one", NULL);
}

int asserting_claims_visitor(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len){
    ++asserting_claims_visitor_calls;
    assert(ctx == NULL);
    int ref_cmp = evr_cmp_claim_ref(ref, asserting_claims_visitor_expected_ref);
    evr_claim_ref_str ref_str, asserting_claims_visitor_expected_ref_str;
    evr_fmt_claim_ref(ref_str, ref);
    evr_fmt_claim_ref(asserting_claims_visitor_expected_ref_str, asserting_claims_visitor_expected_ref);
    assert_msg(ref_cmp == 0, "Expected claim ref to be %s but was %s\n", asserting_claims_visitor_expected_ref_str, ref_str);
    assert(attrs_len == 0);
    return evr_ok;
}

xmlNode *evr_append_claim_set(xmlDoc *doc);

void test_move_claims_without_claimsets(){
    xmlDoc *src = xmlNewDoc(BAD_CAST "1.0");
    assert(src);
    xmlDoc *dst = xmlNewDoc(BAD_CAST "1.0");
    assert(dst);
    assert(evr_move_claims(dst, src, "ye-dst", "ye-src") == evr_error);
    evr_append_claim_set(dst);
    assert(evr_move_claims(dst, src, "ye-dst", "ye-src") == evr_error);
    xmlFreeDoc(dst);
    xmlFreeDoc(src);
}

size_t evr_count_claims(xmlNode *cs);

void test_move_claims_with_one_claim(){
    xmlDoc *src = xmlNewDoc(BAD_CAST "1.0");
    assert(src);
    xmlDoc *dst = xmlNewDoc(BAD_CAST "1.0");
    assert(dst);
    xmlNode *scs = evr_append_claim_set(src);
    xmlNode *dcs = evr_append_claim_set(dst);
    // merge two empty claim-sets
    assert(is_ok(evr_move_claims(dst, src, "ye-dst", "ye-src")));
    assert(evr_first_claim(scs) == NULL);
    assert(evr_first_claim(dcs) == NULL);
    // add one claim to source and merge
    xmlNode *c = xmlNewNode(NULL, BAD_CAST "attr");
    assert(c);
    assert(xmlAddChild(scs, c));
    assert(evr_count_claims(scs) == 1);
    assert(evr_count_claims(dcs) == 0);
    assert(is_ok(evr_move_claims(dst, src, "ye-dst", "ye-src")));
    assert(evr_count_claims(scs) == 0);
    assert(evr_count_claims(dcs) == 1);
    xmlFreeDoc(dst);
    xmlFreeDoc(src);
}

void test_move_claims_with_two_claims(){
    size_t count;
    xmlDoc *src = xmlNewDoc(BAD_CAST "1.0");
    assert(src);
    xmlDoc *dst = xmlNewDoc(BAD_CAST "1.0");
    assert(dst);
    xmlNode *scs = evr_append_claim_set(src);
    xmlNode *dcs = evr_append_claim_set(dst);
    char buf[2];
    int res;
    const int claim_count = 2;
    for(int i = 0; i < claim_count; ++i){
        xmlNode *c = xmlNewNode(NULL, BAD_CAST "attr");
        assert(c);
        res = snprintf(buf, sizeof(buf), "%d", i);
        assert(res >= 0 && res < (int)sizeof(buf));
        assert(xmlSetProp(c, BAD_CAST "index", BAD_CAST buf));
        assert(xmlAddChild(scs, c));
    }
    assert(evr_count_claims(scs) == claim_count);
    assert(evr_count_claims(dcs) == 0);
    assert(is_ok(evr_move_claims(dst, src, "ye-dst", "ye-src")));
    count = evr_count_claims(scs);
    assert_msg(count == 0, "But was %zu", count);
    assert(evr_count_claims(dcs) == claim_count);
    xmlNode *c = evr_first_claim(dcs);
    for(int i = 0; i < claim_count; ++i){
        assert(c);
        char *index = (char*)xmlGetProp(c, BAD_CAST "index");
        assert(index);
        res = snprintf(buf, sizeof(buf), "%d", i);
        assert(res >= 0 && res < (int)sizeof(buf));
        assert_msg(strcmp(index, buf) == 0, "But %s != %s", index, buf);
        xmlFree(index);
        c = evr_next_claim(c);
    }
    xmlFreeDoc(dst);
    xmlFreeDoc(src);
}

size_t evr_count_claims(xmlNode *cs){
    size_t count = 0;
    for(xmlNode *it = evr_first_claim(cs); it; it = evr_next_claim(it)){
        ++count;
    }
    return count;
}

xmlNode *evr_append_claim_set(xmlDoc *doc){
    xmlNode *cs = xmlNewNode(NULL, BAD_CAST "claim-set");
    assert(cs);
    xmlDocSetRootElement(doc, cs);
    xmlNs *ns = xmlNewNs(cs, BAD_CAST evr_claims_ns, NULL);
    assert(ns);
    xmlSetNs(cs, ns);
    return cs;
}

int main(){
    evr_init_basics();
    run_test(test_open_new_attr_index_db_twice);
    run_test(test_add_two_attr_claims_for_same_target);
    run_test(test_get_set_state);
    run_test(test_setup_attr_index_db_twice);
    run_test(test_query_syntax_error);
    run_test(test_attr_factories);
    run_test(test_attr_factories_fail_and_reindex);
    run_test(test_attr_attribute_factories);
    run_test(test_attr_value_type_self_claim_ref);
    run_test(test_attr_type_claim_ref_invalid_value);
    run_test(test_failed_transformation);
    run_test(test_move_claims_without_claimsets);
    run_test(test_move_claims_with_one_claim);
    run_test(test_move_claims_with_two_claims);
    return 0;
}
