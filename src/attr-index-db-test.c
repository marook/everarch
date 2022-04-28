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

#include "assert.h"
#include "configuration-testutil.h"
#include "errors.h"
#include "test.h"
#include "logger.h"
#include "attr-index-db.h"
#include "files.h"

#define permutations 3
#define merge_attrs_len 3

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
struct evr_attr_index_db *create_prepared_attr_index_db(struct evr_attr_index_db_configuration *cfg, struct evr_attr_spec_claim *custom_spec, evr_blob_file_writer custom_writer);

int asserting_claims_visitor_calls;
evr_claim_ref asserting_claims_visitor_expected_ref;
int asserting_claims_visitor(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);

void test_open_new_attr_index_db_twice(){
    const evr_time merge_attrs_t[merge_attrs_len] = {
        10,
        20,
        30,
    };
    struct evr_attr merge_attrs[merge_attrs_len] = {
        { evr_attr_op_replace, "tag", evr_attr_value_type_static, "A" },
        { evr_attr_op_add, "tag", evr_attr_value_type_static, "B" },
        { evr_attr_op_rm, "tag", evr_attr_value_type_static, NULL },
    };
    const int attr_merge_permutations[permutations][merge_attrs_len] = {
        { 0, 1, 2 },
        { 1, 0, 2 },
        { 2, 1, 0 },
    };
    evr_claim_ref ref;
    assert(is_ok(evr_parse_claim_ref(ref, "sha3-224-10000000000000000000000000000000000000000000000000000000-0000")));
    evr_claim_ref other_ref;
    assert(is_ok(evr_parse_claim_ref(other_ref, "sha3-224-00000000000000000000000000000000000000000000000000000001-0000")));
    for(size_t pi = 0; pi < permutations; ++pi){
        log_info("Permutation %d…", pi);
        struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
        for(int round = 0; round < 2; ++round){
            log_info("Round %d…", round);
            struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db", never_called_blob_file_writer, NULL);
            assert(db);
            if(round == 0){
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
                assert(is_ok(evr_setup_attr_index_db(db, &spec)));
            }
            assert(is_ok(evr_prepare_attr_index_db(db)));
            if(round == 0){
                for(size_t rai = 0; rai < merge_attrs_len; ++rai){
                    size_t aai = attr_merge_permutations[pi][rai];
                    evr_time t = merge_attrs_t[aai];
                    struct evr_attr_claim claim;
                    claim.seed_type = evr_seed_type_claim;
                    evr_build_claim_ref(claim.seed, ref, 0);
                    claim.index_seed = 0;
                    claim.attr_len = 1;
                    claim.attr = &merge_attrs[aai];
                    assert(is_ok(evr_merge_attr_index_claim(db, t, claim.seed, &claim)));
                }
            }
            log_info("Assert t=0");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 0, ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert t=10");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 10, ref, visit_attrs, NULL)));
            assert_attrs(1, 0);
            log_info("Assert t=15");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 15, ref, visit_attrs, NULL)));
            assert_attrs(1, 0);
            log_info("Assert t=20");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 20, ref, visit_attrs, NULL)));
            assert_attrs(1, 1);
            log_info("Assert t=25");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 25, ref, visit_attrs, NULL)));
            assert_attrs(1, 1);
            log_info("Assert t=30");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 30, ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert t=35");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 35, ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert not existing ref");
            reset_visit_attrs();
            assert(is_ok(evr_get_seed_attrs(db, 25, other_ref, visit_attrs, NULL)));
            assert_attrs(0, 0);
            log_info("Assert evr_attr_query_claims tag=A t=0");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A", 0, 0, 100, claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A", 25, 0, 100, claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=X t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=X", 25, 0, 100, claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A && tag=B t=25");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A && tag=B", 25, 0, 100, claims_status_ok, visit_claims, NULL)));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=A && tag=B t=15");
            reset_visit_claims();
            assert(is_ok(evr_attr_query_claims(db, "tag=A && tag=B", 15, 0, 100, claims_status_ok, visit_claims, NULL)));
            assert_claims(0);
            assert(is_ok(evr_free_attr_index_db(db)));
        }
        evr_free_attr_index_db_configuration(cfg);
    }
}

int never_called_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, ref);
    fail_msg("never_called_blob_file_writer was called with path %s and ref %s\n", path, ref_str);
    return evr_error;
}

int one_attr_factory_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    assert(ctx == NULL);
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, ref);
    log_debug("one_attr_factory_blob_file_writer invoked with ref %s and path %s", ref_str, path);
    int f = creat(path, mode);
    assert_msg(f >= 0, "Failed to create one_attr_factory_blob_file_writer file: %d", f);
    char content[] =
        "#!/bin/sh\n"
        "cat <<EOF\n"
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">\n"
        "<attr seed=\"sha3-224-c0000000000000000000000000000000000000000000000000000000-0000\">"
        "<a op=\"+\" k=\"source\" v=\"factory\"/>"
        "</attr>"
        "</claim-set>\n"
        "EOF\n";
    assert(is_ok(write_n(f, content, sizeof(content) - 1)));
    assert(close(f) == 0);
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
    if(strcmp(ref_str, "sha3-224-10000000000000000000000000000000000000000000000000000000-0000") == 0){
        found_claim_0 = 1;
    }
    assert(attrs == NULL);
    assert(attrs_len == 0);
    return evr_ok;
}

void assert_claims(int expected_found_claim_0){
    assert_msg(found_claim_0 == expected_found_claim_0, "Expected to have found claim 0 but found %d", found_claim_0);
}

struct evr_attr_index_db *create_prepared_attr_index_db(struct evr_attr_index_db_configuration *cfg, struct evr_attr_spec_claim *custom_spec, evr_blob_file_writer custom_writer){
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
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
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
    evr_free_attr_index_db_configuration(cfg);
}

void test_get_set_state(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    sqlite3_int64 value = -1;
    assert(is_ok(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &value)));
    assert_msg(value == 0, "Expected initial last_indexed_claim_ts to be 0 but was %lu", value);
    assert(is_ok(evr_attr_index_set_state(db, evr_state_key_last_indexed_claim_ts, 42)));
    value = -1;
    assert(is_ok(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &value)));
    assert_msg(value == 42, "Expected last_indexed_claim_ts to be 42 but was %lu", value);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_db_configuration(cfg);
}

void test_setup_attr_index_db_twice(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    assert(is_ok(evr_free_attr_index_db(db)));
    db = create_prepared_attr_index_db(cfg, NULL, NULL);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_db_configuration(cfg);
}

int claims_status_syntax_error_calls;

int claims_status_syntax_error(void *ctx, int parse_res, char *parse_error);

void test_query_syntax_error(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    claims_status_syntax_error_calls = 0;
    assert(is_ok(evr_attr_query_claims(db, "tag=todo && tachjen", 0, 0, 100, claims_status_syntax_error, NULL, NULL)));
    assert(claims_status_syntax_error_calls == 1);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_db_configuration(cfg);
}

int claims_status_syntax_error(void *ctx, int parse_res, char *parse_error){
    ++claims_status_syntax_error_calls;
    assert(is_err(parse_res));
    assert(is_str_eq(parse_error, "syntax error, unexpected END, expecting EQ"));
    return evr_ok;
}

xsltStylesheetPtr create_attr_mapping_stylesheet();
xmlDocPtr create_xml_doc(char *content);

void assert_query_one_result(struct evr_attr_index_db *db, char *query, time_t t, evr_claim_ref expected_ref);

int visited_seed_refs = 0;

int visit_claims_for_seed(void *ctx, const evr_claim_ref claim);

void test_attr_factories(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    evr_blob_ref attr_factory_ref;
    assert(is_ok(evr_parse_blob_ref(attr_factory_ref, "sha3-224-fac00000000000000000000000000000000000000000000000000000")));
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    spec.attr_factories_len = 1;
    spec.attr_factories = &attr_factory_ref;
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, &spec, one_attr_factory_blob_file_writer);
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
    evr_time t;
    assert(is_ok(evr_time_from_iso8601(&t, "2022-01-01T00:00:00.000000Z")));
    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, claim_set_ref, t, raw_claim_set)));
    evr_claim_ref static_claim_ref;
    evr_build_claim_ref(static_claim_ref, claim_set_ref, 0);
    assert_query_one_result(db, "source=original", t, static_claim_ref);
    assert_query_one_result(db, "source=factory", t, static_claim_ref);
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
    evr_free_attr_index_db_configuration(cfg);
}

int visit_claims_for_seed(void *ctx, const evr_claim_ref claim){
    evr_claim_ref *visited_refs = ctx;
    memcpy(visited_refs[visited_seed_refs], claim, evr_claim_ref_size);
    visited_seed_refs++;
    return evr_ok;
}

void test_attr_attribute_factories(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
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
    evr_time t;
    assert(is_ok(evr_time_from_iso8601(&t, "2022-01-01T00:00:00.000000Z")));
    assert(is_ok(evr_merge_attr_index_claim_set(db, &spec, style, claim_set_ref, t, raw_claim_set)));
    evr_claim_ref attr_claim_ref;
    evr_build_claim_ref(attr_claim_ref, claim_set_ref, 0);
    assert_query_one_result(db, "my-key=ye-value", t, attr_claim_ref);
    assert_query_one_result(db, "my-static-key=ye-value", t, attr_claim_ref);
    assert_query_one_result(db, "my-claim-ref-key=sha3-224-c0000000000000000000000000000000000000000000000000000000-0000", t, attr_claim_ref);
    assert_query_one_result(db, "title=win10.jpg", t, attr_claim_ref);
    xmlFreeDoc(raw_claim_set);
    xsltFreeStylesheet(style);
    assert(is_ok(evr_free_attr_index_db(db)));
    evr_free_attr_index_db_configuration(cfg);
}

xsltStylesheetPtr create_attr_mapping_stylesheet(){
    char content[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" xmlns:evr=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" >"
        "<xsl:output encoding=\"UTF-8\"/>"
        "<xsl:template match=\"/evr:claim-set\"><evr:claim-set dc:created=\"{@dc:created}\"><xsl:apply-templates/></evr:claim-set></xsl:template>"
        "<xsl:template match=\"evr:attr\"><xsl:copy-of select=\".\"/></xsl:template>"
        "</xsl:stylesheet>";
    xmlDocPtr doc = create_xml_doc(content);
    xsltStylesheetPtr style = xsltParseStylesheetDoc(doc);
    assert_msg(style, "Failed to parse attr mapping XML document as stylesheet", NULL);
    return style;
}

xmlDocPtr create_xml_doc(char *content){
    xmlDocPtr doc = evr_parse_claim_set(content, strlen(content));
    assert_msg(doc, "Failed to parse XML document: %s", content);
    return doc;
}

void assert_query_one_result(struct evr_attr_index_db *db, char *query, time_t t, evr_claim_ref expected_ref){
    log_info("Asserting query %s has one result", query);
    asserting_claims_visitor_calls = 0;
    memcpy(asserting_claims_visitor_expected_ref, expected_ref, evr_claim_ref_size);
    assert(is_ok(evr_attr_query_claims(db, query, t, 0, 2, claims_status_ok, asserting_claims_visitor, NULL)));
    assert_msg(asserting_claims_visitor_calls == 1, "No claim found but expected one", NULL);
}

int asserting_claims_visitor(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len){
    ++asserting_claims_visitor_calls;
    assert(ctx == NULL);
    int ref_cmp = memcmp(ref, asserting_claims_visitor_expected_ref, evr_claim_ref_size);
    evr_claim_ref_str ref_str, asserting_claims_visitor_expected_ref_str;
    evr_fmt_claim_ref(ref_str, ref);
    evr_fmt_claim_ref(asserting_claims_visitor_expected_ref_str, asserting_claims_visitor_expected_ref);
    assert_msg(ref_cmp == 0, "Expected claim ref to be %s but was %s\n", asserting_claims_visitor_expected_ref_str, ref_str);
    assert(attrs_len == 0);
    return evr_ok;
}

int main(){
    run_test(test_open_new_attr_index_db_twice);
    run_test(test_add_two_attr_claims_for_same_target);
    run_test(test_get_set_state);
    run_test(test_setup_attr_index_db_twice);
    run_test(test_query_syntax_error);
    run_test(test_attr_factories);
    run_test(test_attr_attribute_factories);
    return 0;
}
