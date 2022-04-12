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
int visit_attrs(void *ctx, const evr_claim_ref ref, const char *key, const char *value);
void assert_attrs(int expected_found_tag_a, int expected_found_tag_b);
void reset_visit_claims();
int claims_status_ok(void *ctx, int parse_res);
int visit_claims(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len);
void assert_claims(int expected_found_claim_0);
struct evr_attr_index_db *create_prepared_attr_index_db(struct evr_attr_index_db_configuration *cfg, struct evr_attr_spec_claim *custom_spec, evr_blob_file_writer custom_writer);

void test_open_new_attr_index_db_twice(){
    const evr_time merge_attrs_t[merge_attrs_len] = {
        10,
        20,
        30,
    };
    struct evr_attr merge_attrs[merge_attrs_len] = {
        { evr_attr_op_replace, { "tag", "A" } },
        { evr_attr_op_add, { "tag", "B" } },
        { evr_attr_op_rm, { "tag", NULL } },
    };
    const int attr_merge_permutations[permutations][merge_attrs_len] = {
        { 0, 1, 2 },
        { 1, 0, 2 },
        { 2, 1, 0 },
    };
    evr_claim_ref ref;
    assert_ok(evr_parse_claim_ref(ref, "sha3-224-10000000000000000000000000000000000000000000000000000000-0000"));
    evr_claim_ref other_ref;
    assert_ok(evr_parse_claim_ref(other_ref, "sha3-224-00000000000000000000000000000000000000000000000000000001-0000"));
    for(size_t pi = 0; pi < permutations; ++pi){
        log_info("Permutation %d…", pi);
        struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
        for(int round = 0; round < 2; ++round){
            log_info("Round %d…", round);
            struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db", never_called_blob_file_writer, NULL);
            assert_not_null(db);
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
                assert_ok_msg(evr_setup_attr_index_db(db, &spec), "evr_setup_attr_index_db failed\n");
            }
            assert_ok_msg(evr_prepare_attr_index_db(db), "evr_prepare_attr_index_db failed\n");
            if(round == 0){
                for(size_t rai = 0; rai < merge_attrs_len; ++rai){
                    size_t aai = attr_merge_permutations[pi][rai];
                    evr_time t = merge_attrs_t[aai];
                    struct evr_attr_claim claim;
                    claim.ref_type = evr_ref_type_claim;
                    evr_build_claim_ref(claim.ref, ref, 0);
                    claim.claim_index = 0;
                    claim.attr_len = 1;
                    claim.attr = &merge_attrs[aai];
                    assert_ok(evr_merge_attr_index_claim(db, t, &claim));
                }
            }
            log_info("Assert t=0");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 0, ref, visit_attrs, NULL));
            assert_attrs(0, 0);
            log_info("Assert t=10");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 10, ref, visit_attrs, NULL));
            assert_attrs(1, 0);
            log_info("Assert t=15");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 15, ref, visit_attrs, NULL));
            assert_attrs(1, 0);
            log_info("Assert t=20");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 20, ref, visit_attrs, NULL));
            assert_attrs(1, 1);
            log_info("Assert t=25");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 25, ref, visit_attrs, NULL));
            assert_attrs(1, 1);
            log_info("Assert t=30");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 30, ref, visit_attrs, NULL));
            assert_attrs(0, 0);
            log_info("Assert t=35");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 35, ref, visit_attrs, NULL));
            assert_attrs(0, 0);
            log_info("Assert not existing ref");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 25, other_ref, visit_attrs, NULL));
            assert_attrs(0, 0);
            log_info("Assert evr_attr_query_claims tag=A t=0");
            reset_visit_claims();
            assert_ok(evr_attr_query_claims(db, "tag=A", 0, 0, 100, claims_status_ok, visit_claims, NULL));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A t=25");
            reset_visit_claims();
            assert_ok(evr_attr_query_claims(db, "tag=A", 25, 0, 100, claims_status_ok, visit_claims, NULL));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=X t=25");
            reset_visit_claims();
            assert_ok(evr_attr_query_claims(db, "tag=X", 25, 0, 100, claims_status_ok, visit_claims, NULL));
            assert_claims(0);
            log_info("Assert evr_attr_query_claims tag=A && tag=B t=25");
            reset_visit_claims();
            assert_ok(evr_attr_query_claims(db, "tag=A && tag=B", 25, 0, 100, claims_status_ok, visit_claims, NULL));
            assert_claims(1);
            log_info("Assert evr_attr_query_claims tag=A && tag=B t=15");
            reset_visit_claims();
            assert_ok(evr_attr_query_claims(db, "tag=A && tag=B", 15, 0, 100, claims_status_ok, visit_claims, NULL));
            assert_claims(0);
            assert_ok(evr_free_attr_index_db(db));
        }
        evr_free_attr_index_db_configuration(cfg);
    }
}

int never_called_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, ref);
    fail("never_called_blob_file_writer was called with path %s and ref %s\n", path, ref_str);
    return evr_error;
}

int one_attr_factory_blob_file_writer(void *ctx, char *path, mode_t mode, evr_blob_ref ref){
    assert_null(ctx);
    evr_blob_ref_str ref_str;
    evr_fmt_blob_ref(ref_str, ref);
    log_debug("one_attr_factory_blob_file_writer invoked with ref %s and path %s", ref_str, path);
    int f = creat(path, mode);
    if(f < 0){
        fail("Failed to create one_attr_factory_blob_file_writer file\n");
        return evr_error;
    }
    char content[] =
        "#!/bin/sh\n"
        "cat <<EOF\n"
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set xmlns=\"https://evr.ma300k.de/claims/\" xmlns:dc=\"http://purl.org/dc/terms/\" dc:created=\"1970-01-01T00:00:07.000000Z\">\n"
        "<attr claim=\"0\">"
        "<a op=\"+\" k=\"source\" v=\"factory\"/>"
        "</attr>"
        "</claim-set>\n"
        "EOF\n";
    assert_ok(write_n(f, content, sizeof(content) - 1));
    assert_zero(close(f));
    return evr_ok;
}

void reset_visit_attrs(){
    found_tag_a = 0;
    found_tag_b = 0;
}

int visit_attrs(void *ctx, const evr_claim_ref ref, const char *key, const char *value){
    assert_null(ctx);
    evr_claim_ref_str fmt_ref;
    evr_fmt_claim_ref(fmt_ref, ref);
    assert_str_eq(fmt_ref, "sha3-224-10000000000000000000000000000000000000000000000000000000-0000");
    assert_str_eq(key, "tag");
    assert_not_null(value);
    if(strcmp(value, "A") == 0){
        found_tag_a = 1;
    } else if(strcmp(value, "B") == 0){
        found_tag_b = 1;
    } else {
        fail("Unknown tag value visited: %s", value);
    }
    return evr_ok;
}

void assert_attrs(int expected_found_tag_a, int expected_found_tag_b){
    assert_int_eq_msg(found_tag_a, expected_found_tag_a, "Expected found_a to be %d but was %d\n", expected_found_tag_a, found_tag_a);
    assert_int_eq_msg(found_tag_b, expected_found_tag_b, "Expected found_b to be %d but was %d\n", expected_found_tag_b, found_tag_b);
}

void reset_visit_claims(){
    found_claim_0 = 0;
}

int claims_status_ok(void *ctx, int parse_res){
    assert_ok(parse_res);
    return evr_ok;
}

int visit_claims(void *ctx, const evr_claim_ref ref, struct evr_attr_tuple *attrs, size_t attrs_len){
    assert_null(ctx);
    evr_claim_ref_str ref_str;
    evr_fmt_claim_ref(ref_str, ref);
    if(strcmp(ref_str, "sha3-224-10000000000000000000000000000000000000000000000000000000-0000") == 0){
        found_claim_0 = 1;
    }
    assert_null(attrs);
    assert_int_eq(attrs_len, 0);
    return evr_ok;
}

void assert_claims(int expected_found_claim_0){
    assert_int_eq_msg(found_claim_0, expected_found_claim_0, "Expected to have found claim 0");
}

struct evr_attr_index_db *create_prepared_attr_index_db(struct evr_attr_index_db_configuration *cfg, struct evr_attr_spec_claim *custom_spec, evr_blob_file_writer custom_writer){
    evr_blob_file_writer writer = custom_writer ? custom_writer : never_called_blob_file_writer;
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db", writer, NULL);
    assert_not_null(db);
    struct evr_attr_spec_claim default_spec;
    default_spec.attr_def_len = 0;
    default_spec.attr_def = NULL;
    default_spec.attr_factories_len = 0;
    default_spec.attr_factories = NULL;
    struct evr_attr_spec_claim *spec = custom_spec ? custom_spec : &default_spec;
    assert_ok_msg(evr_setup_attr_index_db(db, spec), "evr_setup_attr_index_db failed\n");
    assert_ok_msg(evr_prepare_attr_index_db(db), "evr_prepare_attr_index_db failed\n");
    return db;
}

void test_add_two_attr_claims_for_same_target(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    struct evr_attr_claim c;
    c.ref_type = evr_ref_type_claim;
    assert_ok(evr_parse_claim_ref(c.ref, "sha3-224-10000000000000000000000000000000000000000000000000000000-0001"));
    c.claim_index = 1;
    c.attr_len = 0;
    c.attr = NULL;
    for(int i = 0; i < 2; ++i){
        log_info("Claim merge #%d", i+1);
        assert_ok(evr_merge_attr_index_claim(db, 10, &c));
    }
    assert_ok(evr_free_attr_index_db(db));
    evr_free_attr_index_db_configuration(cfg);
}

void test_get_set_state(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    sqlite3_int64 value = -1;
    assert_ok(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &value));
    assert_int_eq_msg(value, 0, "Expected initial last_indexed_claim_ts to be 0 but was %lu\n", value);
    assert_ok(evr_attr_index_set_state(db, evr_state_key_last_indexed_claim_ts, 42));
    value = -1;
    assert_ok(evr_attr_index_get_state(db, evr_state_key_last_indexed_claim_ts, &value));
    assert_int_eq_msg(value, 42, "Expected last_indexed_claim_ts to be 42 but was %lu\n", value);
    assert_ok(evr_free_attr_index_db(db));
    evr_free_attr_index_db_configuration(cfg);
}

void test_setup_attr_index_db_twice(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = create_prepared_attr_index_db(cfg, NULL, NULL);
    assert_ok(evr_free_attr_index_db(db));
    db = create_prepared_attr_index_db(cfg, NULL, NULL);
    assert_ok(evr_free_attr_index_db(db));
    evr_free_attr_index_db_configuration(cfg);
}

xsltStylesheetPtr create_attr_mapping_stylesheet();
xmlDocPtr create_xml_doc(char *content);

void test_attr_factories(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    evr_blob_ref attr_factory_ref;
    assert_ok(evr_parse_blob_ref(attr_factory_ref, "sha3-224-fac00000000000000000000000000000000000000000000000000000"));
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
    assert_ok(evr_parse_blob_ref(claim_set_ref, "sha3-224-c0000000000000000000000000000000000000000000000000000000"));
    evr_time t;
    assert_ok(evr_time_from_iso8601(&t, "2022-01-01T00:00:00.000000Z"));
    assert_ok(evr_merge_attr_index_claim_set(db, &spec, style, claim_set_ref, t, raw_claim_set));
    // TODO assert
    xmlFreeDoc(raw_claim_set);
    xsltFreeStylesheet(style);
    assert_ok(evr_free_attr_index_db(db));
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
    assert_not_null_msg(style, "Failed to parse attr mapping XML document as stylesheet");
    return style;
}

xmlDocPtr create_xml_doc(char *content){
    xmlDocPtr doc = evr_parse_claim_set(content, strlen(content));
    assert_not_null_msg(doc, "Failed to parse XML document: %s", content);
    return doc;
}

int main(){
    run_test(test_open_new_attr_index_db_twice);
    run_test(test_add_two_attr_claims_for_same_target);
    run_test(test_get_set_state);
    run_test(test_setup_attr_index_db_twice);
    run_test(test_attr_factories);
    return 0;
}
