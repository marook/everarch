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

#include "assert.h"
#include "configuration-testutil.h"
#include "errors.h"
#include "test.h"
#include "logger.h"
#include "attr-index-db.h"

#define permutations 3
#define merge_attrs_len 3

int found_tag_a = 0;
int found_tag_b = 0;

void reset_visit_attrs();
int visit_attrs(const evr_blob_ref ref, const char *key, const char *value);
void assert_attrs(int expected_found_tag_a, int expected_found_tag_b);
void assert_tag_eq(int actual, int expected, char *name);

void test_open_new_attr_index_db_twice(){
    const time_t merge_attrs_t[merge_attrs_len] = {
        10,
        20,
        30,
    };
    struct evr_attr merge_attrs[merge_attrs_len] = {
        { evr_attr_op_replace, "tag", "A" },
        { evr_attr_op_add, "tag", "B" },
        { evr_attr_op_rm, "tag", NULL },
    };
    const int attr_merge_permutations[permutations][merge_attrs_len] = {
        { 0, 1, 2 },
        { 1, 0, 2 },
        { 2, 1, 0 },
    };
    evr_blob_ref ref;
    evr_parse_blob_ref(ref, "sha3-224-10000000000000000000000000000000000000000000000000000000");
    evr_blob_ref other_ref;
    evr_parse_blob_ref(other_ref, "sha3-224-00000000000000000000000000000000000000000000000000000001");
    for(size_t pi = 0; pi < permutations; ++pi){
        log_info("Permutation %d…", pi);
        struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
        for(int round = 0; round < 2; ++round){
            log_info("Round %d…", round);
            struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db");
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
                memset(spec.stylesheet_blob_ref, 0, evr_blob_ref_size);
                assert_ok_msg(evr_setup_attr_index_db(db, &spec), "evr_setup_attr_index_db failed\n");
            }
            assert_ok_msg(evr_prepare_attr_index_db(db), "evr_prepare_attr_index_db failed\n");
            if(round == 0){
                for(size_t rai = 0; rai < merge_attrs_len; ++rai){
                    size_t aai = attr_merge_permutations[pi][rai];
                    time_t t = merge_attrs_t[aai];
                    struct evr_attr *attr = &merge_attrs[aai];
                    assert_ok(evr_merge_attr_index_attr(db, t, ref, attr, 1));
                }
            }
            log_info("Assert t=0");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 0, ref, visit_attrs));
            assert_attrs(0, 0);
            log_info("Assert t=10");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 10, ref, visit_attrs));
            assert_attrs(1, 0);
            log_info("Assert t=15");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 15, ref, visit_attrs));
            assert_attrs(1, 0);
            log_info("Assert t=20");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 20, ref, visit_attrs));
            assert_attrs(1, 1);
            log_info("Assert t=25");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 25, ref, visit_attrs));
            assert_attrs(1, 1);
            log_info("Assert t=30");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 30, ref, visit_attrs));
            assert_attrs(0, 0);
            log_info("Assert t=35");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 35, ref, visit_attrs));
            assert_attrs(0, 0);
            log_info("Assert not existing ref");
            reset_visit_attrs();
            assert_ok(evr_get_ref_attrs(db, 25, other_ref, visit_attrs));
            assert_attrs(0, 0);
            assert_ok(evr_free_glacier_index_db(db));
        }
        evr_free_attr_index_db_configuration(cfg);
    }
}

void reset_visit_attrs(){
    found_tag_a = 0;
    found_tag_b = 0;
}

int visit_attrs(const evr_blob_ref ref, const char *key, const char *value){
    evr_blob_ref_str fmt_ref;
    evr_fmt_blob_ref(fmt_ref, ref);
    assert_str_eq(fmt_ref, "sha3-224-10000000000000000000000000000000000000000000000000000000");
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

void test_add_two_attr_claims_for_same_target(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db");
    struct evr_attr_spec_claim spec;
    spec.attr_def_len = 0;
    spec.attr_def = NULL;
    assert_ok_msg(evr_setup_attr_index_db(db, &spec), "evr_setup_attr_index_db failed\n");
    assert_ok_msg(evr_prepare_attr_index_db(db), "evr_prepare_attr_index_db failed\n");
    struct evr_attr_claim c;
    c.ref_type = evr_ref_type_blob;
    assert_ok(evr_parse_blob_ref(c.ref, "sha3-224-10000000000000000000000000000000000000000000000000000000"));
    c.claim_index = 1;
    c.attr_len = 0;
    c.attr = NULL;
    for(int i = 0; i < 2; ++i){
        log_info("Claim merge #%d", i+1);
        assert_ok(evr_merge_attr_index_claim(db, 10, &c));
    }
    assert_ok(evr_free_glacier_index_db(db));
    evr_free_attr_index_db_configuration(cfg);
}

int main(){
    run_test(test_open_new_attr_index_db_twice);
    run_test(test_add_two_attr_claims_for_same_target);
    return 0;
}
