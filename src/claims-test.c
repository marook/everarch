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
#include "claims.h"
#include "test.h"
#include "keys.h"

time_t t0 = 0;

void assert_file_claim(const struct evr_file_claim *claim, const char *expected_file_document);

void test_empty_claim_without_finalize(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    assert_ok(evr_free_claim_set(&cs));
}

void test_empty_claim(){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    assert_ok(evr_finalize_claim_set(&cs));
    assert_str_eq((char*)cs.out->content, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<claim-set dc:created=\"1970-01-01T00:00:00Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\"/>\n");
    assert_ok(evr_free_claim_set(&cs));
}

void test_file_claim_with_filename(){
    struct evr_file_slice slice;
    memset(slice.ref, 0, sizeof(slice.ref));
    slice.size = 1;
    const struct evr_file_claim claim = {
        "test.txt",
        1,
        &slice,
    };
    assert_file_claim(&claim, "<file dc:title=\"test.txt\"><body><slice ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\" size=\"1\"/></body></file>");
}

void test_file_claim_with_null_filename(){
    struct evr_file_slice slice;
    memset(slice.ref, 0, sizeof(slice.ref));
    slice.size = 1;
    const struct evr_file_claim claim = {
        NULL,
        1,
        &slice,
    };
    assert_file_claim(&claim, "<file><body><slice ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\" size=\"1\"/></body></file>");
}

void test_file_claim_with_empty_filename(){
    struct evr_file_slice slice;
    memset(slice.ref, 0, sizeof(slice.ref));
    slice.size = 1;
    const struct evr_file_claim claim = {
        "",
        1,
        &slice,
    };
    assert_file_claim(&claim, "<file><body><slice ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\" size=\"1\"/></body></file>");
}

void assert_file_claim(const struct evr_file_claim *claim, const char *expected_file_document){
    struct evr_claim_set cs;
    assert_ok(evr_init_claim_set(&cs, &t0));
    assert_ok(evr_append_file_claim(&cs, claim));
    assert_ok(evr_finalize_claim_set(&cs));
    char *content = (char*)cs.out->content;
    size_t content_len = strlen(content);
    char *stripped_content = malloc(content_len + 1);
    char *src = content;
    char *dst = stripped_content;
    // 0 = within text
    // 1 = newline followed of only spaces yet
    int state = 0;
    while(1){
        if(*src == '\n'){
            state = 1;
        } else if(*src != ' ' && *src != '\n'){
            state = 0;
        }
        if(state == 0){
            *dst = *src;
            ++dst;
        }
        ++src;
        if(*src == '\0'){
            break;
        }
    }
    assert_not_null(strstr(stripped_content, expected_file_document));
    free(stripped_content);
    assert_ok(evr_free_claim_set(&cs));
}

void test_parse_file_claim_claim_set(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<file dc:title=\"test.txt\"><body><slice ref=\"sha3-224-12300000000000000000000000000000000000000000000000000321\" size=\"1\"/></body></file>"
        "<file xmlns=\"https://evr.ma300k.de/something-which-will-never-ever-exist\"></file>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = evr_parse_claim_set(buf, buf_size);
    assert_not_null(doc);
    time_t created;
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert_not_null(csn);
    assert_ok(evr_parse_created(&created, csn));
    assert_equal(created, 7);
    int file_claims_found = 0;
    int unknown_claims_found = 0;
    for(xmlNode *cn = evr_first_claim(csn); cn; cn = evr_next_claim(cn)){
        if(evr_is_evr_element(cn, "file")){
            ++file_claims_found;
            struct evr_file_claim *c = evr_parse_file_claim(cn);
            assert_not_null(c);
            assert_str_eq(c->title, "test.txt");
            assert_equal(c->slices_len, 1);
            evr_fmt_blob_key_t fmt_key;
            evr_fmt_blob_key(fmt_key, c->slices[0].ref);
            assert_str_eq(fmt_key, "sha3-224-12300000000000000000000000000000000000000000000000000321");
            assert_equal(c->slices[0].size, 1);
            free(c);
        } else {
            ++unknown_claims_found;
        }
    }
    assert_equal_msg(file_claims_found, 1, "No file claims found");
    assert_equal_msg(unknown_claims_found, 1, "No unknown claims found");
    xmlFreeDoc(doc);
}

int main(){
    xmlInitParser();
    run_test(test_empty_claim_without_finalize);
    run_test(test_empty_claim);
    run_test(test_file_claim_with_filename);
    run_test(test_file_claim_with_null_filename);
    run_test(test_file_claim_with_empty_filename);
    run_test(test_parse_file_claim_claim_set);
    xmlCleanupParser();
    return 0;
}
