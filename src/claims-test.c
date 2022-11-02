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
#include "errors.h"

evr_time t0 = 0;

void assert_file_claim(const struct evr_file_claim *claim, const char *expected_file_document);

void test_empty_claim_without_finalize(){
    struct evr_claim_set cs;
    assert(is_ok(evr_init_claim_set(&cs, &t0)));
    assert(is_ok(evr_free_claim_set(&cs)));
}

void test_empty_claim(){
    struct evr_claim_set cs;
    assert(is_ok(evr_init_claim_set(&cs, &t0)));
    assert(is_ok(evr_finalize_claim_set(&cs)));
    assert(is_str_eq((char*)cs.out->content, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<claim-set dc:created=\"1970-01-01T00:00:00.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\"/>\n"));
    assert(is_ok(evr_free_claim_set(&cs)));
}

void test_file_claim_with_filename(){
    struct evr_file_slice slice;
    memset(slice.ref, 0, sizeof(slice.ref));
    slice.size = 1;
    const struct evr_file_claim claim = {
        0,
        {},
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
        0,
        {},
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
        0,
        {},
        "",
        1,
        &slice,
    };
    assert_file_claim(&claim, "<file><body><slice ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\" size=\"1\"/></body></file>");
}

void test_file_claim_with_seed(){
    struct evr_file_slice slice;
    memset(slice.ref, 0, sizeof(slice.ref));
    slice.size = 1;
    const struct evr_file_claim claim = {
        1,
        {},
        NULL,
        1,
        &slice,
    };
    assert_file_claim(&claim, "<file seed=\"sha3-224-00000000000000000000000000000000000000000000000000000000-0000\"><body><slice ref=\"sha3-224-00000000000000000000000000000000000000000000000000000000\" size=\"1\"/></body></file>");
}

void assert_file_claim(const struct evr_file_claim *claim, const char *expected_file_document){
    struct evr_claim_set cs;
    assert(is_ok(evr_init_claim_set(&cs, &t0)));
    assert(is_ok(evr_append_file_claim(&cs, claim)));
    assert(is_ok(evr_finalize_claim_set(&cs)));
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
            *dst = '\0';
            break;
        }
    }
    assert_msg(is_str_in(stripped_content, expected_file_document), "Expected\n%s\n to contain\n%s\n", stripped_content, expected_file_document);
    free(stripped_content);
    assert(is_ok(evr_free_claim_set(&cs)));
}

void test_parse_file_claim_claim_set(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<file dc:title=\"test.txt\"><body><slice ref=\"sha3-224-12300000000000000000000000000000000000000000000000000321\" size=\"1\"/></body></file>"
        "<file xmlns=\"https://evr.ma300k.de/something-which-will-never-ever-exist\"></file>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    evr_time created;
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    assert(is_ok(evr_parse_created(&created, csn)));
    assert(created == 7000);
    int file_claims_found = 0;
    int unknown_claims_found = 0;
    for(xmlNode *cn = evr_first_claim(csn); cn; cn = evr_next_claim(cn)){
        if(evr_is_evr_element(cn, "file", evr_claims_ns)){
            ++file_claims_found;
            struct evr_file_claim *c = evr_parse_file_claim(cn);
            assert(c);
            assert(is_str_eq(c->title, "test.txt"));
            assert(c->slices_len == 1);
            evr_blob_ref_str fmt_key;
            evr_fmt_blob_ref(fmt_key, c->slices[0].ref);
            assert(is_str_eq(fmt_key, "sha3-224-12300000000000000000000000000000000000000000000000000321"));
            assert(c->slices[0].size == 1);
            free(c);
        } else {
            ++unknown_claims_found;
        }
    }
    assert(file_claims_found == 1);
    assert(unknown_claims_found == 1);
    xmlFreeDoc(doc);
}

void test_parse_attr_claim_with_claim_seed(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr seed=\"sha3-224-32100000000000000000000000000000000000000000000000000123-0000\">"
        "<a op=\"=\" k=\"title\" v=\"test.txt\"/>"
        "<a op=\"+\" k=\"add\" v=\"spice\"/>"
        "<a op=\"-\" k=\"rm\"/>"
        "<a op=\"=\" k=\"my-ref\" vf=\"claim-ref\"/>"
        "</attr>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_claim *c;
    assert(is_ok(evr_parse_attr_claim(&c, cn)));
    assert(c);
    evr_blob_ref_str fmt_seed;
    evr_fmt_claim_ref(fmt_seed, c->seed);
    assert(c->seed_type == evr_seed_type_claim);
    assert(is_str_eq(fmt_seed, "sha3-224-32100000000000000000000000000000000000000000000000000123-0000"));
    assert(c->index_seed == 0);
    assert(c->attr_len == 4);
    assert(c->attr[0].op == evr_attr_op_replace);
    assert(is_str_eq(c->attr[0].key, "title"));
    assert(c->attr[0].value_type == evr_attr_value_type_static);
    assert(is_str_eq(c->attr[0].value, "test.txt"));
    assert(c->attr[1].op == evr_attr_op_add);
    assert(is_str_eq(c->attr[1].key, "add"));
    assert(c->attr[1].value_type == evr_attr_value_type_static);
    assert(is_str_eq(c->attr[1].value, "spice"));
    assert(c->attr[2].op == evr_attr_op_rm);
    assert(is_str_eq(c->attr[2].key, "rm"));
    assert(c->attr[2].value_type == evr_attr_value_type_static);
    assert(c->attr[2].value == NULL);
    assert(c->attr[3].op == evr_attr_op_replace);
    assert(is_str_eq(c->attr[3].key, "my-ref"));
    assert(c->attr[3].value_type == evr_attr_value_type_self_claim_ref);
    assert(c->attr[3].value == NULL);
    free(c);
    xmlFreeDoc(doc);
}

void test_parse_attr_claim_with_self_ref(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr></attr>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_claim *c;
    assert(is_ok(evr_parse_attr_claim(&c, cn)));
    assert(c);
    assert(c->seed_type == evr_seed_type_self);
    assert(c->index_seed == 0);
    assert(c->attr_len == 0);
    free(c);
    xmlFreeDoc(doc);
}

void test_parse_attr_claim_with_index_seed(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr index-seed=\"1024\"></attr>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_claim *c;
    assert(is_ok(evr_parse_attr_claim(&c, cn)));
    assert(c);
    assert(c->seed_type == evr_seed_type_self);
    assert(c->index_seed == 1024);
    assert(c->attr_len == 0);
    free(c);
    xmlFreeDoc(doc);
}

void test_parse_two_attr_claims(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr></attr>"
        "<attr></attr>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_claim *c;
    assert(is_ok(evr_parse_attr_claim(&c, cn)));
    assert(c);
    assert(c->seed_type == evr_seed_type_self);
    assert(c->index_seed == 0);
    assert(c->attr_len == 0);
    free(c);
    cn = evr_next_claim(cn);
    assert(is_ok(evr_parse_attr_claim(&c, cn)));
    assert(c);
    assert(c->seed_type == evr_seed_type_self);
    assert(c->index_seed == 1);
    assert(c->attr_len == 0);
    free(c);
    xmlFreeDoc(doc);
}

void test_parse_attr_spec_claim(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr-spec>"
        "<attr-def k=\"tag\" type=\"str\"/>"
        "<attr-def k=\"body-size\" type=\"int\"/>"
        "<attr-def k=\"cref\" type=\"claim-ref\"/>"
        "<attr-factory type=\"executable\" blob=\"sha3-224-99900000000000000000000000000000000000000000000000000000\"/>"
        "<transformation type=\"xslt\" blob=\"sha3-224-32100000000000000000000000000000000000000000000000000123\"/>"
        "</attr-spec>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_spec_claim *c = evr_parse_attr_spec_claim(cn);
    assert(c);
    assert(c->attr_def_len == 3);
    struct evr_attr_def *tag_def = &c->attr_def[0];
    assert(is_str_eq(tag_def->key, "tag"));
    assert(tag_def->type == evr_type_str);
    struct evr_attr_def *size_def = &c->attr_def[1];
    assert(is_str_eq(size_def->key, "body-size"));
    assert(size_def->type == evr_type_int);
    struct evr_attr_def *claim_ref_def = &c->attr_def[2];
    assert(is_str_eq(claim_ref_def->key, "cref"));
    assert(claim_ref_def->type == evr_type_claim_ref);
    evr_blob_ref_str fmt_transformation_blob_ref;
    evr_fmt_blob_ref(fmt_transformation_blob_ref, c->transformation_blob_ref);
    assert(is_str_eq(fmt_transformation_blob_ref, "sha3-224-32100000000000000000000000000000000000000000000000000123"));
    assert(c->attr_factories_len == 1);
    evr_blob_ref_str attr_factory_ref_str;
    evr_fmt_blob_ref(attr_factory_ref_str, *c->attr_factories);
    assert(is_str_eq(attr_factory_ref_str, "sha3-224-99900000000000000000000000000000000000000000000000000000"));
    free(c);
    xmlFreeDoc(doc);
}

void test_parse_attr_spec_claim_error_unknown_transformation_type(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr-spec>"
        "<transformation type=\"windows-exe-lol\" blob=\"sha3-224-32100000000000000000000000000000000000000000000000000123\"/>"
        "</attr-spec>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_spec_claim *c = evr_parse_attr_spec_claim(cn);
    assert(c == NULL);
    xmlFreeDoc(doc);
}

void test_parse_attr_spec_claim_error_unknown_attr_factory_type(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr-spec>"
        "<transformation type=\"xslt\" blob=\"sha3-224-32100000000000000000000000000000000000000000000000000123\"/>"
        "<attr-factory type=\"exe\" blob=\"sha3-224-99900000000000000000000000000000000000000000000000000000\"/>"
        "</attr-spec>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *cn = evr_first_claim(csn);
    assert(cn);
    struct evr_attr_spec_claim *c = evr_parse_attr_spec_claim(cn);
    assert(c == NULL);
    xmlFreeDoc(doc);
}

void test_nth_claim(){
    const char *buf =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<claim-set dc:created=\"1970-01-01T00:00:07.000000Z\" xmlns:dc=\"http://purl.org/dc/terms/\" xmlns=\"https://evr.ma300k.de/claims/\">"
        "<attr id=\"first\"></attr>"
        "<attr id=\"second\"></attr>"
        "</claim-set>\n";
    size_t buf_size = strlen(buf);
    xmlDocPtr doc = NULL;
    assert(is_ok(evr_parse_xml(&doc, buf, buf_size)));
    assert(doc);
    xmlNode *csn = evr_get_root_claim_set(doc);
    assert(csn);
    xmlNode *first = evr_nth_claim(csn, 0);
    assert(first);
    char *id = (char *)xmlGetProp(first, BAD_CAST "id");
    assert_msg(is_str_eq(id, "first"), "Got id '%s'", id);
    xmlFree(id);
    xmlNode *second = evr_nth_claim(csn, 1);
    assert(second);
    id = (char *)xmlGetProp(second, BAD_CAST "id");
    assert_msg(is_str_eq(id, "second"), "Got id '%s'", id);
    xmlFree(id);
    xmlNode *third = evr_nth_claim(csn, 2);
    assert(third == NULL);
    xmlFreeDoc(doc);
}

void test_parse_xml_user_data_invalid(){
    char *docs[] = {
        "",
        " ",
        "peng",
        "<",
        "<a>",
        NULL,
    };
    xmlDocPtr doc = NULL;
    for(char **it = docs; *it; ++it){
        assert_msg(evr_parse_xml(&doc, *it, strlen(*it)) == evr_user_data_invalid, "Expected evr_user_data_invalid for doc: %s", *it);
        assert(doc == NULL);
    }
}

void test_format_xml_node(){
    const char src_doc_str[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<root xmlns=\"https://whatever\">"
        "<an-element a-key=\"a-val\">peng</an-element>"
        "</root>";
    xmlDoc *src_doc = NULL;
    assert(is_ok(evr_parse_xml(&src_doc, src_doc_str, sizeof(src_doc_str) - 1)));
    assert(src_doc);
    xmlNode *an_el = xmlDocGetRootElement(src_doc)->children;
    assert(an_el);
    char *an_el_str = evr_format_xml_node(an_el);
    xmlFreeDoc(src_doc);
    assert_msg(is_str_in(an_el_str, "<an-element xmlns=\"https://whatever\" a-key=\"a-val\">peng</an-element>"), "But was %s", an_el_str);
    free(an_el_str);
}

int main(){
    xmlInitParser();
    evr_init_basics();
    run_test(test_empty_claim_without_finalize);
    run_test(test_empty_claim);
    run_test(test_file_claim_with_filename);
    run_test(test_file_claim_with_null_filename);
    run_test(test_file_claim_with_empty_filename);
    run_test(test_file_claim_with_seed);
    run_test(test_parse_file_claim_claim_set);
    run_test(test_parse_attr_claim_with_claim_seed);
    run_test(test_parse_attr_claim_with_self_ref);
    run_test(test_parse_attr_claim_with_index_seed);
    run_test(test_parse_two_attr_claims);
    run_test(test_parse_attr_spec_claim);
    run_test(test_parse_attr_spec_claim_error_unknown_transformation_type);
    run_test(test_parse_attr_spec_claim_error_unknown_attr_factory_type);
    run_test(test_nth_claim);
    run_test(test_parse_xml_user_data_invalid);
    run_test(test_format_xml_node);
    xmlCleanupParser();
    return 0;
}
