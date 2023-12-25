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

#include <libxslt/documents.h>
#include <libxslt/transform.h>

#include "assert.h"
#include "test.h"
#include "keys.h"
#include "seed-desc.h"
#include "errors.h"
#include "claims.h"

int evr_fetch_signed_xml(xmlDocPtr *doc, struct evr_verify_ctx *ctx, struct evr_file *f, evr_blob_ref key){
    // not yet mocked
    return evr_error;
}

#define test_claim_ref "sha3-224-dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5-fde8"

int evr_attri_write_search(struct evr_file *f, char *query){
    return evr_ok;
}

int evr_attri_read_search(struct evr_buf_read *r, int (*visit_seed)(void *ctx, evr_claim_ref seed), int (*visit_attr)(void *ctx, evr_claim_ref seed, char *key, char *val), void *ctx){
    evr_claim_ref seed;
    assert(is_ok(evr_parse_claim_ref(seed, test_claim_ref)));
    if(visit_seed) {
        assert(is_ok(visit_seed(ctx, seed)));
    }
    if(visit_attr){
        assert(is_ok(visit_attr(ctx, seed, "my-key", "my-val")));
    }
    return evr_ok;
}

xsltStylesheet *create_fs_map_xslt(void);

void test_build_seed_desc(void){
    evr_claim_ref seed;
    assert(is_ok(evr_parse_claim_ref(seed, test_claim_ref)));
    xmlDoc *doc;
    xmlNode *set_node;
    assert(is_ok(evr_seed_desc_create_doc(&doc, &set_node, seed)));
    assert(set_node);
    xmlNode *desc_node;
    assert(is_ok(evr_seed_desc_append_desc(doc, set_node, &desc_node, seed)));
    assert(desc_node);
    struct evr_file f;
    struct evr_buf_read r;
    r.f = &f;
    assert(is_ok(evr_seed_desc_append_attrs(doc, desc_node, &r, seed, NULL, NULL)));
    char *desc_node_str = evr_format_xml_node(desc_node);
    assert(desc_node_str);
    xsltStylesheet *style = create_fs_map_xslt();
    const char *xslt_params[] = {
        NULL
    };
    xmlDoc *fs_doc = xsltApplyStylesheet(style, doc, xslt_params);
    assert(fs_doc);
    xsltFreeStylesheet(style);
    xmlFreeDoc(doc);
    xmlNode *file_set = evr_get_root_file_set(fs_doc);
    assert(file_set);
    char *file_set_str = evr_format_xml_node(file_set);
    assert(file_set_str);
    xmlNode *file_n = evr_first_file_node(file_set);
    assert(file_n);
    assert(!evr_next_file_node(file_n));
    struct evr_fs_file *file = evr_parse_fs_file(file_n);
    assert(file);
    xmlFreeDoc(fs_doc);
    assert_msg(is_str_eq("path/my-val", file->path), "But was %s\n\n%s\n\n%s", file->path, desc_node_str, file_set_str);
    free(file);
    free(file_set_str);
    free(desc_node_str);
}

xsltStylesheet *create_fs_map_xslt(void){
    const char buf[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<xsl:stylesheet version=\"1.0\""
        " xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\""
        " xmlns:esd=\"https://evr.ma300k.de/seed-description/\""
        " xmlns:efs=\"https://evr.ma300k.de/files/\""
        ">"
        "<xsl:template match=\"/esd:seed-description-set/esd:seed-description\">"
        "<efs:file-set>"
        "<efs:file file-ref=\"" test_claim_ref "\" size=\"0\">"
        "<xsl:attribute name=\"path\">path/<xsl:value-of select=\"//esd:attr[@k='my-key']/@v\"/></xsl:attribute>"
        "</efs:file>"
        "</efs:file-set>"
        "</xsl:template>"
        "</xsl:stylesheet>";
    xmlDoc *doc;
    assert(is_ok(evr_parse_xml(&doc, buf, sizeof(buf) - 1)));
    xsltStylesheet *style = xsltParseStylesheetDoc(doc);
    assert(style);
    return style;
}

int main(void){
    run_test(test_build_seed_desc);
    return 0;
}
