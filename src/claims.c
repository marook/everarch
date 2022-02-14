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

#include "claims.h"

#include "errors.h"

const char *evr_claim_encoding = "utf-8";
const char *evr_iso_8601_timestamp = "%FT%TZ";
const char *evr_claims_ns = "https://evr.ma300k.de/claims/";

int evr_init_claim_set(struct evr_claim_set *cs, const time_t *created){
    cs->out = xmlBufferCreate();
    if(cs->out == NULL){
        goto out;
    }
    cs->writer = xmlNewTextWriterMemory(cs->out, 0);
    if(cs->writer == NULL){
        goto out_with_free_out;
    }
    if(xmlTextWriterStartDocument(cs->writer, NULL, evr_claim_encoding, NULL) < 0){
        goto out_with_free_writer;
    }
    if(xmlTextWriterStartElementNS(cs->writer, NULL, BAD_CAST "claim-set", BAD_CAST evr_claims_ns) < 0){
        goto out_with_free_writer;
    }
    char buf[30];
    struct tm t;
    gmtime_r(created, &t);
    strftime(buf, sizeof(buf), evr_iso_8601_timestamp, &t);
    if(xmlTextWriterWriteAttributeNS(cs->writer, BAD_CAST "dc", BAD_CAST "created", BAD_CAST "http://purl.org/dc/terms/", BAD_CAST buf) < 0){
        goto out_with_free_writer;
    }
    return evr_ok;
 out_with_free_writer:
    xmlFreeTextWriter(cs->writer);
 out_with_free_out:
    xmlBufferFree(cs->out);
 out:
    return evr_error;
}

int evr_append_file_claim(struct evr_claim_set *cs, const struct evr_file_claim *claim){
    if(xmlTextWriterStartElement(cs->writer, BAD_CAST "file") < 0){
        goto out;
    }
    if(claim->title && claim->title[0] != '\0' && xmlTextWriterWriteAttributeNS(cs->writer, BAD_CAST "dc", BAD_CAST "title", NULL, BAD_CAST claim->title) < 0){
        goto out;
    }
    if(xmlTextWriterStartElement(cs->writer, BAD_CAST "body") < 0){
        goto out;
    }
    const struct evr_file_slice *end = &claim->slices[claim->slices_len];
    evr_fmt_blob_key_t fmt_key;
    char buf[9 + 1];
    for(const struct evr_file_slice *s = claim->slices; s != end; ++s){
        if(xmlTextWriterStartElement(cs->writer, BAD_CAST "slice") < 0){
            goto out;
        }
        evr_fmt_blob_key(fmt_key, s->key);
        if(xmlTextWriterWriteAttribute(cs->writer, BAD_CAST "ref", BAD_CAST fmt_key) < 0){
            goto out;
        }
        if(s->size >= 100 << 20){
            goto out;
        }
        sprintf(buf, "%lu", s->size);
        if(xmlTextWriterWriteAttribute(cs->writer, BAD_CAST "size", BAD_CAST buf) < 0){
            goto out;
        }
        // end segment element
        if(xmlTextWriterEndElement(cs->writer) < 0){
            goto out;
        }
    }
    // end body element
    if(xmlTextWriterEndElement(cs->writer) < 0){
        goto out;
    }
    // end file element
    if(xmlTextWriterEndElement(cs->writer) < 0){
        goto out;
    }
    return evr_ok;
 out:
    return evr_error;
}

int evr_finalize_claim_set(struct evr_claim_set *cs){
    int ret = evr_error;
    // end claim-set element
    if(xmlTextWriterEndElement(cs->writer) < 0){
        goto out;
    }
    if(xmlTextWriterEndDocument(cs->writer) < 0){
        goto out;
    }
    xmlFreeTextWriter(cs->writer);
    cs->writer = NULL;
    ret = evr_ok;
 out:
    return ret;
}

int evr_free_claim_set(struct evr_claim_set *cs){
    if(cs->writer != NULL){
        xmlFreeTextWriter(cs->writer);
    }
    xmlBufferFree(cs->out);
    return evr_ok;
}
