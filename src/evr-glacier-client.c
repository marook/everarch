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

#include "evr-glacier-client.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

#include "basics.h"
#include "errors.h"
#include "logger.h"
#include "claims.h"

int evr_write_auth_token(struct evr_file *f, evr_auth_token t){
    char buf[sizeof(uint8_t) + sizeof(evr_auth_token)];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    int auth_type = evr_auth_type_token;
    evr_push_as(&bp, &auth_type, uint8_t);
    evr_push_n(&bp, t, sizeof(evr_auth_token));
    if(write_n(f, buf, sizeof(buf)) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_write_cmd_configure_connection(struct evr_file *f, struct evr_glacier_connection_config *conf);

int evr_configure_connection(struct evr_file *f, struct evr_glacier_connection_config *conf){
    struct evr_resp_header resp;
    if(evr_write_cmd_configure_connection(f, conf) != evr_ok){
        return evr_error;
    }
    if(evr_read_resp_header(f, &resp) != evr_ok){
        return evr_error;
    }
    if(resp.status_code == evr_unknown_request){
        return evr_unknown_request;
    }
    if(resp.status_code != evr_status_code_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_write_cmd_configure_connection(struct evr_file *f, struct evr_glacier_connection_config *conf){
    char buf[evr_cmd_header_n_size + 1];
    struct evr_buf_pos bp;
    struct evr_cmd_header cmd;
    evr_init_buf_pos(&bp, buf);
    cmd.type = evr_cmd_type_configure_connection;
    cmd.body_size = 1;
    if(evr_format_cmd_header(bp.pos, &cmd) != evr_ok){
        return evr_error;
    }
    evr_inc_buf_pos(&bp, evr_cmd_header_n_size);
    evr_push_as(&bp, &conf->sync_strategy, uint8_t);
    if(write_n(f, buf, sizeof(buf)) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_fetch_xml(xmlDocPtr *doc, struct evr_file *f, evr_blob_ref key){
    int ret = evr_error;
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(f, key, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code != evr_status_code_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("Failed to read blob %s. Responded status code was 0x%02x", fmt_key, resp.status_code);
        goto out;
    }
    char *buf = NULL;
    if(evr_read_cmd_get_resp_blob(&buf, f, resp.body_size, key) != evr_ok){
        goto out;
    }
    // TODO migrate to evr_parse_xml
    *doc = xmlReadMemory(buf, resp.body_size - evr_blob_flags_n_size, NULL, "UTF-8", 0);
    if(!*doc){
        ret = evr_user_data_invalid;
        goto out_with_free_buf;
    }
    ret = evr_ok;
 out_with_free_buf:
    free(buf);
 out:
    return ret;
}

int evr_fetch_signed_xml(xmlDocPtr *doc, struct evr_verify_ctx *ctx, struct evr_file *f, evr_blob_ref key, struct evr_file *meta){
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(f, key, &resp) != evr_ok){
        return evr_error;
    }
    if(resp.status_code != evr_status_code_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("Failed to read blob %s. Responded status code was 0x%02x", fmt_key, resp.status_code);
        return evr_not_found;
    }
    char *buf = NULL;
    if(evr_read_cmd_get_resp_blob(&buf, f, resp.body_size, key) != evr_ok){
        return evr_error;
    }
    struct dynamic_array *claim = NULL;
    int verify_res = evr_verify(ctx, &claim, buf, resp.body_size - evr_blob_flags_n_size, meta);
    free(buf);
    if(verify_res == evr_user_data_invalid){
        return evr_user_data_invalid;
    } else if(verify_res != evr_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("Failed to verify claim with ref %s", fmt_key);
        return evr_error;
    }
    int parse_res = evr_parse_xml(doc, claim->data, claim->size_used);
    free(claim);
    if(parse_res == evr_user_data_invalid){
        return evr_user_data_invalid;
    } else if(parse_res != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_fetch_stylesheet(xsltStylesheetPtr *style, struct evr_file *f, evr_blob_ref ref){
    int ret = evr_error;
    xmlDocPtr style_doc = NULL;
    int xml_res = evr_fetch_xml(&style_doc, f, ref);
    if(xml_res == evr_user_data_invalid){
        ret = evr_user_data_invalid;
        goto out;
    }
    if(xml_res != evr_ok){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, ref);
        log_error("Failed to fetch attr spec's stylesheet with ref %s", ref_str);
        goto out;
    }
    *style = xsltParseStylesheetDoc(style_doc);
    if(!style){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, ref);
        log_error("Failed to parse XSLT stylesheet from blob with ref %s", ref_str);
        // style_doc is freed by xsltFreeStylesheet(style) on
        // successful style parsing.
        xmlFreeDoc(style_doc);
        ret = evr_user_data_invalid;
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

struct evr_file_claim *evr_fetch_file_claim(struct evr_file *c, evr_claim_ref claim_ref, struct evr_verify_ctx *verify_ctx, evr_time *create_timestamp){
    struct evr_file_claim *ret = NULL;
    evr_blob_ref blob_ref;
    int claim_index;
    evr_split_claim_ref(blob_ref, &claim_index, claim_ref);
    xmlDoc *doc = NULL;
    if(evr_fetch_signed_xml(&doc, verify_ctx, c, blob_ref, NULL) != evr_ok){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("No validly signed XML found for ref %s", claim_ref_str);
        goto out;
    }
    xmlNode *cs = evr_get_root_claim_set(doc);
    if(!cs){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("No claim set found in blob for claim ref %s", claim_ref_str);
        goto out_with_free_doc;
    }
    if(create_timestamp && evr_parse_created(create_timestamp, cs) != evr_ok){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("Unable to parse created timestamp for file claim %s", claim_ref_str);
        goto out_with_free_doc;
    }
    xmlNode *cn = evr_nth_claim(cs, claim_index);
    if(!cn){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("There is no claim with index %d in claim-set with ref %s", claim_index, claim_ref_str);
        goto out_with_free_doc;
    }
    ret = evr_parse_file_claim(cn);
    if(!ret){
        evr_claim_ref_str claim_ref_str;
        evr_fmt_claim_ref(claim_ref_str, claim_ref);
        log_error("Unable to parse file claim from claim XML with ref %s", claim_ref_str);
    }
 out_with_free_doc:
    xmlFreeDoc(doc);
 out:
    return ret;
}

int evr_stat_and_put(struct evr_file *c, evr_blob_ref key, int flags, struct chunk_set *blob){
    int ret = evr_error;
#ifdef EVR_LOG_DEBUG
    evr_blob_ref_str fmt_key;
    evr_fmt_blob_ref(fmt_key, key);
#endif
    struct evr_resp_header resp;
    if(evr_req_cmd_stat_blob(c, key, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code == evr_status_code_ok){
        log_debug("blob already exists");
        if(resp.body_size != evr_stat_blob_resp_n_size){
            goto out;
        }
        // TODO :gcflgup: update flags in storage if necessary
        if(dump_n(c, evr_stat_blob_resp_n_size, NULL, NULL) != evr_ok){
            goto out;
        }
        ret = evr_exists;
        goto out;
    }
    if(resp.status_code != evr_status_code_blob_not_found){
        goto out;
    }
    log_debug("Storage indicated blob does not yet exist");
    if(resp.body_size != 0){
        goto out;
    }
    if(evr_write_cmd_put_blob(c, key, flags, blob->size_used) != evr_ok){
        goto out;
    }
    if(write_chunk_set(c, blob) != evr_ok){
        goto out;
    }
    if(evr_read_resp_header(c, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code != evr_status_code_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_req_cmd_stat_blob(struct evr_file *f, evr_blob_ref key, struct evr_resp_header *resp){
    if(evr_write_cmd_stat_blob(f, key) != evr_ok){
        return evr_error;
    }
    if(evr_read_resp_header(f, resp) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_write_cmd_stat_blob(struct evr_file *f, evr_blob_ref key){
    char buf[evr_cmd_header_n_size + evr_blob_ref_size];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_cmd_header cmd;
    cmd.type = evr_cmd_type_stat_blob;
    cmd.body_size = evr_blob_ref_size;
    if(evr_format_cmd_header(bp.pos, &cmd) != evr_ok){
        return evr_error;
    }
    evr_inc_buf_pos(&bp, evr_cmd_header_n_size);
    evr_push_n(&bp, key, evr_blob_ref_size);
#ifdef EVR_LOG_DEBUG
    evr_blob_ref_str key_str;
    evr_fmt_blob_ref(key_str, key);
    log_debug("Sending stat %s command", key_str);
#endif
    if(write_n(f, buf, sizeof(buf)) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_req_cmd_get_blob(struct evr_file *f, evr_blob_ref key, struct evr_resp_header *resp){
    int ret = evr_error;
    if(evr_write_cmd_get_blob(f, key) != evr_ok){
        goto out;
    }
    if(evr_read_resp_header(f, resp) != evr_ok){
        goto out;
    }
    if(resp->body_size > evr_max_blob_data_size){
        log_error("Server reported body size of %llu bytes which is over the limit for blobs", resp->body_size);
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_write_cmd_get_blob(struct evr_file *f, evr_blob_ref key){
    int ret = evr_error;
    char buf[evr_cmd_header_n_size + evr_blob_ref_size];
    struct evr_cmd_header cmd;
    cmd.type = evr_cmd_type_get_blob;
    cmd.body_size = evr_blob_ref_size;
    if(evr_format_cmd_header(buf, &cmd) != evr_ok){
        goto out;
    }
    memcpy(&buf[evr_cmd_header_n_size], key, evr_blob_ref_size);
#ifdef EVR_LOG_DEBUG
    {
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_debug("Sending get %s command to server", fmt_key);
    }
#endif
    if(write_n(f, buf, sizeof(buf)) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_read_cmd_get_resp_blob(char **blob, struct evr_file *c, size_t resp_body_size, evr_blob_ref expected_ref){
    int ret = evr_error;
    // read flags but ignore them
    char flags_buf[evr_blob_flags_n_size];
    if(resp_body_size < sizeof(flags_buf) || resp_body_size > evr_max_blob_data_size + sizeof(flags_buf)){
        goto out;
    }
    if(read_n(c, flags_buf, sizeof(flags_buf), NULL, NULL) != evr_ok){
        goto out;
    }
    size_t blob_size = resp_body_size - sizeof(flags_buf);
    char *buf = malloc(blob_size);
    if(!buf){
        goto out;
    }
    evr_blob_ref_hd hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto out_with_free_buf;
    }
    if(read_n(c, buf, blob_size, evr_blob_ref_write_se, hd) != evr_ok){
        goto out_with_close_hd;
    }
    if(evr_blob_ref_hd_match(hd, expected_ref) != evr_ok){
        goto out_with_close_hd;
    }
    evr_blob_ref_close(hd);
    *blob = buf;
    ret = evr_ok;
    return ret;
 out_with_close_hd:
    evr_blob_ref_close(hd);
 out_with_free_buf:
    free(buf);
 out:
    return ret;
}

int evr_pipe_cmd_get_resp_blob(struct evr_file *dst, struct evr_file *src, size_t resp_body_size, evr_blob_ref expected_ref){
    int ret = evr_error;
    char flags_buf[evr_blob_flags_n_size];
    if(resp_body_size < sizeof(flags_buf)){
        goto out;
    }
    // read flags but don't use them
    int read_res = read_n(src, flags_buf, sizeof(flags_buf), NULL, NULL);
    if(read_res == evr_end){
        ret = evr_end;
        goto out;
    }
    if(read_res != evr_ok){
        goto out;
    }
    evr_blob_ref_hd hd;
    if(evr_blob_ref_open(&hd) != evr_ok){
        goto out;
    }
    int pipe_res = pipe_n(dst, src, resp_body_size - 1, evr_blob_ref_write_se, hd);
    if(pipe_res == evr_end){
        ret = evr_end;
        goto out_with_close_hd;
    }
    if(pipe_res != evr_ok){
        goto out_with_close_hd;
    }
    if(evr_blob_ref_hd_match(hd, expected_ref) != evr_ok){
        goto out_with_close_hd;
    }
    ret = evr_ok;
 out_with_close_hd:
    evr_blob_ref_close(hd);
 out:
    return ret;
}

int evr_write_cmd_put_blob(struct evr_file *f, evr_blob_ref key, int flags, size_t blob_size){
    const size_t body_size = evr_blob_ref_size + sizeof(uint8_t);
    char buf[evr_cmd_header_n_size + body_size];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_cmd_header cmd;
    cmd.type = evr_cmd_type_put_blob;
    cmd.body_size = body_size + blob_size;
    if(evr_format_cmd_header(buf, &cmd) != evr_ok){
        return evr_error;
    }
    evr_inc_buf_pos(&bp, evr_cmd_header_n_size);
    evr_push_n(&bp, key, evr_blob_ref_size);
    evr_push_as(&bp, &flags, uint8_t);
    if(write_n(f, buf, sizeof(buf)) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}

int evr_req_cmd_watch_blobs(struct evr_file *f, struct evr_blob_filter *filter){
    int ret = evr_error;
    if(evr_write_cmd_watch_blobs(f, filter) != evr_ok){
        goto out;
    }
    struct evr_resp_header resp;
    if(evr_read_resp_header(f, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code != evr_status_code_ok){
        goto out;
    }
    if(resp.body_size != 0){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_write_cmd_watch_blobs(struct evr_file *f, struct evr_blob_filter *filter){
    int ret = evr_error;
    char buf[evr_cmd_header_n_size + evr_blob_filter_n_size];
    struct evr_buf_pos bp;
    evr_init_buf_pos(&bp, buf);
    struct evr_cmd_header cmd;
    cmd.type = evr_cmd_type_watch_blobs;
    cmd.body_size = evr_blob_filter_n_size;
    if(evr_format_cmd_header(bp.pos, &cmd) != evr_ok){
        goto out;
    }
    bp.pos += evr_cmd_header_n_size;
    if(evr_format_blob_filter(bp.pos, filter) != evr_ok){
        goto out;
    }
    log_debug("Sending watch command to server with sort order 0x%02x, flags filter 0x%02x and last_modified_after %llu", filter->sort_order, filter->flags_filter, filter->last_modified_after);
    if(write_n(f, buf, evr_cmd_header_n_size + evr_blob_filter_n_size) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_read_resp_header(struct evr_file *f, struct evr_resp_header *resp){
    int ret = evr_error;
    char buf[evr_resp_header_n_size];
    if(read_n(f, buf, evr_resp_header_n_size, NULL, NULL) != evr_ok){
        goto out;
    }
    if(evr_parse_resp_header(resp, buf) != evr_ok){
        goto out;
    }
    log_debug("Storage responded with status code 0x%02x and body size %d", resp->status_code, resp->body_size);
    ret = evr_ok;
 out:
    return ret;
}

int evr_read_watch_blobs_body(struct evr_file *f, struct evr_watch_blobs_body *body){
    char buf[evr_watch_blobs_body_n_size];
    int read_res = read_n(f, buf, evr_watch_blobs_body_n_size, NULL, NULL);
    if(read_res == evr_end){
        return evr_end;
    }
    if(read_res != evr_ok){
        return evr_error;
    }
    if(evr_parse_watch_blobs_body(body, buf) != evr_ok){
        return evr_error;
    }
    return evr_ok;
}
