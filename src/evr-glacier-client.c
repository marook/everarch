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
#include "files.h"
#include "errors.h"
#include "logger.h"
#include "signatures.h"

int evr_connect_to_storage(char *host, char *port){
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    struct addrinfo *result;
    int res = getaddrinfo(host, port, &hints, &result);
    if(res != 0){
        log_error("Failed to resolve %s:%s: %s", host, port, gai_strerror(res));
        return -1;
    }
    for(struct addrinfo *p = result; p != NULL; p = p->ai_next){
        int s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s == -1){
            continue;
        }
        if(connect(s, p->ai_addr, p->ai_addrlen) != 0){
            close(s);
            continue;
        }
        freeaddrinfo(result);
        return s;
    }
    freeaddrinfo(result);
    log_error("Unable to connect to glacier storage %s:%s", host, port);
    return -1;
}

xmlDocPtr evr_fetch_xml(int fd, evr_blob_ref key){
    xmlDocPtr doc = NULL;
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(fd, key, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code != evr_status_code_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("Failed to read blob %s. Responded status code was 0x%02x", resp.status_code);
        goto out;
    }
    char *buf = malloc(resp.body_size + 1);
    if(!buf){
        goto out;
    }
    if(read_n(fd, buf, resp.body_size) != evr_ok){
        goto out_with_free_buf;
    }
    // first buf byte is blob flags which we ignore
    const size_t flags_size = 1;
    doc = xmlReadMemory(&buf[flags_size], resp.body_size - flags_size, NULL, "UTF-8", 0);
 out_with_free_buf:
    free(buf);
 out:
    return doc;
}

xmlDocPtr evr_fetch_signed_xml(int fd, evr_blob_ref key){
    xmlDocPtr doc = NULL;
    struct evr_resp_header resp;
    if(evr_req_cmd_get_blob(fd, key, &resp) != evr_ok){
        goto out;
    }
    if(resp.status_code != evr_status_code_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("Failed to read blob %s. Responded status code was 0x%02x", resp.status_code);
        goto out;
    }
    char *buf = malloc(resp.body_size);
    if(!buf){
        goto out;
    }
    if(read_n(fd, buf, resp.body_size) != evr_ok){
        goto out_with_free_buf;
    }
    struct dynamic_array *claim = NULL;
    // first buf byte is blob flags which we ignore
    const size_t flags_size = 1;
    if(evr_verify(&claim, &buf[flags_size], resp.body_size - flags_size) != evr_ok){
        evr_blob_ref_str fmt_key;
        evr_fmt_blob_ref(fmt_key, key);
        log_error("Failed to verify claim with ref %s", fmt_key);
        goto out_with_free_buf;
    }
    doc = xmlReadMemory(claim->data, claim->size_used, NULL, "UTF-8", 0);
    free(claim);
 out_with_free_buf:
    free(buf);
 out:
    return doc;
}

xsltStylesheetPtr evr_fetch_stylesheet(int fd, evr_blob_ref ref){
    xsltStylesheetPtr style = NULL;
    xmlDocPtr style_doc = evr_fetch_xml(fd, ref);
    if(!style_doc){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, ref);
        log_error("Failed to fetch attr spec's stylesheet with ref %s", ref_str);
        goto out;
    }
    style = xsltParseStylesheetDoc(style_doc);
    if(!style){
        evr_blob_ref_str ref_str;
        evr_fmt_blob_ref(ref_str, ref);
        log_error("Failed to parse XSLT stylesheet from blob with ref %s", ref_str);
        // style_doc is freed by xsltFreeStylesheet(style) on
        // successful style parsing.
        xmlFreeDoc(style_doc);
        goto out;
    }
 out:
    return style;
}

int evr_req_cmd_get_blob(int fd, evr_blob_ref key, struct evr_resp_header *resp){
    int ret = evr_error;
    if(evr_write_cmd_get_blob(fd, key) != evr_ok){
        goto out;
    }
    if(evr_read_resp_header(fd, resp) != evr_ok){
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

int evr_write_cmd_get_blob(int fd, evr_blob_ref key){
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
    if(write_n(fd, buf, sizeof(buf)) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_req_cmd_watch_blobs(int fd, struct evr_blob_filter *filter){
    int ret = evr_error;
    if(evr_write_cmd_watch_blobs(fd, filter) != evr_ok){
        goto out;
    }
    struct evr_resp_header resp;
    if(evr_read_resp_header(fd, &resp) != evr_ok){
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

int evr_write_cmd_watch_blobs(int fd, struct evr_blob_filter *filter){
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
    if(write_n(fd, buf, evr_cmd_header_n_size + evr_blob_filter_n_size) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}

int evr_read_resp_header(int fd, struct evr_resp_header *resp){
    int ret = evr_error;
    char buf[evr_resp_header_n_size];
    if(read_n(fd, buf, evr_resp_header_n_size) != evr_ok){
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

int evr_read_watch_blobs_body(int fd, struct evr_watch_blobs_body *body){
    int ret = evr_error;
    char buf[evr_watch_blobs_body_n_size];
    if(read_n(fd, buf, evr_watch_blobs_body_n_size) != evr_ok){
        goto out;
    }
    if(evr_parse_watch_blobs_body(body, buf) != evr_ok){
        goto out;
    }
    ret = evr_ok;
 out:
    return ret;
}
