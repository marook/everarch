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

/*
 * claims.h provides functions to produce a claim set document from
 * claim structs.
 *
 * The general approach is to evr_init_claim_set(…) a claim set. Then
 * append claims to the claim set. evr_finalize_claim_set(…) the claim
 * set so the claim set document can be extracted via
 * evr_claim_set.out->content. evr_free_claim_set(…) after the claim
 * document content has been consumed.
 */

#ifndef __evr_claims_h__
#define __evr_claims_h__

#include <time.h>
#include <libxml/xmlwriter.h>

#include "keys.h"

struct evr_claim_set {
    /**
     * out contains the serialized claim set after
     * evr_finalize_claim_set has been called. Read it via out->content.
     */
    xmlBufferPtr out;

    xmlTextWriterPtr writer;
};

struct evr_file_claim {
    /**
     * title could be the file name.
     */
    char *title;

    size_t segments_len;
    
    evr_blob_key_t *segments;
};

int evr_init_claim_set(struct evr_claim_set *cs, const time_t *created);

int evr_append_file_claim(struct evr_claim_set *cs, const struct evr_file_claim *claim);

int evr_finalize_claim_set(struct evr_claim_set *cs);

int evr_free_claim_set(struct evr_claim_set *cs);

#endif
