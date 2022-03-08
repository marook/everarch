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

void test_open_new_attr_index_db_twice(){
    struct evr_attr_index_db_configuration *cfg = create_temp_attr_index_db_configuration();
    for(int i = 0; i < 2; ++i){
        log_info("Round %d…", i);
        struct evr_attr_index_db *db = evr_open_attr_index_db(cfg, "ye-db");
        assert_not_null(db);
        if(i == 0){
            struct evr_attr_def attr_def[2];
            attr_def[0].key = "tag";
            attr_def[0].type = evr_type_str;
            attr_def[1].key = "size";
            attr_def[1].type = evr_type_int;
            struct evr_attr_spec_claim spec;
            spec.attr_def_len = 2;
            spec.attr_def = attr_def;
            memset(spec.stylesheet_blob_ref, 0, evr_blob_key_size);
            assert_ok(evr_setup_attr_index_db(db, &spec));
        }
        assert_ok(evr_free_glacier_index_db(db));
    }
    evr_free_attr_index_db_configuration(cfg);
}

int main(){
    run_test(test_open_new_attr_index_db_twice);
    return 0;
}
