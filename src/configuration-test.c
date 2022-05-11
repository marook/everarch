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

#include "assert.h"
#include "configuration.h"
#include "test.h"

void test_merge_evr_glacier_storage_cfg_file(){
    struct evr_glacier_storage_cfg *config = create_evr_glacier_storage_cfg();
    assert_str_eq(config->cert_path, "~/.config/everarch/cert.pem");
    assert_str_eq(config->key_path, "~/.config/everarch/key.pem");
    assert_null(config->cert_root_path);

    assert_zero(merge_evr_glacier_storage_cfg_file(config, "etc/configuration/empty.json"));
    assert_str_eq(config->cert_path, "~/.config/everarch/cert.pem");
    assert_null(config->cert_root_path);

    assert_zero(merge_evr_glacier_storage_cfg_file(config, "etc/configuration/full.json"));
    assert_str_eq(config->cert_path, "path/to/my/cert");
    assert_str_eq(config->key_path, "path/to/my/key");
    assert_str_eq(config->cert_root_path, "path/to/my/root/cert");

    free_evr_glacier_storage_cfg(config);
}

void test_load_evr_glacier_storage_cfgs(){
    struct evr_glacier_storage_cfg *config = create_evr_glacier_storage_cfg();
    const char *config_paths[] = {
        "etc/configuration/empty.json",
        "etc/configuration/no-such-file-exists-for-sure.json",
        "etc/configuration/full.json",
    };
    assert_zero(load_evr_glacier_storage_cfgs(config, config_paths, sizeof(config_paths) / sizeof(char*)));
    assert_str_eq(config->cert_path, "path/to/my/cert");
    assert_str_eq(config->key_path, "path/to/my/key");
    assert_str_eq(config->cert_root_path, "path/to/my/root/cert");
    free_evr_glacier_storage_cfg(config);
}

void test_free_null_configuration(){
    free_evr_glacier_storage_cfg(NULL);
}

int main(){
    run_test(test_merge_evr_glacier_storage_cfg_file);
    run_test(test_load_evr_glacier_storage_cfgs);
    run_test(test_free_null_configuration);
    return 0;
}
