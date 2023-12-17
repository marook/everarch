/*
 * everarch - the hopefully ever lasting archive
 * Copyright (C) 2021-2023  Markus Peröbner
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

import { fromEvent } from 'rxjs';
import { tap } from 'rxjs/operators';

import { createRouter } from '../routers.js';
import { instantiateTemplate } from '../mvc.js';

class UploadController {
    constructor(){
        this.element = instantiateTemplate('upload');
        this.active = fromEvent(this.element.querySelector('form[name=fileUpload]'), 'submit').pipe(
            tap(event => {
                event.preventDefault();
                let files = this.element.querySelector('form[name=fileUpload] input[name=file]').files;
                let file = files[0];
                let authToken = localStorage.getItem('evr-upload-httpd-auth-token');
                fetch(`/evr-upload-httpd/files/${file.name}`, {
                    method: 'POST',
                    headers: {
                        Authorization: `Bearer AT${authToken}`,
                    },
                    body: file,
                });
            }),
        );
    }
}

let router = createRouter(document.getElementById('viewport'), routePath => {
    return new UploadController();
});
router.subscribe();
